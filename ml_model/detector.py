import os
import json
import time
import logging
import threading
import csv
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import joblib
import numpy as np
import pandas as pd
from nfstream import NFStreamer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [detector] %(message)s",
)
log = logging.getLogger("ml_detector")

IFACE = os.environ.get("IFACE", "eth0")
MODEL_PATH = os.environ.get("MODEL_PATH", "/app/models/isolation_forest.joblib")
SCALER_PATH = os.environ.get("SCALER_PATH", "/app/models/scaler.joblib")
ALERT_LOG_PATH = os.environ.get("ALERT_LOG_PATH", "/var/log/ml_detector/alerts.log")
FLOW_CSV_PATH = os.environ.get("FLOW_CSV_PATH", "/var/log/ml_detector/flows.csv")
MODEL_VERSION = os.environ.get("MODEL_VERSION", "isolation_forest_v1")
SERVER_IP = os.environ.get("SERVER_IP", "10.10.10.1")

SCAN_MODEL_PATH = os.environ.get("SCAN_MODEL_PATH", "/app/models/scan_persistent_model.joblib")
SCAN_SCALER_PATH = os.environ.get("SCAN_SCALER_PATH", "/app/models/scan_persistent_scaler.joblib")
SCAN_WINDOW_SECONDS = int(os.environ.get("SCAN_WINDOW_SECONDS", 60))
# NOTE: default corrected to -0.10 to match the threshold actually validated
# by the timeline test (see docs, section 3.4) for both models. Override via
# env var if a different value is intentionally being tested.
SCAN_THRESHOLD = float(os.environ.get("SCAN_THRESHOLD", -0.10))

# NOTE: this was hardcoded as a magic number (-0.10) in several places in
# the original code. Pulled into one constant so the per-flow threshold is
# defined in exactly one place.
PER_FLOW_THRESHOLD = float(os.environ.get("PER_FLOW_THRESHOLD", -0.10))

IDLE_TIMEOUT = int(os.environ.get("IDLE_TIMEOUT", 10))
ACTIVE_TIMEOUT = int(os.environ.get("ACTIVE_TIMEOUT", 30))
MIN_BIDIRECTIONAL_PACKETS = int(os.environ.get("MIN_PACKETS", 3))

ALERT_BATCH_SECONDS = int(os.environ.get("ALERT_BATCH_SECONDS", 10))

LOCAL_TZ = timezone(timedelta(hours=3))

FEATURE_COLUMNS = [
    "bidirectional_duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "src2dst_bytes",
    "src2dst_duration_ms",
    "dst2src_packets",
    "dst2src_bytes",
    "dst2src_duration_ms",
    "bidirectional_min_ps",
    "bidirectional_mean_ps",
    "bidirectional_stddev_ps",
    "bidirectional_max_ps",
    "bidirectional_min_piat_ms",
    "bidirectional_mean_piat_ms",
    "bidirectional_stddev_piat_ms",
    "bidirectional_max_piat_ms",
    "bidirectional_syn_packets",
    "bidirectional_cwr_packets",
    "bidirectional_ece_packets",
    "bidirectional_urg_packets",
    "bidirectional_ack_packets",
    "bidirectional_psh_packets",
    "bidirectional_rst_packets",
    "bidirectional_fin_packets",
]

WINDOW_FEATURES = [
    "unique_dst_ports", "unique_dst_ips", "total_flows",
    "failed_ratio", "port_diversity_rate", "connection_rate",
    "avg_flow_duration", "max_flow_duration", "std_flow_duration",
    "avg_bytes",
]

CSV_HEADER = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "detection_layer", "anomaly_score",
] + FEATURE_COLUMNS


class MLDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.scan_model = None
        self.scan_scaler = None
        self.alert_count = 0
        self.flow_count = 0
        self.window_alert_count = 0
        self.per_flow_alert_count = 0

        self.pending_anomalies = []
        self.batch_start = time.time()
        self._batch_lock = threading.Lock()

        self.window_flows = defaultdict(list)
        self._window_lock = threading.Lock()

        self._stop_event = threading.Event()

        self.flow_csv_file = None
        self.flow_csv_writer = None

    def load_model(self):
        log.info(f"Loading model from: {MODEL_PATH}")
        self.model = joblib.load(MODEL_PATH)
        log.info(f"Loading scaler from: {SCALER_PATH}")
        self.scaler = joblib.load(SCALER_PATH)
        log.info(f"Model loaded successfully (version: {MODEL_VERSION})")

        try:
            log.info(f"Loading window model from: {SCAN_MODEL_PATH}")
            self.scan_model = joblib.load(SCAN_MODEL_PATH)
            log.info(f"Loading window scaler from: {SCAN_SCALER_PATH}")
            self.scan_scaler = joblib.load(SCAN_SCALER_PATH)
            log.info("Window-based model loaded successfully")
        except Exception as e:
            log.warning(f"Could not load window model: {e}")

    def init_flow_csv(self):
        os.makedirs(os.path.dirname(FLOW_CSV_PATH), exist_ok=True)
        file_exists = os.path.exists(FLOW_CSV_PATH) and os.path.getsize(FLOW_CSV_PATH) > 0
        self.flow_csv_file = open(FLOW_CSV_PATH, "a", newline="")
        self.flow_csv_writer = csv.writer(self.flow_csv_file)
        if not file_exists:
            self.flow_csv_writer.writerow(CSV_HEADER)
            self.flow_csv_file.flush()
        log.info(f"Flows CSV will be written to: {FLOW_CSV_PATH}")

    def flow_to_features(self, flow):
        features = []
        for col in FEATURE_COLUMNS:
            val = getattr(flow, col, 0)
            features.append(float(val) if val is not None else 0.0)
        return np.array(features)

    def get_per_flow_score(self, features):
        features_clean = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
        features_scaled = self.scaler.transform([features_clean])
        score = self.model.decision_function(features_scaled)[0]
        return float(score)

    def normalize_protocol(self, proto_val):
        proto_str = str(proto_val).lower()
        mapping = {
            "6": "tcp",
            "17": "udp",
            "1": "icmp",
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
        }
        return mapping.get(proto_str, "tcp")

    def log_flow_to_csv(self, flow, detection_layer, anomaly_score):
        protocol = self.normalize_protocol(getattr(flow, "protocol", 0))
        row = [
            datetime.now(LOCAL_TZ).isoformat(),
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            protocol,
            detection_layer,
            round(anomaly_score, 4),
        ] + [float(getattr(flow, col, 0) or 0) for col in FEATURE_COLUMNS]

        if self.flow_csv_writer:
            self.flow_csv_writer.writerow(row)
            self.flow_csv_file.flush()

    def create_per_flow_alert(self, anomalous_flows):
        flows = [f for f, _ in anomalous_flows]
        scores = [s for _, s in anomalous_flows]

        unique_src_ips = list(set(f.src_ip for f in flows))
        unique_dst_ports = list(set(f.dst_port for f in flows))
        total_packets = sum(f.bidirectional_packets for f in flows)
        total_bytes = sum(f.bidirectional_bytes for f in flows)
        worst_score = min(scores)

        proto_val = getattr(flows[0], "protocol", "tcp")
        protocol = self.normalize_protocol(proto_val)

        src_ip = unique_src_ips[0] if len(unique_src_ips) == 1 else "10.10.10.3"

        return {
            "source_type": "ml_model",
            "detection_layer": "per_flow_anomaly",
            "timestamp": datetime.now(LOCAL_TZ).isoformat(),
            "src_ip": src_ip,
            "dst_ip": SERVER_IP,
            "src_port": 0,
            "dst_port": unique_dst_ports[0] if len(unique_dst_ports) == 1 else 0,
            "protocol": protocol,
            "anomaly_score": round(worst_score, 4),
            "model_version": MODEL_VERSION,
            "is_anomaly": True,
            "description": (
                f"{len(flows)} anomalous flow(s) in batch: "
                f"{len(unique_src_ips)} unique IPs, "
                f"{total_packets} packets, "
                f"{total_bytes} bytes"
            ),
            "features_snapshot": {
                "batch_flows": len(flows),
                "unique_ips": len(unique_src_ips),
                "unique_ports": len(unique_dst_ports),
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "worst_score": round(worst_score, 4),
                "all_scores": [round(s, 4) for s in scores],
            },
        }

    def maybe_flush_per_flow_batch(self):
        with self._batch_lock:
            if time.time() - self.batch_start >= ALERT_BATCH_SECONDS:
                self._flush_per_flow_batch_locked()

    def _flush_per_flow_batch_locked(self):
        if self.pending_anomalies:
            alert = self.create_per_flow_alert(self.pending_anomalies)
            self.write_alert(alert)
            self.per_flow_alert_count += 1
            self.pending_anomalies = []
        self.batch_start = time.time()

    def queue_per_flow_anomaly(self, flow, score):
        """
        FIX: this is the piece that was missing entirely in the previous
        version. Every place that computes a per-flow score and decides
        it's anomalous must call this, or pending_anomalies stays empty
        forever and per_flow_anomaly alerts never reach alerts.log.
        """
        with self._batch_lock:
            self.pending_anomalies.append((flow, score))

    def is_failed_flow(self, flow):
        return (
            (flow.bidirectional_syn_packets >= 1 and flow.bidirectional_ack_packets == 0)
            or flow.bidirectional_rst_packets >= 1
        )

    def build_window_features(self, flows):
        dst_ports = set()
        dst_ips = set()
        total = len(flows)
        failed = 0
        durations = []
        bytes_list = []

        for f in flows:
            dst_ports.add(f.dst_port)
            dst_ips.add(f.dst_ip)
            if self.is_failed_flow(f):
                failed += 1
            durations.append(f.bidirectional_duration_ms)
            bytes_list.append(f.bidirectional_bytes)

        unique_dst_ports = len(dst_ports)
        unique_dst_ips = len(dst_ips)
        failed_ratio = failed / total if total else 0
        port_diversity_rate = unique_dst_ports / total if total else 0
        connection_rate = total / SCAN_WINDOW_SECONDS
        avg_duration = np.mean(durations) if durations else 0
        max_duration = np.max(durations) if durations else 0
        std_duration = np.std(durations) if durations else 0
        avg_bytes = np.mean(bytes_list) if bytes_list else 0

        return [
            unique_dst_ports,
            unique_dst_ips,
            total,
            failed_ratio,
            port_diversity_rate,
            connection_rate,
            avg_duration,
            max_duration,
            std_duration,
            avg_bytes,
        ]

    def evaluate_per_flow(self, flow):
        """
        Shared helper: score a single flow with the per-flow model, log it
        to flows.csv with the right detection_layer, AND (this is the fix)
        queue it for alerting when it crosses PER_FLOW_THRESHOLD.
        """
        score = self.get_per_flow_score(self.flow_to_features(flow))
        if score < PER_FLOW_THRESHOLD:
            self.log_flow_to_csv(flow, "per_flow_anomaly", score)
            self.queue_per_flow_anomaly(flow, score)
        else:
            self.log_flow_to_csv(flow, "normal", score)

    def check_window_anomalies(self):
        with self._window_lock:
            if not self.window_flows:
                return
            windows = dict(self.window_flows)
            self.window_flows.clear()

        for src_ip, flows in windows.items():
            # FIX: the per-flow model used to only run on flows whose window
            # was NOT flagged as anomalous (it sat in the "else" branch
            # below). That meant any window the scan_persistent model
            # flagged had its flows logged straight as "window_anomaly" and
            # never reached the per-flow model at all, making the two
            # layers mutually exclusive instead of independent. Evaluating
            # every flow here, unconditionally, restores the two layers as
            # separate, independent checks on the same traffic.
            for flow in flows:
                self.evaluate_per_flow(flow)

            if len(flows) < 2:
                continue

            feats = self.build_window_features(flows)
            feats_df = pd.DataFrame([feats], columns=WINDOW_FEATURES)
            feats_scaled = self.scan_scaler.transform(feats_df)
            score = self.scan_model.decision_function(feats_scaled)[0]

            if score < SCAN_THRESHOLD:
                for flow in flows:
                    self.log_flow_to_csv(flow, "window_anomaly", score)

                alert = self.create_window_alert(src_ip, flows, score)
                self.write_alert(alert)

    def create_window_alert(self, src_ip, flows, score):
        self.window_alert_count += 1
        dst_ports = sorted(set(f.dst_port for f in flows))
        return {
            "source_type": "ml_model",
            "detection_layer": "window_anomaly",
            "timestamp": datetime.now(LOCAL_TZ).isoformat(),
            "src_ip": src_ip,
            "dst_ip": SERVER_IP,
            "src_port": 0,
            "dst_port": dst_ports[0] if dst_ports else 0,
            "protocol": "tcp",
            "anomaly_score": round(score, 4),
            "model_version": MODEL_VERSION,
            "is_anomaly": True,
            "description": (
                f"Window-based anomaly from {src_ip}: "
                f"{len(flows)} flows over {SCAN_WINDOW_SECONDS}s "
                f"to {len(dst_ports)} distinct ports"
            ),
            "features_snapshot": {
                "flow_count": len(flows),
                "unique_ports": len(dst_ports),
                "window_seconds": SCAN_WINDOW_SECONDS,
                "threshold": SCAN_THRESHOLD,
                "score": round(score, 4),
            },
        }

    def window_checker_loop(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(SCAN_WINDOW_SECONDS)
            if self._stop_event.is_set():
                break
            self.check_window_anomalies()

    def write_alert(self, alert):
        os.makedirs(os.path.dirname(ALERT_LOG_PATH), exist_ok=True)
        with open(ALERT_LOG_PATH, "a", buffering=1) as f:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")
            f.flush()

        self.alert_count += 1
        log.info(
            f"ALERT #{self.alert_count} [{alert['detection_layer']}]: "
            f"{alert['description']} "
            f"score={alert['anomaly_score']:.4f}"
        )

    def handle_flow(self, flow):
        self.flow_count += 1

        with self._window_lock:
            self.window_flows[flow.src_ip].append(flow)

        self.maybe_flush_per_flow_batch()

    def run(self):
        self.load_model()
        self.init_flow_csv()

        log.info(f"Starting live capture on interface: {IFACE}")
        log.info(f"idle_timeout={IDLE_TIMEOUT}s active_timeout={ACTIVE_TIMEOUT}s min_packets={MIN_BIDIRECTIONAL_PACKETS}")
        log.info(f"Per-Flow batching every {ALERT_BATCH_SECONDS}s, threshold={PER_FLOW_THRESHOLD}")
        log.info(f"Window-threshold: {SCAN_THRESHOLD} window={SCAN_WINDOW_SECONDS}s")
        log.info(f"Alerts will be written to: {ALERT_LOG_PATH}")
        log.info(f"Flows will be written to: {FLOW_CSV_PATH}")
        log.info("-" * 60)

        window_thread = threading.Thread(target=self.window_checker_loop, daemon=True)
        window_thread.start()

        streamer = NFStreamer(
            source=IFACE,
            statistical_analysis=True,
            idle_timeout=IDLE_TIMEOUT,
            active_timeout=ACTIVE_TIMEOUT,
        )

        log_interval = 0
        try:
            for flow in streamer:
                self.handle_flow(flow)

                log_interval += 1
                if log_interval >= 500:
                    log_interval = 0
                    log.info(
                        f"Flows: {self.flow_count} | "
                        f"Alerts: {self.alert_count} "
                        f"(per_flow={self.per_flow_alert_count}, "
                        f"window={self.window_alert_count})"
                    )

        except KeyboardInterrupt:
            self.check_window_anomalies()
            with self._batch_lock:
                self._flush_per_flow_batch_locked()
            log.info(f"Detector stopped. Flows: {self.flow_count}, Alerts: {self.alert_count}")
        except Exception as e:
            self.check_window_anomalies()
            with self._batch_lock:
                self._flush_per_flow_batch_locked()
            log.error(f"Fatal error: {e}")
            raise
        finally:
            self._stop_event.set()
            if self.flow_csv_file:
                self.flow_csv_file.close()


def main():
    detector = MLDetector()
    detector.run()


if __name__ == "__main__":
    main()