import os
import time
import json
import requests
from datetime import datetime, timezone, timedelta

SNORT_ALERTS_DIR = "./snort_logs"
SNORT_ALERT_FILE = os.path.join(SNORT_ALERTS_DIR, "alert_json.txt")

ML_ALERT_FILE = os.getenv("ML_ALERT_FILE", "./ml_alerts/alerts.log")

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000/api/alerts/ingest")

UTC_PLUS_3 = timezone(timedelta(hours=3))

file_positions = {
    "snort": 0,
    "ml": 0,
}

PROTO_MAP = {"tcp": "tcp", "udp": "udp", "icmp": "icmp"}


def convert_snort_timestamp(timestamp_str):
    try:
        ts = datetime.strptime(timestamp_str, "%m/%d-%H:%M:%S.%f")
        ts = ts.replace(year=datetime.now().year)
        ts_utc = ts.replace(tzinfo=timezone.utc)
        ts_damascus = ts_utc.astimezone(UTC_PLUS_3)
        return ts_damascus.isoformat()
    except Exception as e:
        print(f"Error converting Snort timestamp {timestamp_str}: {e}")
        return datetime.now(UTC_PLUS_3).isoformat()


def build_payload_snort(alert):
    sid_val = alert.get("sid", 0)
    gid_val = alert.get("gid", 1)
    rev_val = alert.get("rev", 0)
    msg = alert.get("msg", "")
    priority = alert.get("priority", 0)
    proto = alert.get("proto", "")
    src_ip = alert.get("src_addr", "0.0.0.0")
    dst_ip = alert.get("dst_addr", "0.0.0.0")
    src_port = alert.get("src_port", 0)
    dst_port = alert.get("dst_port", 0)
    timestamp_raw = alert.get("timestamp", "")

    timestamp = convert_snort_timestamp(timestamp_raw)
    protocol = PROTO_MAP.get(str(proto).lower(), "unknown")

    return {
        "source_type": "snort",
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "signature_id": sid_val,
        "signature_gen": gid_val,
        "signature_rev": rev_val,
        "signature_msg": msg,
        "priority": priority,
    }


def build_payload_ml(alert):
    proto_raw = str(alert.get("protocol", "tcp")).lower()
    proto_mapping = {
        "6": "tcp",
        "17": "udp",
        "1": "icmp",
        "tcp": "tcp",
        "udp": "udp",
        "icmp": "icmp",
        "unknown": "tcp",
    }
    protocol = proto_mapping.get(proto_raw, "tcp")

    src_ip = alert.get("src_ip", "0.0.0.0")
    dst_ip = alert.get("dst_ip", "0.0.0.0")
    if src_ip == "multiple":
        src_ip = "0.0.0.0"
    if dst_ip == "multiple":
        dst_ip = "0.0.0.0"

    return {
        "source_type": "ml_model",
        "detection_layer": alert.get("detection_layer", "isolation_forest"),
        "timestamp": alert.get("timestamp", datetime.now(UTC_PLUS_3).isoformat()),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": alert.get("src_port", 0),
        "dst_port": alert.get("dst_port", 0),
        "protocol": protocol,
        "anomaly_score": alert.get("anomaly_score", 0.0),
        "model_version": alert.get("model_version", "1.0.0"),
        "description": (alert.get("description", "") or "")[:200],
    }


def process_file(file_path, source_key, payload_builder):
    if not os.path.exists(file_path):
        return

    try:
        with open(file_path, "r") as f:
            f.seek(file_positions[source_key])
            new_lines = f.readlines()
            file_positions[source_key] = f.tell()

        alerts = []
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                alerts.append(payload_builder(alert))
            except json.JSONDecodeError:
                print(f"[{source_key}] Could not parse line: {line[:80]}")

        if alerts:
            send_alerts(alerts, source_key)

    except Exception as e:
        print(f"[{source_key}] Error reading file: {e}")


def send_alerts(payloads, source_key):
    sent = 0
    for payload in payloads:
        try:
            response = requests.post(BACKEND_URL, json=payload, timeout=5)
            response.raise_for_status()
            sent += 1
        except requests.RequestException as e:
            print(f"[{source_key}] Failed to send alert: {e}")
            continue

    if sent > 0:
        print(f"[{source_key}] Sent {sent} alerts at {datetime.now(UTC_PLUS_3).strftime('%Y-%m-%d %H:%M:%S')} (UTC+3)")


def init_position(file_path, source_key):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            f.seek(0, 2)
            file_positions[source_key] = f.tell()
            print(f"[{source_key}] Starting from end of file (position {file_positions[source_key]})")


if __name__ == "__main__":
    print("Monitoring Snort and ML detector alert files...")
    print(f"Forwarding alerts to backend at: {BACKEND_URL}")
    print(f"Current UTC+3 time: {datetime.now(UTC_PLUS_3).strftime('%Y-%m-%d %H:%M:%S')}")

    init_position(SNORT_ALERT_FILE, "snort")
    init_position(ML_ALERT_FILE, "ml")

    while True:
        try:
            process_file(SNORT_ALERT_FILE, "snort", build_payload_snort)
            process_file(ML_ALERT_FILE, "ml", build_payload_ml)
        except Exception as e:
            print(f"Loop error: {e}")
        time.sleep(1)