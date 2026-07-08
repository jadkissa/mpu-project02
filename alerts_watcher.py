#!/usr/bin/env python3
# alerts_watcher.py

import os
import time
import json
import requests
from datetime import datetime, timezone, timedelta

ALERTS_DIR = "./snort_logs"
ALERT_FILE = os.path.join(ALERTS_DIR, "alert_json.txt")

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000/api/alerts/ingest")

# Define UTC+3 timezone (Damascus)
UTC_PLUS_3 = timezone(timedelta(hours=3))

file_position = 0

PROTO_MAP = {"tcp": "tcp", "udp": "udp", "icmp": "icmp"}


def process_new_lines():
    global file_position

    if not os.path.exists(ALERT_FILE):
        return

    try:
        with open(ALERT_FILE, "r") as f:
            f.seek(file_position)
            new_lines = f.readlines()
            file_position = f.tell()

        alerts = []
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                alerts.append(alert)
            except json.JSONDecodeError:
                print(f"Could not parse line: {line[:80]}")

        if alerts:
            send_alerts(alerts)

    except Exception as e:
        print(f"Error reading file: {e}")


def convert_to_utc_plus_3(timestamp_str):
    """Convert Snort timestamp (UTC) to UTC+3 (Damascus time)"""
    try:
        # Parse Snort timestamp format: "04/19-08:53:41.975661"
        ts = datetime.strptime(timestamp_str, "%m/%d-%H:%M:%S.%f")
        ts = ts.replace(year=datetime.now().year)

        # Make it timezone-aware as UTC
        ts_utc = ts.replace(tzinfo=timezone.utc)

        # Convert to UTC+3
        ts_damascus = ts_utc.astimezone(UTC_PLUS_3)

        # Return as ISO string for JSON transport
        return ts_damascus.isoformat()
    except Exception as e:
        print(f"Error converting timestamp {timestamp_str}: {e}")
        # Fallback to current time in UTC+3
        return datetime.now(UTC_PLUS_3).isoformat()


def build_payload(alert):
    sid_val  = alert.get("sid", 0)
    gid_val  = alert.get("gid", 1)
    rev_val  = alert.get("rev", 0)
    msg      = alert.get("msg", "")
    priority = alert.get("priority", 0)
    proto    = alert.get("proto", "")
    src_ip   = alert.get("src_addr", "0.0.0.0")
    dst_ip   = alert.get("dst_addr", "0.0.0.0")
    src_port = alert.get("src_port", 0)
    dst_port = alert.get("dst_port", 0)
    timestamp_raw = alert.get("timestamp", "")

    timestamp = convert_to_utc_plus_3(timestamp_raw)
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


def send_alerts(alerts):
    sent = 0
    for alert in alerts:
        payload = build_payload(alert)
        try:
            response = requests.post(BACKEND_URL, json=payload, timeout=5)
            response.raise_for_status()
            sent += 1
        except requests.RequestException as e:
            print(f"Failed to send alert (sid={payload.get('signature_id')}): {e}")
            continue

    if sent > 0:
        print(f"Sent {sent} alerts at {datetime.now(UTC_PLUS_3).strftime('%Y-%m-%d %H:%M:%S')} (UTC+3)")


if __name__ == "__main__":
    print("Monitoring ./snort_logs for Snort 3 JSON alerts...")
    print(f"Forwarding alerts to backend at: {BACKEND_URL}")
    print(f"Current UTC+3 time: {datetime.now(UTC_PLUS_3).strftime('%Y-%m-%d %H:%M:%S')}")

    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "r") as f:
            f.seek(0, 2)
            file_position = f.tell()
        print(f"Starting from end of file (position {file_position})")

    while True:
        try:
            process_new_lines()
        except Exception as e:
            print(f"Loop error: {e}")
        time.sleep(1)