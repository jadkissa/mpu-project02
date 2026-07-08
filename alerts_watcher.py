#!/usr/bin/env python3
# alerts_watcher.py

import os
import time
import json
import psycopg2
from datetime import datetime, timezone, timedelta

ALERTS_DIR = "./snort_logs"
ALERT_FILE = os.path.join(ALERTS_DIR, "alert_json.txt")

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "mpu_db"),
    "user": os.getenv("DB_USER", "mpu"),
    "password": os.getenv("DB_PASSWORD", "123"),
    "host": os.getenv("DB_HOST", "postgres"),
    "port": int(os.getenv("DB_PORT", 5432))
}

# Define UTC+3 timezone (Damascus)
UTC_PLUS_3 = timezone(timedelta(hours=3))

file_position = 0


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
            insert_to_db(alerts)

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
        
        # Return as string without timezone info for database
        return ts_damascus.strftime("%Y-%m-%d %H:%M:%S.%f")
    except Exception as e:
        print(f"Error converting timestamp {timestamp_str}: {e}")
        # Fallback to current time in UTC+3
        return datetime.now(UTC_PLUS_3).strftime("%Y-%m-%d %H:%M:%S.%f")


def insert_to_db(alerts):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        inserted = 0
        for alert in alerts:
            try:
                sid_val   = alert.get("sid", 0)
                gid_val   = alert.get("gid", 1)
                rev_val   = alert.get("rev", 0)
                msg       = alert.get("msg", "")
                priority  = alert.get("priority", 0)
                proto     = alert.get("proto", "")
                src_ip    = alert.get("src_addr", "0.0.0.0")
                dst_ip    = alert.get("dst_addr", "0.0.0.0")
                src_port  = alert.get("src_port", 0)
                dst_port  = alert.get("dst_port", 0)
                timestamp_raw = alert.get("timestamp", "")
                
                # Convert timestamp to UTC+3
                timestamp = convert_to_utc_plus_3(timestamp_raw)

                proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
                proto_num = proto_map.get(str(proto).lower(), 0)

                cur.execute("""
                    INSERT INTO signature (sig_sid, sig_name, sig_priority, sig_rev)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (sid_val, msg, priority, rev_val))

                cur.execute("""
                    INSERT INTO event
                    (sid, cid, signature, signature_gen, signature_id, signature_rev,
                     timestamp, ip_src, ip_dst, layer4_sport, layer4_dport, ip_proto, priority)
                    VALUES (
                        1, nextval('event_cid_seq'),
                        %s, %s, %s, %s,
                        %s::timestamp,
                        %s, %s, %s, %s, %s, %s
                    )
                """, (
                    msg, gid_val, sid_val, rev_val,
                    timestamp,
                    src_ip, dst_ip, src_port, dst_port, proto_num, priority
                ))

                cur.execute("""
                    UPDATE statistics SET
                        total_snort_alerts = total_snort_alerts + 1,
                        high_threats   = high_threats   + CASE WHEN %s = 1 THEN 1 ELSE 0 END,
                        medium_threats = medium_threats + CASE WHEN %s = 2 THEN 1 ELSE 0 END,
                        updated_at = NOW() AT TIME ZONE 'Asia/Damascus'
                    WHERE id = 1
                """, (priority, priority))

                inserted += 1

            except Exception as e:
                print(f"Error inserting alert: {e}")
                conn.rollback()
                continue

        conn.commit()
        cur.close()
        conn.close()

        if inserted > 0:
            print(f"Inserted {inserted} alerts at {datetime.now(UTC_PLUS_3).strftime('%Y-%m-%d %H:%M:%S')} (UTC+3)")

    except Exception as e:
        print(f"DB connection error: {e}")


if __name__ == "__main__":
    print(f"Monitoring ./snort_logs for Snort 3 JSON alerts...")
    print(f"Converting all timestamps to UTC+3 (Damascus time)")
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