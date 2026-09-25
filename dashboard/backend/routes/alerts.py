from fastapi import APIRouter, HTTPException, Query
from typing import Literal
from psycopg2.extras import Json

from database import query, execute_transaction
from schemas.alerts import AlertIngest

router = APIRouter()

PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1}


def _fetch_snort_alerts(limit: int):
    return query("""
        SELECT
            e.sid,
            e.cid,
            e.signature,
            e.timestamp,
            host(e.ip_src) AS ip_src,
            host(e.ip_dst) AS ip_dst,
            e.layer4_sport,
            e.layer4_dport,
            e.ip_proto,
            e.priority,
            s.sig_name
        FROM event e
        LEFT JOIN signature s ON s.sig_sid = e.signature_id
        ORDER BY e.timestamp DESC
        LIMIT %s
    """, (limit,))


def _fetch_ml_alerts(limit: int):
    return query("""
        SELECT
            id,
            timestamp,
            host(ip_src) AS ip_src,
            host(ip_dst) AS ip_dst,
            layer4_sport,
            layer4_dport,
            ip_proto,
            anomaly_score,
            model_version,
            detection_layer,
            features_snapshot
        FROM ml_alert
        ORDER BY timestamp DESC
        LIMIT %s
    """, (limit,))


@router.get("")
def get_alerts(
    source_type: Literal["snort", "ml_model"] = Query(..., description="Alert source filter"),
    limit: int = 1000,
):
    if source_type == "snort":
        rows = _fetch_snort_alerts(limit)
    else:
        rows = _fetch_ml_alerts(limit)
    return {"data": rows, "source_type": source_type}


@router.get("/snort")
def get_snort_alerts(limit: int = 1000):
    rows = _fetch_snort_alerts(limit)
    return {"data": rows}


@router.post("/ingest")
def ingest_alert(alert: AlertIngest):
    if alert.source_type == "snort":
        return _ingest_snort_alert(alert)
    return _ingest_ml_alert(alert)


def _ingest_snort_alert(alert: AlertIngest):
    proto_num = PROTO_MAP.get(alert.protocol.lower(), 0)

    statements = [
        ("""
            INSERT INTO signature (sig_sid, sig_name, sig_priority, sig_rev)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (alert.signature_id, alert.signature_msg, alert.priority, alert.signature_rev)),

        ("""
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
            alert.signature_msg, alert.signature_gen, alert.signature_id, alert.signature_rev,
            alert.timestamp,
            alert.src_ip, alert.dst_ip, alert.src_port, alert.dst_port,
            proto_num, alert.priority
        )),

        ("""
            UPDATE statistics SET
                total_snort_alerts = total_snort_alerts + 1,
                high_threats   = high_threats   + CASE WHEN %s = 1 THEN 1 ELSE 0 END,
                medium_threats = medium_threats + CASE WHEN %s = 2 THEN 1 ELSE 0 END,
                updated_at = NOW() AT TIME ZONE 'Asia/Damascus'
            WHERE id = 1
        """, (alert.priority, alert.priority)),
    ]

    try:
        execute_transaction(statements)
        return {"status": "accepted", "source_type": "snort"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


def _ingest_ml_alert(alert: AlertIngest):
    if alert.anomaly_score is None:
        raise HTTPException(status_code=422, detail="anomaly_score is required for ml_model alerts")
    if not alert.model_version:
        raise HTTPException(status_code=422, detail="model_version is required for ml_model alerts")

    proto_num = PROTO_MAP.get(alert.protocol.lower(), 0)
    features = Json(alert.features_snapshot) if alert.features_snapshot is not None else None
    detection_layer = alert.detection_layer or "isolation_forest"

    statements = [
        ("""
            INSERT INTO ml_alert
            (timestamp, ip_src, ip_dst, layer4_sport, layer4_dport, ip_proto,
             anomaly_score, model_version, detection_layer, features_snapshot)
            VALUES (
                %s::timestamptz,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s
            )
        """, (
            alert.timestamp,
            alert.src_ip, alert.dst_ip, alert.src_port, alert.dst_port,
            proto_num, alert.anomaly_score, alert.model_version, detection_layer, features,
        )),
    ]

    try:
        execute_transaction(statements)
        return {"status": "accepted", "source_type": "ml_model"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")