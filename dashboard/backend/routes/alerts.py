from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Literal
from database import query, execute_transaction

router = APIRouter()


class AlertIngest(BaseModel):
    source_type: Literal["snort", "ml_north_south", "ml_east_west"]
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str

    # Snort-specific fields
    signature_id: Optional[int] = None
    signature_gen: Optional[int] = None
    signature_rev: Optional[int] = None
    signature_msg: Optional[str] = None
    priority: Optional[int] = None

    # ML-specific fields (reserved for later use)
    anomaly_score: Optional[float] = None
    is_anomaly: Optional[bool] = None
    model_version: Optional[str] = None


PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1}


@router.get("/snort")
def get_snort_alerts(limit: int = 1000):
    rows = query("""
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
    return {"data": rows}


@router.post("/ingest")
def ingest_alert(alert: AlertIngest):
    if alert.source_type == "snort":
        return _ingest_snort_alert(alert)
    else:
        raise HTTPException(status_code=501, detail="ML alert ingestion not implemented yet")


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