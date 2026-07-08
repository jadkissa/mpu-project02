# stats.py
from fastapi import APIRouter
from database import query

router = APIRouter()

@router.get("/summary")
def get_summary():
    rows = query("""
        SELECT
            (SELECT COUNT(*) FROM event) AS total_snort_alerts,
            (SELECT COUNT(*) FROM event WHERE priority = 1) AS high_threats,
            (SELECT COUNT(*) FROM event WHERE priority = 2) AS medium_threats
    """)
    if not rows:
        return {
            "total_snort_alerts": 0,
            "high_threats": 0,
            "medium_threats": 0
        }
    return rows[0]

@router.get("/by-protocol")
def get_by_protocol():
    rows = query("""
        SELECT
            CASE ip_proto
                WHEN 6  THEN 'TCP'
                WHEN 17 THEN 'UDP'
                WHEN 1  THEN 'ICMP'
                ELSE 'Other'
            END AS protocol,
            COUNT(*) AS count
        FROM event
        GROUP BY ip_proto
        ORDER BY count DESC
    """)
    return {"data": rows}

@router.get("/by-priority")
def get_by_priority():
    rows = query("""
        SELECT
            priority,
            COUNT(*) AS count
        FROM event
        GROUP BY priority
        ORDER BY priority ASC
    """)
    return {"data": rows}

@router.get("/timeline")
def get_timeline():
    rows = query("""
        SELECT
            DATE_TRUNC('hour', timestamp) AS hour,
            COUNT(*) AS count
        FROM event
        GROUP BY hour
        ORDER BY hour DESC
        LIMIT 24
    """)
    return {"data": rows}