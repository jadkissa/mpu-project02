# backend/schemas/alerts.py
from pydantic import BaseModel
from typing import Optional, Literal


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

    # ML-specific fields (for later use)
    anomaly_score: Optional[float] = None
    is_anomaly: Optional[bool] = None
    model_version: Optional[str] = None