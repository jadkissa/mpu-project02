from pydantic import BaseModel
from typing import Optional, Literal, Any


class AlertIngest(BaseModel):
    source_type: Literal["snort", "ml_model"]
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str

    signature_id: Optional[int] = None
    signature_gen: Optional[int] = None
    signature_rev: Optional[int] = None
    signature_msg: Optional[str] = None
    priority: Optional[int] = None

    anomaly_score: Optional[float] = None
    is_anomaly: Optional[bool] = None
    model_version: Optional[str] = None
    detection_layer: Optional[str] = None
    features_snapshot: Optional[dict[str, Any]] = None