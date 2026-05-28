from typing import List, Optional

from pydantic import BaseModel


class DetectedSecret(BaseModel):
    type: str
    severity: str
    start: int
    end: int
    masked_value: str


class ScanResponse(BaseModel):
    input_type: str
    filename: Optional[str] = None
    detected_count: int
    risk_score: int
    detected_types: List[str]
    detections: List[DetectedSecret]
    sanitized_output: str
