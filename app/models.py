from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    input_type: str
    detected_count: int = 0
    risk_score: int = 0
    detected_types: str = "[]"
    created_at: datetime = Field(default_factory=datetime.utcnow)
