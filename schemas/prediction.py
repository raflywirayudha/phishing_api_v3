from pydantic import BaseModel
from typing import Optional

class URLRequest(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    status: str
    layer: str
    probability: float
    total_server_latency_ms: Optional[float] = None