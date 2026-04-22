from pydantic import BaseModel
from typing import Optional

class URLRequest(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    status: str
    layer: str
    probability: float
    total_server_latency_ms: Optional[float] = None
    domain: Optional[str] = None
    subdomain: Optional[str] = None
    ml_features: Optional[list] = None