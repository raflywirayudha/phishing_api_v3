from pydantic import BaseModel
from typing import Optional

class URLRequest(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    status: str
    layer: str
    probability: float
    # subdomain: Optional[str] = None
    # domain: Optional[str] = None
    features: Optional[list] = None
    latency: Optional[float] = None