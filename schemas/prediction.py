from pydantic import BaseModel
from typing import Optional

class URLRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    status: str
    layer: str
    probability: float
    features: Optional[list] = None
    latency: Optional[float] = None


    # subdomain: Optional[str] = None
    # domain: Optional[str] = None