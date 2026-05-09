import time
import asyncio
from fastapi import APIRouter, Request
import tldextract

from schemas.prediction import URLRequest, ScanResponse
from services.blacklist_service import check_phishtank
from services.whitelist_service import check_tranco
from ml.ml_service import ml_engine
from core.config import prediction_cache

router = APIRouter()
extractor = tldextract.TLDExtract(include_psl_private_domains=True)

@router.get("/")
async def root():
    return {
        "app": "Raphish API",
        "status": "running",
    }

@router.post("/scan", response_model=ScanResponse)
async def predict_phishing(request: URLRequest, fastapi_req: Request):
    url = request.url

    print(f"SCAN:     {url}")
    
    # Cek cache
    if url in prediction_cache:
        return prediction_cache[url]

    start_time = time.time()
    client = fastapi_req.app.state.requests_client
    
    # Penggunaan tldextract
    ext = extractor(url)
    registered_domain = ext.top_domain_under_public_suffix
    
    try:
        # Eksekusi paralel
        tasks = [
            check_phishtank(client, url),
            check_tranco(client, registered_domain),
            asyncio.to_thread(ml_engine.predict, url)
        ]
        
        # Menunggu semua hasil selesai dikumpulkan
        is_blacklisted, is_whitelisted, ml_data = await asyncio.gather(*tasks)
        
        # Logika prioritas keputusan
        if is_blacklisted:
            res = {
                "status": "phishing",
                "layer": "blacklist",
                "probability": 1.0
            }
        elif is_whitelisted and not ext.is_private:
            res = {
                "status": "safe",
                "layer": "whitelist",
                "probability": 0.0
            }
        else:
            # Jika is_private=True, sistem dipaksa masuk ke sini (Layer 3 - ML)
            if ext.is_private:
                print(f"          {registered_domain} terdeteksi sebagai Private Suffix (PaaS). Wajib analisis ML.")
            
            res = {
                "status": "phishing" if ml_data["probability"] > 0.7 else "safe",
                "layer": "ml",
                "probability": round(ml_data["probability"], 4),
                "features": ml_data["features"],
                "domain": ext.top_domain_under_public_suffix
            }

        res["latency"] = round((time.time() - start_time) * 1000, 2)
        res["domain"] = registered_domain
        res["subdomain"] = ext.subdomain if ext.subdomain else "-"
        
        # Simpan ke cache
        prediction_cache[url] = res
        return res

    except Exception as e:
        return {
            "status": "error",
            "layer": "error",
            "probability": 0.0,
            "subdomain": "error",
            "domain": "error",
            "latency": round((time.time() - start_time) * 1000, 2),
        }