import time
import asyncio
from fastapi import FastAPI, Request
from urllib.parse import urlparse
import tldextract
from core.lifespan import lifespan
from schemas.prediction import URLRequest, PredictionResponse
from services.blacklist_service import check_phishtank
from services.whitelist_service import check_tranco
from services.ml_service import ml_engine

app = FastAPI(lifespan=lifespan)
prediction_cache = {}

extractor = tldextract.TLDExtract(include_psl_private_domains=True)

@app.get("/")
async def root():
    return {
        "app": "Raphish API",
        "status": "running",
    }

# Paralel
@app.post("/scan", response_model=PredictionResponse)
async def predict_phishing(request: URLRequest, fastapi_req: Request):
    url = request.url
    
    # Cek cache
    if url in prediction_cache:
        return prediction_cache[url]

    start_time = time.time()

    client = fastapi_req.app.state.requests_client

    # Penggunaan tldextract
    ext = extractor(url)
    registered_domain = ext.top_domain_under_public_suffix
    # top_domain_under_public_suffix otomatis menggabungkan domain + suffix (misal: uin-suska.ac.id)

    try:
        # Eksekusi paralel (Layer 1, 2, dan 3 dijalankan bersamaan)
        # ml_engine.predict dijalankan di thread agar tidak memblokir async loop
        tasks = [
            check_phishtank(client, url),             
            check_tranco(client, registered_domain),           
            asyncio.to_thread(ml_engine.predict, url)
        ]
        
        # Menunggu semua hasil selesai dikumpulkan
        is_blacklisted, is_whitelisted_raw, ml_data = await asyncio.gather(*tasks)

        # Logika priotitas keputusan
        # Walaupun semua hasil sudah ada, kita tetap mengikuti aturan prioritas:
        if is_blacklisted:
            res = {
                "status": "phishing", 
                "layer": "blacklist", 
                "probability": 1.0
            }
        elif is_whitelisted_raw and not ext.is_private:
            res = {
                "status": "safe", 
                "layer": "whitelist", 
                "probability": 0.0
            }
        else:

            # Jika is_private=True (seperti instaagrann.vercel.app), 
            # sistem dipaksa masuk ke sini (Layer 3 - ML)
            if ext.is_private:
                print(f"🚩 {registered_domain} terdeteksi sebagai Private Suffix (PaaS). Wajib analisis ML.")

            res = {
                "status": "phishing" if ml_data["probability"] > 0.8 else "safe",
                "layer": "ml",
                "probability": round(ml_data["probability"], 4),
                "ml_features": ml_data["features"],
                "domain": ext.top_domain_under_public_suffix
            }

        # Latensi server
        res["total_server_latency_ms"] = round((time.time() - start_time) * 1000, 2)
        res["domain"] = registered_domain
        res["subdomain"] = ext.subdomain if ext.subdomain else "-"

        # Simpan ke cache
        prediction_cache[url] = res
        return res

    except Exception as e:
        return {
            "status": "safe", 
            "layer": "error", 
            "probability": 0.0,
            "subdomain": "error",
            "domain": "error",
            "total_server_latency_ms": round((time.time() - start_time) * 1000, 2),
        }