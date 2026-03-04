import time
import asyncio
from fastapi import FastAPI, Request
from urllib.parse import urlparse

from core.lifespan import lifespan
from schemas.prediction import URLRequest, PredictionResponse
from services.blacklist_service import check_phishtank
from services.whitelist_service import check_tranco
from services.ml_service import ml_engine

app = FastAPI(lifespan=lifespan)
prediction_cache = {}


#  # Berurutan
# @app.post("/predict", response_model=PredictionResponse)
# async def predict_phishing(request: URLRequest, fastapi_req: Request):
#     url = request.url
    
#     # 1. CEK CACHE
#     if url in prediction_cache:
#         return prediction_cache[url]

#     start_time = time.time()
#     parsed_url = urlparse(url)
#     hostname = (parsed_url.hostname or "").replace("www.", "")
#     client = fastapi_req.app.state.requests_client

#     try:
#         # 2. EKSEKUSI SEKUENSIAL (Layer per layer dengan Short-Circuiting)
        
#         # Layer 1: Blacklist (Hanya lanjut jika tidak masuk blacklist)
#         is_blacklisted = await check_phishtank(client, url)
        
#         if is_blacklisted:
#             res = {
#                 "status": "phishing", 
#                 "layer": "blacklist", 
#                 "probability": 1.0
#             }
#         else:
#             # Layer 2: Whitelist (Hanya lanjut jika tidak masuk whitelist)
#             is_whitelisted = await check_tranco(client, hostname)
            
#             if is_whitelisted:
#                 res = {
#                     "status": "safe", 
#                     "layer": "whitelist", 
#                     "probability": 0.0
#                 }
#             else:
#                 # Layer 3: ML (Hanya dijalankan jika Layer 1 & 2 tidak memberikan hasil pasti)
#                 ml_prob = await asyncio.to_thread(ml_engine.predict, url)
#                 res = {
#                     "status": "phishing" if ml_prob > 0.8 else "safe",
#                     "layer": "ml",
#                     "probability": round(ml_prob, 4)
#                 }

#         # Tambahkan latensi server
#         res["total_server_latency_ms"] = round((time.time() - start_time) * 1000, 2)
        
#         # Simpan ke cache
#         prediction_cache[url] = res
#         return res

#     except Exception as e:
#         return {
#             "status": "safe", 
#             "layer": "error", 
#             "probability": 0.0,
#             "total_server_latency_ms": round((time.time() - start_time) * 1000, 2)
#         }

 # Paralel
@app.post("/predict", response_model=PredictionResponse)
async def predict_phishing(request: URLRequest, fastapi_req: Request):
    url = request.url
    
    # 1. CEK CACHE
    if url in prediction_cache:
        return prediction_cache[url]

    start_time = time.time()
    parsed_url = urlparse(url)
    hostname = (parsed_url.hostname or "").replace("www.", "")
    client = fastapi_req.app.state.requests_client

    try:
        # 2. EKSEKUSI PARALEL (Layer 1, 2, dan 3 dijalankan bersamaan)
        # ml_engine.predict dijalankan di thread agar tidak memblokir async loop
        tasks = [
            check_phishtank(client, url),             # Layer 1 (I/O Bound)
            check_tranco(client, hostname),           # Layer 2 (I/O Bound)
            asyncio.to_thread(ml_engine.predict, url) # Layer 3 (CPU Bound - Speculative)
        ]
        
        # Menunggu semua hasil selesai dikumpulkan
        is_blacklisted, is_whitelisted, ml_prob = await asyncio.gather(*tasks)

        # 3. LOGIKA PRIORITAS KEPUTUSAN
        # Walaupun semua hasil sudah ada, kita tetap mengikuti aturan prioritas:
        if is_blacklisted:
            res = {
                "status": "phishing", 
                "layer": "blacklist", 
                "probability": 1.0
            }
        elif is_whitelisted:
            res = {
                "status": "safe", 
                "layer": "whitelist", 
                "probability": 0.0
            }
        else:
            res = {
                "status": "phishing" if ml_prob > 0.8 else "safe",
                "layer": "ml",
                "probability": round(ml_prob, 4)
            }

        # Tambahkan latensi server
        res["total_server_latency_ms"] = round((time.time() - start_time) * 1000, 2)
        
        # Simpan ke cache
        prediction_cache[url] = res
        return res

    except Exception as e:
        return {
            "status": "safe", 
            "layer": "error", 
            "probability": 0.0,
            "total_server_latency_ms": round((time.time() - start_time) * 1000, 2)
        }