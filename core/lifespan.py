import httpx
from fastapi import FastAPI
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Mengelola siklus hidup resource aplikasi.
    Inisialisasi dilakukan saat startup, dan pembersihan saat shutdown.
    """
    # Mengatur limit koneksi agar server lebih efisien dan tidak memakan resource berlebih
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
    
    # Membuat satu instance AsyncClient yang akan digunakan oleh seluruh layer (Phishtank & Tranco)
    # Disimpan di app.state agar bisa diakses dari object Request di endpoint mana pun
    app.state.requests_client = httpx.AsyncClient(timeout=5.0, limits=limits)
    
    yield
    
    # Menutup koneksi secara rapi saat server dimatikan untuk menghindari memory leak
    await app.state.requests_client.aclose()