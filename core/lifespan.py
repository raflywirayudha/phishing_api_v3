import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Inisialisasi HTTP Client global untuk connection pooling
    app.state.requests_client = httpx.AsyncClient()
    yield
    # Shutdown: Tutup koneksi dengan aman untuk mencegah memory leak
    await app.state.requests_client.aclose()