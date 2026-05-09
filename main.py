from fastapi import FastAPI
from core.lifespan import lifespan
from api.routes import router

# Inisialisasi aplikasi dengan lifespan untuk manajemen HTTP Client
app = FastAPI(lifespan=lifespan)

# Mendaftarkan semua endpoint dari folder api/
app.include_router(router)