from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.routers import traffic, zero_trust

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Firewall Backend",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(traffic.router)
app.include_router(zero_trust.router)

@app.get("/")
def root():
    return {"status": "Running", "docs": "/docs"}
