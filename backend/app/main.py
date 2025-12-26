from fastapi import FastAPI
from app.api.predict import router

app = FastAPI(title="Multi-Stage IDS")

app.include_router(router)

@app.get("/")
def health():
    return {"status": "IDS backend running"}
