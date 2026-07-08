from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes.alerts import router as alerts_router
from routes.stats  import router as stats_router

app = FastAPI(
    title="NIDS Dashboard API",
    description="Network Intrusion Detection System — Backend API",
    version="1.0.0"
)

# Allow React frontend to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# Routes
app.include_router(alerts_router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(stats_router,  prefix="/api/stats",  tags=["Stats"])


@app.get("/")
def root():
    return {"status": "NIDS API is running"}