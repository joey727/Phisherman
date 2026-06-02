"""
FastAPI application for the Phisherman ML phishing URL classifier.

Endpoints:
  POST /predict  — Classify a URL as phishing / suspicious / safe
  GET  /health   — Health check (for ALB / ECS target group)
  GET  /ping     — SageMaker-compatible health check
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .schemas import PredictRequest, PredictResponse, HealthResponse
from .model import load_model, predict, is_model_loaded

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger("ml-service")


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the model at startup."""
    logger.info("Starting ML service — loading model...")
    loaded = load_model()
    if loaded:
        logger.info("Model loaded. Service ready for inference.")
    else:
        logger.warning("No trained model found. Service will use heuristic fallback.")
    yield
    logger.info("ML service shutting down.")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Phisherman ML Service",
    description="XGBoost-powered phishing URL classification microservice",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/predict", response_model=PredictResponse)
async def predict_endpoint(req: PredictRequest):
    """Classify a URL and return a risk score with explainability."""
    try:
        result = predict(req.url, req.meta)
        return PredictResponse(**result)
    except Exception as e:
        logger.error(f"Prediction failed for URL '{req.url}': {e}")
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint for ALB / ECS."""
    return HealthResponse(
        status="ok",
        model_loaded=is_model_loaded(),
        version="1.0.0",
    )


@app.get("/ping")
async def ping():
    """SageMaker-compatible health check."""
    return ""


@app.post("/invocations", response_model=PredictResponse)
async def invocations(req: PredictRequest):
    """SageMaker-compatible inference endpoint (mirrors /predict)."""
    return await predict_endpoint(req)
