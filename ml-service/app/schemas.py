"""Pydantic schemas for request/response validation."""

from pydantic import BaseModel, Field
from typing import Optional


class PredictRequest(BaseModel):
    """Incoming prediction request."""
    url: str = Field(..., min_length=1, description="The URL to classify")
    meta: Optional[dict] = Field(
        default=None,
        description="Optional enrichment metadata (domain_age_days, prior_score, etc.)",
    )


class PredictResponse(BaseModel):
    """Prediction result returned to the caller."""
    score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    label: str = Field(..., description="Classification label: phishing | suspicious | safe")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model confidence")
    top_features: list[str] = Field(
        default_factory=list,
        description="Top contributing features for explainability",
    )
    inference_time_ms: float = Field(..., description="Inference latency in milliseconds")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"
    model_loaded: bool = False
    version: str = "1.0.0"
