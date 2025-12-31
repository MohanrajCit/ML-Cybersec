"""
FastAPI REST API for CVE Risk Prediction System
================================================
REST API that exposes ML-based CVE risk prediction via HTTP endpoints.

Key Features:
- POST /predict - Predict risk for a single CVE description
- GET /predict/latest-cves - Fetch and analyze recent CVEs from NVD

Design Principles:
- Models loaded at startup (not per request)
- Reuses existing prediction logic without modification
- Returns JSON responses with proper error handling
- CORS enabled for frontend integration
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
import logging
import os
import uuid

# Import existing prediction functions (DO NOT MODIFY THESE)
from cve_realtime_processor import (
    predict_risk,
    detect_anomaly,
    process_new_cves
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="CVE Risk Prediction API",
    description="REST API for ML-based CVE risk prediction with anomaly detection",
    version="1.0.0"
)

# Enable CORS for frontend integration
# Read additional origins from environment variable (comma-separated)
extra_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]

allowed_origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:8080",
] + extra_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

# --- Pydantic Models for Request/Response Validation ---

class PredictRequest(BaseModel):
    """Request model for /predict endpoint"""
    description: str = Field(
        ...,
        min_length=20,
        description="CVE vulnerability description text (minimum 20 characters)"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "description": "A remote code execution vulnerability exists in the web application framework that allows an attacker to execute arbitrary code by sending specially crafted requests to the server endpoint."
            }
        }


class PredictResponse(BaseModel):
    """Response model for /predict endpoint"""
    risk: str = Field(..., description="Risk level: HIGH, MEDIUM, or LOW")
    confidence: float = Field(..., description="Confidence score (0.0 to 1.0)")
    anomalous: bool = Field(..., description="Whether the pattern is anomalous")
    anomaly_score: float = Field(..., description="Anomaly score (lower = more anomalous)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "risk": "HIGH",
                "confidence": 0.87,
                "anomalous": False,
                "anomaly_score": 0.15
            }
        }


class CVEPrediction(BaseModel):
    """Model for individual CVE prediction in batch results"""
    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2024-1234)")
    risk: str = Field(..., description="Risk level: HIGH, MEDIUM, or LOW")
    confidence: float = Field(..., description="Confidence score (0.0 to 1.0)")
    anomalous: bool = Field(..., description="Whether the pattern is anomalous")
    
    class Config:
        json_schema_extra = {
            "example": {
                "cve_id": "CVE-2024-1234",
                "risk": "MEDIUM",
                "confidence": 0.65,
                "anomalous": True
            }
        }


# --- Startup Event: Verify Models are Loaded ---

@app.on_event("startup")
async def startup_event():
    """
    Verify that ML models are loaded at startup.
    Models are actually loaded in cve_realtime_processor module at import time.
    """
    logger.info("🚀 Starting CVE Risk Prediction API")
    
    # Verify required model files exist
    required_files = [
        "rf_model.pkl",
        "tfidf_vectorizer.pkl",
        "anomaly_model.pkl"
    ]
    
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        logger.error(f"❌ Missing model files: {missing_files}")
        raise FileNotFoundError(f"Required model files not found: {missing_files}")
    
    logger.info("✅ All model files loaded successfully")
    logger.info("📡 API ready at http://127.0.0.1:8000")
    logger.info("📚 Interactive docs at http://127.0.0.1:8000/docs")


# --- API Endpoints ---

@app.get("/")
async def root():
    """
    Root endpoint - API health check and information
    """
    return {
        "message": "CVE Risk Prediction API",
        "status": "running",
        "version": "1.0.0",
        "endpoints": {
            "predict": "POST /predict",
            "latest_cves": "GET /predict/latest-cves",
            "meta": "GET /meta",
            "health": "GET /health",
            "docs": "GET /docs"
        }
    }


@app.get("/meta")
async def get_meta():
    """
    Get metadata about the model and API.
    
    Returns:
    - `model_name`: Name of the ML model
    - `version`: API version
    - `risk_levels`: Available risk classifications
    - `features`: Model capabilities
    """
    return {
        "model_name": "RandomForest CVE Risk Classifier",
        "version": "1.0.0",
        "risk_levels": ["HIGH", "MEDIUM", "LOW"],
        "features": [
            "TF-IDF text vectorization",
            "Binary classification with probability mapping",
            "Isolation Forest anomaly detection",
            "Real-time NVD CVE ingestion"
        ],
        "thresholds": {
            "high_risk": ">= 0.70 probability",
            "medium_risk": "0.40 - 0.69 probability",
            "low_risk": "< 0.40 probability"
        }
    }


@app.post("/predict", response_model=PredictResponse)
async def predict(request: PredictRequest):
    """
    Predict risk level for a single CVE description.
    
    **Process:**
    1. Validates input description (minimum 20 characters)
    2. Runs pre-trained ML model (no retraining)
    3. Detects anomalous patterns using Isolation Forest
    4. Returns risk level (HIGH/MEDIUM/LOW) with confidence
    
    **Returns:**
    - `risk`: Risk classification (HIGH, MEDIUM, or LOW)
    - `confidence`: Model confidence (0.0 to 1.0)
    - `anomalous`: Whether pattern deviates from historical CVEs
    - `anomaly_score`: Anomaly detection score (lower = more anomalous)
    
    **Example Request:**
    ```json
    {
      "description": "Remote code execution vulnerability in web framework..."
    }
    ```
    """
    try:
        # Call existing prediction function (reuse, don't modify)
        risk_result = predict_risk(request.description)
        
        # Call existing anomaly detection function
        anomaly_result = detect_anomaly(request.description)
        
        # Combine results into response format
        return PredictResponse(
            risk=risk_result["risk"],
            confidence=float(risk_result["confidence"]),
            anomalous=bool(anomaly_result["anomalous"]),
            anomaly_score=float(anomaly_result["anomaly_score"])
        )
    
    except Exception as e:
        trace_id = str(uuid.uuid4())[:8]
        logger.error(f"[{trace_id}] Prediction error: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": f"Prediction failed: {str(e)}", "trace_id": trace_id}
        )


@app.get("/predict/latest-cves", response_model=List[CVEPrediction])
async def predict_latest_cves(
    days_back: int = Query(default=3, ge=1, le=30, description="Number of days to look back (1-30)"),
    max_results: int = Query(default=10, ge=1, le=100, description="Maximum number of CVEs to fetch (1-100)")
):
    """
    Fetch recent CVEs from NVD and predict their risk levels.
    
    **Process:**
    1. Fetches CVEs published in the last N days from NVD API
    2. Extracts English descriptions
    3. Runs risk prediction for each CVE
    4. Detects anomalous patterns
    5. Returns sorted results
    
    **Query Parameters:**
    - `days_back`: Number of days to look back (default: 3, max: 30)
    - `max_results`: Maximum CVEs to fetch (default: 10, max: 100)
    
    **Returns:**
    List of CVE predictions with:
    - `cve_id`: CVE identifier (e.g., CVE-2024-1234)
    - `risk`: Risk level (HIGH, MEDIUM, or LOW)
    - `confidence`: Prediction confidence
    - `anomalous`: Anomaly detection flag
    
    **Note:**
    - Requires internet connection
    - May be rate-limited by NVD API
    - Set NVD_API_KEY environment variable for higher rate limits
    
    **Example Response:**
    ```json
    [
      {
        "cve_id": "CVE-2024-1234",
        "risk": "HIGH",
        "confidence": 0.89,
        "anomalous": false
      }
    ]
    ```
    """
    try:
        # Read NVD API key from environment (optional, but recommended)
        api_key = os.getenv("NVD_API_KEY")
        
        if not api_key:
            logger.warning("NVD_API_KEY not set - API requests will be rate-limited")
        
        # Call existing pipeline function (reuse, don't modify)
        results = process_new_cves(
            days_back=days_back,
            max_results=max_results,
            api_key=api_key
        )
        
        # Convert to response format
        # The process_new_cves function already returns the correct structure
        return [
            CVEPrediction(
                cve_id=result["cve_id"],
                risk=result["risk"],
                confidence=float(result["confidence"]),
                anomalous=bool(result["anomalous"])
            )
            for result in results
        ]
    
    except Exception as e:
        trace_id = str(uuid.uuid4())[:8]
        logger.error(f"[{trace_id}] Error fetching latest CVEs: {e}")
        raise HTTPException(
            status_code=502,
            detail={"error": f"Failed to fetch CVEs from NVD: {str(e)}", "trace_id": trace_id}
        )


# --- Health Check Endpoint ---

@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring and load balancers.
    
    Returns:
    - `status`: "healthy" if all models are loaded
    - `models_loaded`: true/false
    """
    # Check if models are accessible
    required_files = ["rf_model.pkl", "tfidf_vectorizer.pkl", "anomaly_model.pkl"]
    models_loaded = all(os.path.exists(f) for f in required_files)
    
    return {
        "status": "healthy" if models_loaded else "unhealthy",
        "models_loaded": models_loaded
    }


# --- Run Server ---
# Start with: uvicorn app:app --reload
# Access at: http://127.0.0.1:8000
# Docs at: http://127.0.0.1:8000/docs
