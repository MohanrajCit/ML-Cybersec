"""
FastAPI REST API for CVE Risk Prediction System
================================================
REST API that exposes ML-based CVE risk prediction via HTTP endpoints.

Key Features:
- POST /predict - Predict risk for a single CVE description
- GET /predict/latest-cves - Fetch and analyze recent CVEs from NVD
- GET /api/history - Historical prediction records
- GET /api/export/csv|pdf - Report export
- POST /api/explain - Prediction explainability

Design Principles:
- Models loaded at startup (not per request)
- Reuses existing prediction logic without modification
- Returns JSON responses with proper error handling
- CORS enabled for frontend integration
"""

from fastapi import FastAPI, HTTPException, Query, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict
from datetime import datetime, timezone, timedelta
import logging
import os
import io
import uuid
import asyncio
import json

from sqlalchemy.orm import Session
from sqlalchemy import func

# Import prediction functions
from cve_realtime_processor import (
    predict_risk,
    detect_anomaly,
    process_new_cves,
    predict_cvss_score,
    explain_prediction,
)

# Import daily CVE service
from nvd_daily_service import fetch_cves_daily_with_fallback

# Import database
from database import get_db, init_db
from db_models import CVEPredictionRecord

from report_generator import generate_csv, generate_pdf

# Import auth
from auth import (
    get_password_hash, verify_password, create_access_token, get_current_user,
    ACCESS_TOKEN_EXPIRE_MINUTES, oauth2_scheme
)
from db_models import User
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from auth import SECRET_KEY, ALGORITHM

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
    cvss_predicted: Optional[float] = Field(None, description="Predicted CVSS score (0.0 to 10.0)")
    anomalous: bool = Field(..., description="Whether the pattern is anomalous")
    anomaly_score: float = Field(..., description="Anomaly score (lower = more anomalous)")
    explanation: Optional[dict] = Field(None, description="Explainability data (top features, keyword matches)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "risk": "HIGH",
                "confidence": 0.87,
                "cvss_predicted": 8.1,
                "anomalous": False,
                "anomaly_score": 0.15,
                "explanation": None
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

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str
    is_active: bool



# --- Startup Event: Verify Models are Loaded ---

@app.on_event("startup")
async def startup_event():
    """
    Verify that ML models are loaded and initialize the database at startup.
    Models are actually loaded in cve_realtime_processor module at import time.
    """
    logger.info("🚀 Starting CVE Risk Prediction API")
    
    # Initialize database
    init_db()
    
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
    
    # Check optional CVSS model
    if os.path.exists("cvss_regressor.pkl"):
        logger.info("✅ All models loaded (including CVSS regressor)")
    else:
        logger.info("✅ Core models loaded (CVSS regressor not available)")
    
    # Start WebSocket polling task
    asyncio.create_task(nvd_polling_task())
    
    logger.info("📡 API ready at http://127.0.0.1:8000")
    logger.info("📚 Interactive docs at http://127.0.0.1:8000/docs")

# --- WebSocket & Real-Time Feed ---

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

seen_cves = set()

async def nvd_polling_task():
    """Background task to poll NVD and broadcast new high-risk CVEs"""
    logger.info("Started NVD polling task for WebSockets")
    
    # Wait for application to fully start
    await asyncio.sleep(10)
    
    api_key = os.getenv("NVD_API_KEY")
    
    while True:
        try:
            logger.info("WebSocket Poll: Fetching latest CVEs")
            loop = asyncio.get_event_loop()
            
            # Use run_in_executor to not block the event loop
            results = await loop.run_in_executor(
                None, 
                lambda: process_new_cves(days_back=1, max_results=5, api_key=api_key)
            )
            
            new_cves = []
            for r in results:
                if r["cve_id"] not in seen_cves:
                    seen_cves.add(r["cve_id"])
                    new_cves.append(r)
                    
            if new_cves:
                logger.info(f"WebSocket Poll: Found {len(new_cves)} new CVEs. Broadcasting...")
                for cve in new_cves:
                    message = json.dumps(cve)
                    await manager.broadcast(message)
                    
            # Keep set size manageable
            if len(seen_cves) > 1000:
                seen_cves.clear()
                
            # Poll every 5 minutes to avoid rate limits
            await asyncio.sleep(300)
            
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in polling task: {e}")
            await asyncio.sleep(60)

@app.websocket("/ws/cve-feed")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Just keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

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
            "daily_cves": "GET /api/nvd/daily",
            "meta": "GET /meta",
            "health": "GET /health",
            "docs": "GET /docs",
            "register": "POST /api/register",
            "login": "POST /api/login"
        }
    }

# --- Auth Endpoints ---

@app.post("/api/register", response_model=UserResponse)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    db_email = db.query(User).filter(User.email == user.email).first()
    if db_email:
        raise HTTPException(status_code=400, detail="Email already registered")
        
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/api/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


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
async def predict(
    request: PredictRequest, 
    db: Session = Depends(get_db),
    # Optional auth token so unauthenticated requests still work for demo
    authorization: Optional[str] = Depends(oauth2_scheme)
):
    """
    Predict risk level for a single CVE description.
    
    **Process:**
    1. Validates input description (minimum 20 characters)
    2. Runs pre-trained ML model (no retraining)
    3. Predicts CVSS score (if regression model available)
    4. Detects anomalous patterns using Isolation Forest
    5. Generates explainability report
    6. Stores prediction in database
    
    **Returns:**
    - `risk`: Risk classification (HIGH, MEDIUM, or LOW)
    - `confidence`: Model confidence (0.0 to 1.0)
    - `cvss_predicted`: Predicted CVSS score (0.0–10.0) or null
    - `anomalous`: Whether pattern deviates from historical CVEs
    - `anomaly_score`: Anomaly detection score (lower = more anomalous)
    - `explanation`: Explainability data (top features, keyword boosts)
    """
    try:
        # Risk prediction
        risk_result = predict_risk(request.description)
        
        # Anomaly detection
        anomaly_result = detect_anomaly(request.description)
        
        # CVSS score prediction (optional)
        cvss_score = predict_cvss_score(request.description)
        
        # Explainability
        try:
            xai_data = explain_prediction(request.description)
        except Exception:
            xai_data = None
        
        # Get optional user_id
        user_id = None
        if authorization:
            try:
                payload = jwt.decode(authorization, SECRET_KEY, algorithms=[ALGORITHM])
                username: str = payload.get("sub")
                if username:
                    user = db.query(User).filter(User.username == username).first()
                    if user:
                        user_id = user.id
            except JWTError:
                pass
                
        # Store in database
        record = CVEPredictionRecord(
            description=request.description,
            risk_level=risk_result["risk"],
            confidence=float(risk_result["confidence"]),
            cvss_predicted=cvss_score,
            anomalous=bool(anomaly_result["anomalous"]),
            anomaly_score=float(anomaly_result["anomaly_score"]),
            source="manual",
            explanation=xai_data,
            user_id=user_id,
        )
        db.add(record)
        db.commit()
        
        return PredictResponse(
            risk=risk_result["risk"],
            confidence=float(risk_result["confidence"]),
            cvss_predicted=cvss_score,
            anomalous=bool(anomaly_result["anomalous"]),
            anomaly_score=float(anomaly_result["anomaly_score"]),
            explanation=xai_data,
        )
    
    except Exception as e:
        trace_id = str(uuid.uuid4())[:8]
        logger.error(f"[{trace_id}] Prediction error: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": f"Prediction failed: {str(e)}", "trace_id": trace_id}
        )

@app.post("/api/explain")
async def explain_cve(request: PredictRequest):
    """
    Generate an explainability report for a given CVE description.
    """
    try:
        xai_data = explain_prediction(request.description)
        return xai_data
    except Exception as e:
        logger.error(f"Error explaining prediction: {e}")
        raise HTTPException(status_code=500, detail=str(e))


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


# --- Daily CVE Prediction Endpoint ---

class DailyCVEItem(BaseModel):
    """Model for individual CVE in daily response"""
    cve_id: str = Field(..., description="CVE identifier")
    published: Optional[str] = Field(None, description="Published timestamp (ISO-8601 UTC)")
    lastModified: Optional[str] = Field(None, description="Last modified timestamp (ISO-8601 UTC)")
    risk: str = Field(..., description="Risk level: HIGH, MEDIUM, or LOW")
    confidence: float = Field(..., description="Confidence score (0.0 to 1.0)")
    anomalous: bool = Field(..., description="Whether the pattern is anomalous")


class DailyCVEWindow(BaseModel):
    """Date window for daily CVE fetch"""
    pubStartDate: str = Field(..., description="Start of window (ISO-8601 UTC with Z suffix)")
    pubEndDate: str = Field(..., description="End of window (ISO-8601 UTC with Z suffix)")


class DailyCVEResponse(BaseModel):
    """Response model for /api/nvd/daily endpoint"""
    mode: str = Field(..., description="'daily' if today's CVEs found, 'fallback' if using last N days")
    window: DailyCVEWindow = Field(..., description="Date window used for fetching")
    count: int = Field(..., description="Number of CVEs returned")
    items: List[DailyCVEItem] = Field(..., description="List of CVE predictions")
    
    class Config:
        json_schema_extra = {
            "example": {
                "mode": "daily",
                "window": {
                    "pubStartDate": "2026-01-02T00:00:00.000Z",
                    "pubEndDate": "2026-01-02T17:45:30.123Z"
                },
                "count": 2,
                "items": [
                    {
                        "cve_id": "CVE-2026-12345",
                        "published": "2026-01-02T10:30:00.000Z",
                        "lastModified": "2026-01-02T12:00:00.000Z",
                        "risk": "HIGH",
                        "confidence": 0.87,
                        "anomalous": False
                    }
                ]
            }
        }


@app.get("/api/nvd/daily", response_model=DailyCVEResponse)
async def get_daily_cves(
    fallback_days: int = Query(
        default=3,
        ge=2,
        le=3,
        description="Fallback window in days if no CVEs today (allowed: 2 or 3)"
    )
):
    """
    Fetch CVEs published today (UTC) with automatic fallback.
    
    **Process:**
    1. Fetches CVEs published today (UTC 00:00:00 to now)
    2. If none found, falls back to last N days (configurable)
    3. Runs ML risk prediction and anomaly detection for each CVE
    4. Returns structured JSON with mode indicator
    
    **Query Parameters:**
    - `fallback_days`: Days for fallback window (default: 3, allowed: 2 or 3)
    
    **Response:**
    - `mode`: "daily" if CVEs found today, "fallback" if using last N days
    - `window`: Date range used for fetching (pubStartDate/pubEndDate in UTC)
    - `count`: Number of CVEs returned
    - `items`: List of CVE predictions with risk/confidence/anomaly
    
    **Note:**
    - Uses NVD API 2.0 with pagination
    - Requires NVD_API_KEY environment variable for higher rate limits
    - Implements exponential backoff for rate limiting (429) and server errors
    """
    try:
        result = fetch_cves_daily_with_fallback(fallback_days=fallback_days)
        return DailyCVEResponse(
            mode=result["mode"],
            window=DailyCVEWindow(
                pubStartDate=result["window"]["pubStartDate"],
                pubEndDate=result["window"]["pubEndDate"]
            ),
            count=result["count"],
            items=[
                DailyCVEItem(
                    cve_id=item["cve_id"],
                    published=item.get("published"),
                    lastModified=item.get("lastModified"),
                    risk=item["risk"],
                    confidence=item["confidence"],
                    anomalous=item["anomalous"]
                )
                for item in result["items"]
            ]
        )
    except Exception as e:
        trace_id = str(uuid.uuid4())[:8]
        logger.error(f"[{trace_id}] Error in daily CVE fetch: {e}")
        raise HTTPException(
            status_code=502,
            detail={"error": f"Failed to fetch daily CVEs: {str(e)}", "trace_id": trace_id}
        )


@app.get("/api/history")
async def get_history(
    limit: int = Query(default=50, ge=1, le=500, description="Max records to return"),
    risk_level: Optional[str] = Query(default=None, description="Filter by risk (HIGH, MEDIUM, LOW)"),
    db: Session = Depends(get_db)
):
    """
    Get historical prediction records.
    """
    try:
        query = db.query(CVEPredictionRecord)
        if risk_level:
            query = query.filter(CVEPredictionRecord.risk_level == risk_level.upper())
            
        records = query.order_by(CVEPredictionRecord.created_at.desc()).limit(limit).all()
        
        # Calculate some stats for the response
        total_high = db.query(CVEPredictionRecord).filter(CVEPredictionRecord.risk_level == "HIGH").count()
        total_medium = db.query(CVEPredictionRecord).filter(CVEPredictionRecord.risk_level == "MEDIUM").count()
        total_low = db.query(CVEPredictionRecord).filter(CVEPredictionRecord.risk_level == "LOW").count()
        
        stats = {
            "total_predictions": total_high + total_medium + total_low,
            "risk_distribution": {
                "HIGH": total_high,
                "MEDIUM": total_medium,
                "LOW": total_low
            }
        }
        
        return {
            "stats": stats,
            "records": [rec.to_dict() for rec in records]
        }
    except Exception as e:
        logger.error(f"Error fetching history: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/export/csv")
async def export_csv(
    limit: int = Query(default=500, ge=1, le=5000),
    db: Session = Depends(get_db)
):
    """
    Export prediction history as CSV.
    """
    records = db.query(CVEPredictionRecord).order_by(CVEPredictionRecord.created_at.desc()).limit(limit).all()
    dicts = [rec.to_dict() for rec in records]
    csv_str = generate_csv(dicts)
    
    return StreamingResponse(
        io.StringIO(csv_str),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=cves_export_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"}
    )

@app.get("/api/export/pdf")
async def export_pdf(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """
    Export prediction history as PDF report.
    """
    records = db.query(CVEPredictionRecord).order_by(CVEPredictionRecord.created_at.desc()).limit(limit).all()
    dicts = [rec.to_dict() for rec in records]
    
    total = len(dicts)
    if total == 0:
        raise HTTPException(status_code=404, detail="No records to export")
        
    high = sum(1 for r in dicts if r.get("risk_level") == "HIGH")
    med = sum(1 for r in dicts if r.get("risk_level") == "MEDIUM")
    low = sum(1 for r in dicts if r.get("risk_level") == "LOW")
    anom = sum(1 for r in dicts if r.get("anomalous"))
    conf = sum(r.get("confidence", 0) for r in dicts) / total
    
    cvss_scores = [r.get("cvss_predicted") for r in dicts if r.get("cvss_predicted") is not None]
    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else None
    
    stats = {
        "total_predictions": total,
        "risk_distribution": {"HIGH": high, "MEDIUM": med, "LOW": low},
        "anomaly_count": anom,
        "avg_confidence": conf,
        "avg_cvss_predicted": avg_cvss,
    }
    
    pdf_bytes = generate_pdf(dicts, stats)
    
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=cves_report_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"}
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
