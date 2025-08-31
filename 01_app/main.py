from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from app.api.routes import router
from app.services.model import ModelService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global model service instance
model_service = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global model_service
    try:
        model_service = ModelService()
        await model_service.load_model()
        logger.info("Model loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")

app = FastAPI(
    title="Email Phishing Detection API",
    description="AI-powered email phishing detection service",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api/v1")

@app.get("/")
async def root():
    return {"message": "Email Phishing Detection API", "status": "running"}

@app.get("/health")
async def health_check():
    global model_service
    return {
        "status": "healthy",
        "model_loaded": model_service is not None and model_service.is_loaded()
    }