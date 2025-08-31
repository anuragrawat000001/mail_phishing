from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
import json
from app.services.analyzer import PhishingAnalyzer
from app.utils.email_parser import EmailParser
from app.utils.validators import validate_email_data

router = APIRouter()

class EmailAnalysisRequest(BaseModel):
    sender: EmailStr
    subject: str
    body: str
    headers: Optional[Dict[str, str]] = None
    links: Optional[list] = None

class EmailAnalysisResponse(BaseModel):
    is_phishing: bool
    confidence: float
    risk_score: float
    features: Dict[str, Any]
    explanation: str
    recommendations: list

@router.post("/analyze/email", response_model=EmailAnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    """Analyze an email for phishing indicators"""
    try:
        # Validate input
        validate_email_data(request.dict())
        
        # Initialize analyzer
        analyzer = PhishingAnalyzer()
        
        # Perform analysis
        result = await analyzer.analyze_email(
            sender=request.sender,
            subject=request.subject,
            body=request.body,
            headers=request.headers or {},
            links=request.links or []
        )
        
        return EmailAnalysisResponse(**result)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.post("/analyze/file")
async def analyze_email_file(file: UploadFile = File(...)):
    """Analyze an email file (.eml, .msg, or .json)"""
    try:
        # Parse uploaded file
        parser = EmailParser()
        email_data = await parser.parse_file(file)
        
        # Validate parsed data
        validate_email_data(email_data)
        
        # Initialize analyzer
        analyzer = PhishingAnalyzer()
        
        # Perform analysis
        result = await analyzer.analyze_email(**email_data)
        
        return EmailAnalysisResponse(**result)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File analysis failed: {str(e)}")

@router.post("/analyze/raw")
async def analyze_raw_email(raw_email: str):
    """Analyze raw email content"""
    try:
        # Parse raw email
        parser = EmailParser()
        email_data = parser.parse_raw_email(raw_email)
        
        # Validate parsed data
        validate_email_data(email_data)
        
        # Initialize analyzer
        analyzer = PhishingAnalyzer()
        
        # Perform analysis
        result = await analyzer.analyze_email(**email_data)
        
        return EmailAnalysisResponse(**result)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Raw email analysis failed: {str(e)}")

@router.get("/features")
async def get_supported_features():
    """Get list of supported phishing detection features"""
    from app.services.feature_extractor import FeatureExtractor
    
    extractor = FeatureExtractor()
    return {
        "features": extractor.get_feature_list(),
        "categories": [
            "header_analysis",
            "url_analysis", 
            "content_analysis",
            "sender_reputation",
            "linguistic_analysis"
        ]
    }

