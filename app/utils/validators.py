import re
from typing import Dict, Any
from fastapi import HTTPException

def validate_email_data(email_data: Dict[str, Any]):
    """Validate email data before analysis"""
    
    # Check required fields
    required_fields = ['sender', 'subject', 'body']
    for field in required_fields:
        if field not in email_data or not email_data[field]:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required field: {field}"
            )
    
    # Validate email format
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email_data['sender']):
        raise HTTPException(
            status_code=400,
            detail="Invalid email format for sender"
        )
    
    # Check content length limits
    if len(email_data['body']) > 100000:  # 100KB limit
        raise HTTPException(
            status_code=400,
            detail="Email body too large (max 100KB)"
        )
    
    if len(email_data['subject']) > 1000:
        raise HTTPException(
            status_code=400,
            detail="Subject line too long (max 1000 characters)"
        )

def validate_file_upload(file):
    """Validate uploaded file"""
    allowed_extensions = ['.eml', '.msg', '.json', '.txt']
    
    if not any(file.filename.endswith(ext) for ext in allowed_extensions):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type. Allowed: {allowed_extensions}"
        )
    
    # Check file size (5MB limit)
    if hasattr(file, 'size') and file.size > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="File too large (max 5MB)"
        )