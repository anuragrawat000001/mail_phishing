import pytest
from fastapi.testclient import TestClient
from app.main import app
import json
import io

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "Email Phishing Detection API"

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert "status" in response.json()

def test_analyze_email():
    test_email = {
        "sender": "test@example.com",
        "subject": "Test Email",
        "body": "This is a test email body.",
        "headers": {},
        "links": []
    }
    
    response = client.post("/api/v1/analyze/email", json=test_email)
    assert response.status_code == 200
    
    result = response.json()
    assert "is_phishing" in result
    assert "confidence" in result
    assert "risk_score" in result
    assert "features" in result

def test_analyze_phishing_email():
    phishing_email = {
        "sender": "security@paypal-security.tk",
        "subject": "URGENT: Verify your account immediately!!!",
        "body": "Click here to verify your account: http://fake-paypal.tk/login. Your account will be suspended if you don't act now!",
        "headers": {},
        "links": ["http://fake-paypal.tk/login"]
    }
    
    response = client.post("/api/v1/analyze/email", json=phishing_email)
    assert response.status_code == 200
    
    result = response.json()
    # Should detect some suspicious indicators
    assert result["risk_score"] > 0.3

def test_analyze_email_missing_fields():
    incomplete_email = {
        "sender": "test@example.com",
        "subject": "Test"
        # Missing body
    }
    
    response = client.post("/api/v1/analyze/email", json=incomplete_email)
    assert response.status_code == 422  # Validation error

def test_analyze_email_invalid_sender():
    invalid_email = {
        "sender": "invalid-email",
        "subject": "Test",
        "body": "Test body"
    }
    
    response = client.post("/api/v1/analyze/email", json=invalid_email)
    assert response.status_code == 400

def test_analyze_raw_email():
    raw_email = """From: test@example.com
Subject: Test Email
Date: Mon, 1 Sep 2025 12:00:00 +0000

This is a test email body."""
    
    response = client.post("/api/v1/analyze/raw", data=raw_email)
    assert response.status_code == 200

def test_analyze_file_upload():
    # Create a mock EML file
    eml_content = """From: test@example.com
Subject: Test Email
Date: Mon, 1 Sep 2025 12:00:00 +0000

This is a test email body."""
    
    files = {"file": ("test.eml", io.StringIO(eml_content), "message/rfc822")}
    response = client.post("/api/v1/analyze/file", files=files)
    assert response.status_code == 200

def test_get_supported_features():
    response = client.get("/api/v1/features")
    assert response.status_code == 200
    
    result = response.json()
    assert "features" in result
    assert "categories" in result
    assert len(result["features"]) > 0