import pytest
from fastapi.testclient import TestClient
from app.main import app

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