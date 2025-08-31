import pytest
import asyncio
from app.services.analyzer import PhishingAnalyzer

class TestPhishingAnalyzer:
    
    @pytest.fixture
    def analyzer(self):
        return PhishingAnalyzer()
    
    @pytest.mark.asyncio
    async def test_analyze_legitimate_email(self, analyzer):
        result = await analyzer.analyze_email(
            sender="colleague@company.com",
            subject="Meeting tomorrow",
            body="Hi, let's meet tomorrow at 2 PM in the conference room.",
            headers={"From": "colleague@company.com"},
            links=[]
        )
        
        assert isinstance(result["is_phishing"], bool)
        assert 0 <= result["confidence"] <= 1
        assert 0 <= result["risk_score"] <= 1
        assert isinstance(result["features"], dict)
        assert isinstance(result["recommendations"], list)
    
    @pytest.mark.asyncio
    async def test_analyze_phishing_email(self, analyzer):
        result = await analyzer.analyze_email(
            sender="security@bank-alert.tk",
            subject="URGENT: Verify Account NOW!!!",
            body="Click here immediately to verify your account or it will be suspended: http://fake-bank.tk/verify",
            headers={"From": "security@bank-alert.tk"},
            links=["http://fake-bank.tk/verify"]
        )
        
        # Should detect multiple phishing indicators
        assert result["risk_score"] > 0.4
        assert "urgent" in result["explanation"].lower() or "suspicious" in result["explanation"].lower()
    
    @pytest.mark.asyncio
    async def test_rule_based_analysis(self, analyzer):
        # Test with known phishing patterns
        features = {
            "urgent_language": True,
            "suspicious_links": 2,
            "spoofed_sender": True,
            "missing_security_headers": 3,
            "typos_count": 6
        }
        
        score = analyzer._rule_based_analysis(features)
        assert score > 0.5  # Should be flagged as suspicious
    
    def test_generate_explanation_phishing(self, analyzer):
        features = {
            "suspicious_links": 2,
            "urgent_language": True,
            "spoofed_sender": False
        }
        
        explanation = analyzer._generate_explanation(features, True, 0.8)
        assert "phishing" in explanation.lower()
        assert "suspicious links" in explanation.lower()
    
    def test_generate_recommendations_phishing(self, analyzer):
        features = {"suspicious_links": 1}
        recommendations = analyzer._generate_recommendations(features, True)
        
        assert any("not click" in rec.lower() for rec in recommendations)
        assert any("delete" in rec.lower() for rec in recommendations)