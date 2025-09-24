import asyncio
from typing import Dict, Any, List
import re
import logging
from app.services.feature_extractor import FeatureExtractor
from app.services.models import ModelService

logger = logging.getLogger(__name__)

class PhishingAnalyzer:
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.model_service = ModelService()
        
    async def analyze_email(self, sender: str, subject: str, body: str, 
                           headers: Dict[str, str], links: List[str]) -> Dict[str, Any]:
        """Main analysis function"""
        try:
            # Extract features
            features = await self.feature_extractor.extract_all_features(
                sender=sender,
                subject=subject,
                body=body,
                headers=headers,
                links=links
            )
            
            # Get ML model prediction
            ml_prediction = await self.model_service.predict(features)
            
            # Rule-based analysis
            rule_based_score = self._rule_based_analysis(features)
            
            # Combine scores
            final_score = (ml_prediction['confidence'] * 0.7) + (rule_based_score * 0.3)
            is_phishing = final_score > 0.5
            
            # Generate explanation
            explanation = self._generate_explanation(features, is_phishing, final_score)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(features, is_phishing)
            
            return {
                "is_phishing": is_phishing,
                "confidence": ml_prediction['confidence'],
                "risk_score": final_score,
                "features": features,
                "explanation": explanation,
                "recommendations": recommendations
            }
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            raise
    
    def _rule_based_analysis(self, features: Dict[str, Any]) -> float:
        """Rule-based phishing detection"""
        score = 0.0
        
        # Check for suspicious patterns
        if features.get('urgent_language', False):
            score += 0.2
        if features.get('suspicious_links', 0) > 0:
            score += 0.3
        if features.get('spoofed_sender', False):
            score += 0.4
        if features.get('missing_security_headers', 0) > 2:
            score += 0.2
        if features.get('typos_count', 0) > 5:
            score += 0.1
        
        return min(score, 1.0)
    
    def _generate_explanation(self, features: Dict[str, Any], is_phishing: bool, score: float) -> str:
        """Generate human-readable explanation"""
        if is_phishing:
            reasons = []
            if features.get('suspicious_links', 0) > 0:
                reasons.append(f"Contains {features['suspicious_links']} suspicious links")
            if features.get('urgent_language', False):
                reasons.append("Uses urgent/threatening language")
            if features.get('spoofed_sender', False):
                reasons.append("Sender appears to be spoofed")
            
            return f"This email is likely phishing (confidence: {score:.2%}). " + "; ".join(reasons)
        else:
            return f"This email appears legitimate (confidence: {1-score:.2%})"
    
    def _generate_recommendations(self, features: Dict[str, Any], is_phishing: bool) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if is_phishing:
            recommendations.extend([
                "Do not click any links in this email",
                "Do not download any attachments",
                "Report this email to your IT security team",
                "Delete the email immediately"
            ])
        else:
            if features.get('suspicious_links', 0) > 0:
                recommendations.append("Verify links before clicking")
            if features.get('external_sender', False):
                recommendations.append("Exercise caution with external sender")
        
        return recommendations
    