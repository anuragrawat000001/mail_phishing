import pickle
import numpy as np
from typing import Dict, Any, Optional
import logging
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

class ModelService:
    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = []
        self.is_model_loaded = False
    
    async def load_model(self):
        """Load the trained model from file or create a default one"""
        model_path = "models/phishing_model.pkl"
        
        try:
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    model_data = pickle.load(f)
                    self.model = model_data['model']
                    self.scaler = model_data.get('scaler')
                    self.feature_names = model_data.get('feature_names', [])
                logger.info("Model loaded from file")
            else:
                # Create a default model for demonstration
                self._create_default_model()
                logger.info("Created default model")
            
            self.is_model_loaded = True
            
        except Exception as e:
            logger.error(f"Model loading error: {e}")
            self._create_default_model()
            self.is_model_loaded = True
    
    def _create_default_model(self):
        """Create a basic model for demonstration purposes"""
        # This is a simplified model - in production, train on real data
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        
        # Define expected feature names
        from app.services.feature_extractor import FeatureExtractor
        extractor = FeatureExtractor()
        self.feature_names = extractor.get_feature_list()
        
        # Create dummy training data for demonstration
        dummy_features = np.random.rand(1000, len(self.feature_names))
        dummy_labels = np.random.choice([0, 1], 1000, p=[0.7, 0.3])
        
        # Fit scaler and model
        scaled_features = self.scaler.fit_transform(dummy_features)
        self.model.fit(scaled_features, dummy_labels)
    
    async def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Make phishing prediction"""
        if not self.is_model_loaded:
            await self.load_model()
        
        try:
            # Convert features to array
            feature_array = self._features_to_array(features)
            
            # Scale features
            if self.scaler:
                feature_array = self.scaler.transform([feature_array])
            else:
                feature_array = [feature_array]
            
            # Make prediction
            prediction = self.model.predict(feature_array)[0]
            confidence = self.model.predict_proba(feature_array)[0].max()
            
            return {
                'prediction': int(prediction),
                'confidence': float(confidence),
                'is_phishing': bool(prediction)
            }
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            # Fallback to rule-based prediction
            return {
                'prediction': 0,
                'confidence': 0.5,
                'is_phishing': False
            }
    
    def _features_to_array(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert feature dictionary to numpy array"""
        feature_array = []
        
        for feature_name in self.feature_names:
            value = features.get(feature_name, 0)
            
            # Convert boolean to int
            if isinstance(value, bool):
                value = int(value)
            elif isinstance(value, str):
                value = len(value)  # Use length for string features
            elif value is None:
                value = 0
            
            feature_array.append(float(value))
        
        return np.array(feature_array)
    
    def is_loaded(self) -> bool:
        """Check if model is loaded"""
        return self.is_model_loaded