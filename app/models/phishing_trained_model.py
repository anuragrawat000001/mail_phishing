import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_sample_dataset():
    """Create a sample dataset for demonstration"""
    np.random.seed(42)
    
    # Define feature names
    feature_names = [
        'urgent_language', 'suspicious_links', 'spoofed_sender', 'suspicious_domain',
        'external_sender', 'excessive_punctuation', 'all_caps_subject', 'subject_length',
        'body_length', 'word_count', 'urgent_body_language', 'typos_count', 'has_forms',
        'has_scripts', 'requests_personal_info', 'link_count', 'shortened_links',
        'external_links', 'missing_security_headers', 'hop_count', 'suspicious_routing'
    ]
    
    # Generate synthetic data
    n_samples = 10000
    n_features = len(feature_names)
    
    # Create legitimate emails (70% of dataset)
    n_legit = int(n_samples * 0.7)
    legit_features = np.random.beta(2, 5, (n_legit, n_features))  # Skewed towards 0
    legit_labels = np.zeros(n_legit)
    
    # Create phishing emails (30% of dataset)
    n_phishing = n_samples - n_legit
    phishing_features = np.random.beta(5, 2, (n_phishing, n_features))  # Skewed towards 1
    phishing_labels = np.ones(n_phishing)
    
    # Combine datasets
    X = np.vstack([legit_features, phishing_features])
    y = np.hstack([legit_labels, phishing_labels])
    
    # Shuffle
    indices = np.random.permutation(len(X))
    X, y = X[indices], y[indices]
    
    return X, y, feature_names

def train_model():
    """Train the phishing detection model"""
    logger.info("Creating sample dataset...")
    X, y, feature_names = create_sample_dataset()
    
    logger.info(f"Dataset shape: {X.shape}")
    logger.info(f"Phishing emails: {sum(y)}, Legitimate emails: {len(y) - sum(y)}")
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    logger.info("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train model
    logger.info("Training model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight='balanced'
    )
    
    model.fit(X_train_scaled, y_train)
    
    # Evaluate model
    logger.info("Evaluating model...")
    train_score = model.score(X_train_scaled, y_train)
    test_score = model.score(X_test_scaled, y_test)
    
    logger.info(f"Training accuracy: {train_score:.4f}")
    logger.info(f"Test accuracy: {test_score:.4f}")
    
    # Predictions for detailed evaluation
    y_pred = model.predict(X_test_scaled)
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nTop 10 Most Important Features:")
    print(feature_importance.head(10))
    
    # Save model
    logger.info("Saving model...")
    model_data = {
        'model': model,
        'scaler': scaler,
        'feature_names': feature_names,
        'feature_importance': feature_importance.to_dict(),
        'metrics': {
            'train_accuracy': train_score,
            'test_accuracy': test_score
        }
    }
    
    with open('models/phishing_model.pkl', 'wb') as f:
        pickle.dump(model_data, f)
    
    logger.info("Model training completed and saved!")

if __name__ == "__main__":
    import os
    os.makedirs('models', exist_ok=True)
    train_model()