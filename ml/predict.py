import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple
import os

class TrafficClassifier:
    def __init__(self, model_path: str, encoders_path: str):
        """Initialize the traffic classifier with trained model and encoders."""
        self.model = joblib.load(model_path)
        artifacts = joblib.load(encoders_path)
        self.scaler = artifacts['scaler']
        self.feature_names = artifacts['feature_names']
    
    def preprocess(self, traffic_data: List[Dict]) -> np.ndarray:
        """Preprocess incoming traffic data for prediction."""
        # Convert to DataFrame
        df = pd.DataFrame(traffic_data)
        
        # Ensure we have all required features
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0  # Fill missing features with 0
                
        # Select and order features as per training
        X = df[self.feature_names].copy()
        
        # Convert all columns to numeric, coercing errors
        for col in self.feature_names:
            X[col] = pd.to_numeric(X[col], errors='coerce')
        
        # Fill any remaining NaN values with 0
        X = X.fillna(0)
        
        # Scale the features
        X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def predict(self, traffic_data: List[Dict]) -> List[Dict]:
        """Make predictions on traffic data."""
        if not traffic_data:
            return []
            
        # Preprocess the data
        X = self.preprocess(traffic_data)
        
        # Make predictions
        predictions = self.model.predict(X)
        
        # Get probabilities if available
        try:
            probabilities = self.model.predict_proba(X)
            has_probabilities = True
        except:
            has_probabilities = False
        
        # Prepare results
        results = []
        for i, pred in enumerate(predictions):
            result = {
                'prediction': int(pred),
                'is_malicious': bool(pred == 1)
            }
            
            # Add probability if available
            if has_probabilities:
                # Handle binary and multi-class cases
                prob = probabilities[i]
                if len(prob) > 1:  # Binary classification
                    result['probability'] = float(prob[1])
                else:  # Only one class
                    result['probability'] = float(prob[0])
            
            results.append(result)
            
        return results

# Example usage
if __name__ == "__main__":
    # Initialize classifier
    model_dir = os.path.dirname(os.path.abspath(__file__))
    classifier = TrafficClassifier(
        model_path=os.path.join(model_dir, 'model.pkl'),
        encoders_path=os.path.join(model_dir, 'encoders.pkl')
    )
    
    # Example traffic data (replace with actual traffic data)
    example_traffic = [
        {
            # Example feature values - these should match the training features
            '5': 0.001, '6': 100, '7': 50, '8': 30, '9': 60,  # Numeric features
            '10': 0, '11': 0.1, '12': 500000, '13': 600000,    # More numeric features
            '14': 2, '15': 2, '16': 0, '17': 0, '18': 0, '19': 0, '20': 0,
            '21': 0, '22': 0, '23': 0, '24': 0, '25': 0, '26': 0, '27': 0,
            '28': 0, '29': 0, '30': 0, '31': 0, '32': 0, '33': 0, '34': 0,
            '35': 0, '36': 0, '37': 0, '38': 0, '39': 0, '40': 0, '41': 0,
            '1': 0, '2': 0, '3': 0  # Categorical features (protocol, service, state)
        }
    ]
    
    # Make predictions
    predictions = classifier.predict(example_traffic)
    print("Predictions:", predictions)
