import numpy as np
import joblib
import os
import math
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class ThreatModel:
    def __init__(self, training_threshold=2000, model_path="baseline_model.pkl", scaler_path="scaler.pkl"):
        self.model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
        self.scaler = StandardScaler()
        self.training_buffer = []
        self.is_trained = False
        self.training_threshold = training_threshold
        self.model_path = model_path
        self.scaler_path = scaler_path
        
        
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.is_trained = True
            except Exception:
                pass 

    def calculate_entropy(self, data_counts):
        """Calculates Shannon Entropy for a given set of frequency counts."""
        if not data_counts:
            return 0.0
        
        total = sum(data_counts.values())
        if total == 0:
            return 0.0
            
        entropy = 0.0
        for count in data_counts.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy

    def extract_features(self, rate, ports_count, syn_count, payload_sizes_dict):
        """Convert raw packet stats into mathematical features."""
        payload_entropy = self.calculate_entropy(payload_sizes_dict)
        return [rate, ports_count, syn_count, payload_entropy]

    def observe(self, features):
        if not self.is_trained:
            self.training_buffer.append(features)
            if len(self.training_buffer) >= self.training_threshold:
                self.train()

    def train(self):
        X = np.array(self.training_buffer)
        
        # --- THE FIX: Scale the data before training ---
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        
        self.is_trained = True
        self.training_buffer = [] 
        
        try:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path) 
        except Exception:
            pass

    def predict(self, features):
        if not self.is_trained:
            return False 
            
        X = np.array([features])
        
        
        X_scaled = self.scaler.transform(X)
        prediction = self.model.predict(X_scaled)
        
        return prediction[0] == -1