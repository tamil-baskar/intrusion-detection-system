# ml_engine_v2.py
import os
import math
import joblib
import numpy as np
import lightgbm as lgb
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler
from collections import defaultdict

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LGBM_PATH = os.path.join(BASE_DIR, "models", "lgbm_threat.joblib")
DEFAULT_AE_PATH = os.path.join(BASE_DIR, "models", "autoencoder.pth")
DEFAULT_AE_META_PATH = os.path.join(BASE_DIR, "models", "ae_meta.joblib")


def calculate_entropy(data_counts):
    """Calculates Shannon Entropy for a given set of frequency counts or returns float directly."""
    if isinstance(data_counts, (int, float)):
        return float(data_counts)
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
    return float(entropy)


# ==========================================
# 1. LIGHTGBM THREAT MODEL
# ==========================================
class LightGBMThreatModel:
    def __init__(self, model_path: str = DEFAULT_LGBM_PATH, threshold: float = 0.5):
        self.model_path = model_path
        self.threshold = threshold
        self.model = None
        self.is_trained = False
        self.load()

    def extract_features(
        self,
        rate: float,
        ports_count: int,
        syn_count: int,
        payload_data,
        expand_ratios: bool = True
    ) -> np.ndarray:
        payload_entropy = calculate_entropy(payload_data)
        base = [float(rate), float(ports_count), float(syn_count), float(payload_entropy)]
        if expand_ratios:
            safe_rate = max(float(rate), 1.0)
            syn_ratio = float(syn_count) / safe_rate
            port_diversity = float(ports_count) / safe_rate
            base.extend([syn_ratio, port_diversity])
        return np.array(base, dtype=np.float32).reshape(1, -1)

    def train(self, X: np.ndarray, y: np.ndarray):
        self.model = lgb.LGBMClassifier(
            n_estimators=150,
            learning_rate=0.05,
            max_depth=6,
            num_leaves=31,
            objective="binary",
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X, y)
        self.is_trained = True
        self.save()

    def predict(self, feature_vector: np.ndarray) -> bool:
        if not self.is_trained or self.model is None:
            return False
        prob_attack = self.model.predict_proba(feature_vector)[0][1]
        return bool(prob_attack >= self.threshold)

    def predict_detailed(self, feature_vector: np.ndarray) -> dict:
        """Returns raw LGBM attack probability (0.0-1.0), or None if unavailable."""
        if not self.is_trained or self.model is None:
            return {"prob": None, "flagged": False}
        prob_attack = float(self.model.predict_proba(feature_vector)[0][1])
        return {"prob": prob_attack, "flagged": prob_attack >= self.threshold}

    def save(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)

    def load(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.is_trained = True
            except Exception:
                self.is_trained = False


# ==========================================
# 2. PYTORCH AUTOENCODER THREAT MODEL
# ==========================================
class _AutoencoderNet(nn.Module):
    def __init__(self, input_dim: int = 6):
        super().__init__()
        # Encoder: Input -> Dense(8) -> Latent(2)
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 8),
            nn.ReLU(),
            nn.Linear(8, 2),
            nn.ReLU()
        )
        # Decoder: Latent(2) -> Dense(8) -> Reconstructed Input
        self.decoder = nn.Sequential(
            nn.Linear(2, 8),
            nn.ReLU(),
            nn.Linear(8, input_dim)
        )

    def forward(self, x):
        latent = self.encoder(x)
        return self.decoder(latent)


class AutoencoderThreatModel:
    """Unsupervised anomaly detector trained purely on normal baseline traffic.
    Triggers an alert when reconstruction MSE exceeds the learned threshold.
    """
    def __init__(
        self,
        model_path: str = DEFAULT_AE_PATH,
        meta_path: str = DEFAULT_AE_META_PATH,
        input_dim: int = 6
    ):
        self.model_path = model_path
        self.meta_path = meta_path
        self.input_dim = input_dim
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.net = _AutoencoderNet(input_dim).to(self.device)
        self.scaler = StandardScaler()
        self.threshold = 0.0
        self.is_trained = False
        self.load()

    def extract_features(
        self,
        rate: float,
        ports_count: int,
        syn_count: int,
        payload_data,
        expand_ratios: bool = True
    ) -> np.ndarray:
        payload_entropy = calculate_entropy(payload_data)
        base = [float(rate), float(ports_count), float(syn_count), float(payload_entropy)]
        if expand_ratios:
            safe_rate = max(float(rate), 1.0)
            syn_ratio = float(syn_count) / safe_rate
            port_diversity = float(ports_count) / safe_rate
            base.extend([syn_ratio, port_diversity])
        return np.array(base, dtype=np.float32).reshape(1, -1)

    def train(self, X_normal: np.ndarray, epochs: int = 40, batch_size: int = 64, lr: float = 0.005):
        X_scaled = self.scaler.fit_transform(X_normal)
        tensor_data = torch.tensor(X_scaled, dtype=torch.float32).to(self.device)
        dataset = torch.utils.data.TensorDataset(tensor_data, tensor_data)
        loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = torch.optim.Adam(self.net.parameters(), lr=lr)
        criterion = nn.MSELoss()

        self.net.train()
        for _ in range(epochs):
            for batch_x, _ in loader:
                optimizer.zero_grad()
                reconstructed = self.net(batch_x)
                loss = criterion(reconstructed, batch_x)
                loss.backward()
                optimizer.step()

        self.net.eval()
        with torch.no_grad():
            preds = self.net(tensor_data).cpu().numpy()
            errors = np.mean(np.square(X_scaled - preds), axis=1)
            self.threshold = float(np.percentile(errors, 99.0))

        self.is_trained = True
        self.save()

    def predict(self, feature_vector: np.ndarray) -> bool:
        if not self.is_trained:
            return False

        scaled_vec = self.scaler.transform(feature_vector)
        tensor_in = torch.tensor(scaled_vec, dtype=torch.float32).to(self.device)

        self.net.eval()
        with torch.no_grad():
            reconstructed = self.net(tensor_in).cpu().numpy()
            mse = float(np.mean(np.square(scaled_vec - reconstructed)))

        return mse > self.threshold

    def predict_detailed(self, feature_vector: np.ndarray) -> dict:
        """Returns raw AE reconstruction MSE and the anomaly threshold."""
        if not self.is_trained:
            return {"mse": None, "threshold": None, "flagged": False}
        scaled_vec = self.scaler.transform(feature_vector)
        tensor_in = torch.tensor(scaled_vec, dtype=torch.float32).to(self.device)
        self.net.eval()
        with torch.no_grad():
            reconstructed = self.net(tensor_in).cpu().numpy()
            mse = float(np.mean(np.square(scaled_vec - reconstructed)))
        return {"mse": mse, "threshold": self.threshold, "flagged": mse > self.threshold}

    def save(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        torch.save(self.net.state_dict(), self.model_path)
        joblib.dump({"scaler": self.scaler, "threshold": self.threshold}, self.meta_path)

    def load(self):
        if os.path.exists(self.model_path) and os.path.exists(self.meta_path):
            try:
                self.net.load_state_dict(torch.load(self.model_path, map_location=self.device, weights_only=True))
                self.net.eval()
                meta = joblib.load(self.meta_path)
                self.scaler = meta["scaler"]
                self.threshold = meta["threshold"]
                self.is_trained = True
            except Exception:
                try:
                    self.net.load_state_dict(torch.load(self.model_path, map_location=self.device))
                    self.net.eval()
                    meta = joblib.load(self.meta_path)
                    self.scaler = meta["scaler"]
                    self.threshold = meta["threshold"]
                    self.is_trained = True
                except Exception:
                    self.is_trained = False


# ==========================================
# 3. UNIFIED MANAGER / ENSEMBLE FACTORY
# ==========================================
class ThreatModelManager:
    """Unified entry point for detector.py.
    Supports: 'lightgbm', 'autoencoder', 'isolation_forest', or 'ensemble'.
    """
    def __init__(
        self,
        mode: str = "ensemble",
        lgbm_path: str = DEFAULT_LGBM_PATH,
        ae_path: str = DEFAULT_AE_PATH,
        ae_meta_path: str = DEFAULT_AE_META_PATH,
        legacy_model_path: str = "baseline_model.pkl"
    ):
        self.mode = mode.lower()
        self.lgbm = LightGBMThreatModel(model_path=lgbm_path)
        self.autoencoder = AutoencoderThreatModel(model_path=ae_path, meta_path=ae_meta_path)
        
        # Load legacy IsolationForest if available
        self.isolation_forest = None
        if os.path.exists(legacy_model_path):
            try:
                self.isolation_forest = joblib.load(legacy_model_path)
            except Exception:
                self.isolation_forest = None

    @property
    def is_trained(self) -> bool:
        if self.mode == "lightgbm":
            return self.lgbm.is_trained
        elif self.mode == "autoencoder":
            return self.autoencoder.is_trained
        elif self.mode == "isolation_forest":
            return self.isolation_forest is not None
        elif self.mode == "ensemble":
            return self.lgbm.is_trained or self.autoencoder.is_trained
        return False

    @property
    def status_string(self) -> str:
        if self.mode == "ensemble":
            l_stat = "LightGBM: Active" if self.lgbm.is_trained else "LightGBM: Inactive"
            a_stat = "Autoencoder: Active" if self.autoencoder.is_trained else "Autoencoder: Inactive"
            return f"Ensemble ({l_stat} | {a_stat})"
        elif self.mode == "lightgbm":
            return "LightGBM Active" if self.lgbm.is_trained else "LightGBM Inactive"
        elif self.mode == "autoencoder":
            return "Autoencoder Active" if self.autoencoder.is_trained else "Autoencoder Inactive"
        elif self.mode == "isolation_forest":
            return "IsolationForest Active" if self.isolation_forest is not None else "IsolationForest Inactive"
        return self.mode.capitalize()

    def extract_features(self, rate: float, ports_count: int, syn_count: int, payload_data) -> np.ndarray:
        return self.lgbm.extract_features(rate, ports_count, syn_count, payload_data, expand_ratios=True)

    def observe(self, features):
        pass

    def predict(self, feature_vector: np.ndarray) -> bool:
        if self.mode == "lightgbm":
            return self.lgbm.predict(feature_vector)

        elif self.mode == "autoencoder":
            return self.autoencoder.predict(feature_vector)

        elif self.mode == "isolation_forest" and self.isolation_forest is not None:
            legacy_vec = feature_vector[:, :4]
            return bool(self.isolation_forest.predict(legacy_vec)[0] == -1)

        elif self.mode == "ensemble":
            flag_lgbm = self.lgbm.predict(feature_vector) if self.lgbm.is_trained else False
            flag_ae = self.autoencoder.predict(feature_vector) if self.autoencoder.is_trained else False
            return flag_lgbm or flag_ae

        return False

    def predict_detailed(self, feature_vector: np.ndarray) -> dict:
        """Return detailed scores from LGBM and Autoencoder for the Threat Details panel."""
        lgbm_result = self.lgbm.predict_detailed(feature_vector) if self.lgbm.is_trained else {"prob": None, "flagged": False}
        ae_result = self.autoencoder.predict_detailed(feature_vector) if self.autoencoder.is_trained else {"mse": None, "threshold": None, "flagged": False}
        return {"lgbm": lgbm_result, "ae": ae_result}