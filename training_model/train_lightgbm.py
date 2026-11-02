# train_lightgbm.py
import numpy as np
from sklearn.metrics import classification_report
from ml_engine_v2 import LightGBMThreatModel


def generate_synthetic_dataset(num_samples: int = 5000):
    """Generates labeled feature vectors reflecting your network profiles:
    Features: [rate, ports_count, syn_count, payload_entropy, syn_ratio, port_diversity]
    """
    half = num_samples // 2

    # --- 1. Benign Traffic (normal.py) ---
    # Low-to-moderate rate, few destination ports, normal entropy, low SYN count
    normal_rate = np.random.uniform(2.0, 30.0, half)
    normal_ports = np.random.randint(1, 4, half)
    normal_syn = np.random.binomial(n=5, p=0.1, size=half)
    normal_entropy = np.random.uniform(3.5, 7.5, half)

    # --- 2. Attack Traffic (attack simulators) ---
    # Mixture of Volumetric DoS, Port Scans, and SYN Floods
    attack_types = np.random.choice(["dos", "scan", "syn_flood"], size=half)

    attack_rate = []
    attack_ports = []
    attack_syn = []
    attack_entropy = []

    for atype in attack_types:
        if atype == "dos":  # Volumetric UDP flood
            attack_rate.append(np.random.uniform(200.0, 1000.0))
            attack_ports.append(np.random.randint(1, 3))
            attack_syn.append(0)
            attack_entropy.append(np.random.uniform(0.1, 1.5))
        elif atype == "scan":  # Port scan
            attack_rate.append(np.random.uniform(40.0, 120.0))
            attack_ports.append(np.random.randint(20, 200))
            attack_syn.append(np.random.randint(15, 60))
            attack_entropy.append(np.random.uniform(0.0, 2.0))
        else:  # SYN flood
            attack_rate.append(np.random.uniform(150.0, 500.0))
            attack_ports.append(np.random.randint(1, 5))
            attack_syn.append(np.random.randint(100, 450))
            attack_entropy.append(np.random.uniform(0.0, 1.0))

    # Combine
    rates = np.concatenate([normal_rate, attack_rate])
    ports = np.concatenate([normal_ports, attack_ports])
    syns = np.concatenate([normal_syn, attack_syn])
    entropies = np.concatenate([normal_entropy, attack_entropy])

    # Compute ratio features
    safe_rates = np.maximum(rates, 1.0)
    syn_ratios = syns / safe_rates
    port_diversities = ports / safe_rates

    X = np.column_stack([rates, ports, syns, entropies, syn_ratios, port_diversities])
    y = np.array([0] * half + [1] * half, dtype=np.int32)

    # Shuffle
    indices = np.arange(len(y))
    np.random.shuffle(indices)
    return X[indices], y[indices]


if __name__ == "__main__":
    print("[*] Generating dataset matching network profiles...")
    X, y = generate_synthetic_dataset()

    split_idx = int(len(X) * 0.8)
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]

    print("[*] Training LightGBMThreatModel...")
    model_handler = LightGBMThreatModel(model_path="models/lgbm_threat.joblib")
    model_handler.train(X_train, y_train)

    # Validation
    y_pred = [model_handler.predict(vec.reshape(1, -1)) for vec in X_test]
    print("\nModel Evaluation:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))
    print(f"[✔] Model saved to {model_handler.model_path}")