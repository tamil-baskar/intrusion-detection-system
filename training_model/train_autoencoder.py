# train_autoencoder.py
import numpy as np
from ml_engine_v2 import AutoencoderThreatModel


def generate_normal_baseline(n_samples: int = 5000):
    """Generates synthetic normal traffic baseline mimicking normal.py."""
    rates = np.random.uniform(2.0, 30.0, n_samples)
    ports = np.random.randint(1, 4, n_samples)
    syns = np.random.binomial(n=5, p=0.1, size=n_samples)
    entropies = np.random.uniform(3.5, 7.5, n_samples)

    safe_rates = np.maximum(rates, 1.0)
    syn_ratios = syns / safe_rates
    port_diversities = ports / safe_rates

    return np.column_stack([rates, ports, syns, entropies, syn_ratios, port_diversities])


def generate_attack_samples(n_samples: int = 500):
    """Generates synthetic attack samples to verify threshold detection."""
    rates = np.random.uniform(200.0, 800.0, n_samples)
    ports = np.random.randint(20, 150, n_samples)
    syns = np.random.randint(50, 400, n_samples)
    entropies = np.random.uniform(0.0, 1.5, n_samples)

    safe_rates = np.maximum(rates, 1.0)
    return np.column_stack([rates, ports, syns, entropies, syns / safe_rates, ports / safe_rates])


if __name__ == "__main__":
    print("[*] Generating baseline normal network traffic...")
    X_normal = generate_normal_baseline(6000)

    print("[*] Training Autoencoder on baseline traffic...")
    ae_model = AutoencoderThreatModel(
        model_path="models/autoencoder.pth",
        meta_path="models/ae_meta.joblib"
    )
    ae_model.train(X_normal, epochs=35, batch_size=64, lr=0.005)
    print(f"[✔] Learned MSE Anomaly Threshold: {ae_model.threshold:.5f}")

    # Sanity verification against attack samples
    print("[*] Testing detection sensitivity on attack samples...")
    X_attacks = generate_attack_samples(200)
    detected = sum(ae_model.predict(vec.reshape(1, -1)) for vec in X_attacks)
    print(f"[✔] Attack Detection Rate: {detected}/{len(X_attacks)} ({detected/len(X_attacks)*100:.1f}%)")
    print(f"[✔] Saved weights to {ae_model.model_path} and metadata to {ae_model.meta_path}")