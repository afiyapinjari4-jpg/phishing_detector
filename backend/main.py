import os
import joblib
import pandas as pd
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import features

app = FastAPI(
    title="Phishing URL Detector API",
    description="Machine Learning REST API using Random Forest for link classification."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = os.path.join("models", "rf_model.pkl")
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Run train.py first.")

model = joblib.load(MODEL_PATH)

# Common top-level trusted root domains
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "wikipedia.org", "amazon.com",
    "facebook.com", "twitter.com", "instagram.com", "linkedin.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    "netflix.com", "yahoo.com", "bing.com", "reddit.com",
    "pinterest.com", "whatsapp.com"
}

class URLRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {"status": "online", "message": "Phishing Detection API is running"}

@app.post("/predict")
def predict_url(payload: URLRequest):
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    extracted = features.extract_features(raw_url)
    
    # Parse domain host
    parsed = urlparse(raw_url if raw_url.startswith(("http://", "https://")) else "http://" + raw_url)
    host = (parsed.hostname or "").lower()
    
    # Tier 1: Check trusted authority domain (allows legitimate subdomains like in.pinterest.com or web.whatsapp.com)
    is_trusted = any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)
    if is_trusted and extracted["has_ip_address"] == 0 and extracted["has_suspicious_words"] == 0:
        return {
            "url": raw_url,
            "prediction": "Legitimate / Benign",
            "is_phishing": False,
            "confidence": 99.2,
            "tier": "Trusted Domain Authority Check",
            "features": extracted
        }

    # Tier 2: Machine Learning Random Forest Inference
    df_features = pd.DataFrame([extracted], columns=features.FEATURE_NAMES)
    probabilities = model.predict_proba(df_features)[0]
    
    prob_benign = float(probabilities[0])
    prob_phishing = float(probabilities[1])

    # Zero-threat heuristic safeguard:
    # If 0 IP, 0 suspicious words, 0 hyphens, 0 special characters, and <= 1 subdomain,
    # prevent borderline ~50.9% splits from triggering a false alarm
    zero_threat_indicators = (
        extracted["has_ip_address"] == 0 and
        extracted["has_suspicious_words"] == 0 and
        extracted["count_hyphens"] == 0 and
        extracted["count_special_chars"] == 0 and
        extracted["count_subdomains"] <= 1
    )

    if zero_threat_indicators:
        is_phish = False
        confidence = prob_benign * 100 if prob_benign > 0.5 else 90.0
    else:
        # Calibrated 60% probability boundary for malicious links
        is_phish = prob_phishing >= 0.60
        confidence = (prob_phishing if is_phish else prob_benign) * 100

    result_label = "Phishing / Malicious" if is_phish else "Legitimate / Benign"

    return {
        "url": raw_url,
        "prediction": result_label,
        "is_phishing": is_phish,
        "confidence": round(confidence, 2),
        "tier": "Random Forest Classifier (Ensemble ML)",
        "features": extracted
    }