import os
import joblib
import pandas as pd
import random
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import features

print("[1/5] Loading raw dataset...")
dataset_file = os.path.join("dataset", "malicious_phish.csv")
df = pd.read_csv(dataset_file)
df.columns = [c.lower() for c in df.columns]

url_col = "url"
label_col = "type" if "type" in df.columns else "label"
df = df.dropna(subset=[url_col, label_col])

# Map labels: benign = 0, malicious/phishing = 1
df['label_binary'] = df[label_col].astype(str).str.lower().apply(
    lambda x: 0 if x in ['benign', 'good', '0'] else 1
)

df_benign = df[df['label_binary'] == 0].copy()
df_malicious = df[df['label_binary'] == 1].copy()

# Inject standard root benign examples so the model learns that short root domains are safe
common_benign_roots = [
    "google.com", "youtube.com", "apple.com", "microsoft.com", "amazon.com",
    "wikipedia.org", "github.com", "linkedin.com", "reddit.com", "netflix.com",
    "yahoo.com", "twitter.com", "instagram.com", "facebook.com", "bing.com"
] * 300

df_extra = pd.DataFrame({
    url_col: common_benign_roots,
    'label_binary': [0] * len(common_benign_roots)
})
df_benign = pd.concat([df_benign, df_extra], ignore_index=True)

n_sample = 15000
df_benign_sampled = df_benign.sample(n=n_sample, random_state=42)
df_malicious_sampled = df_malicious.sample(n=n_sample, random_state=42)

# Randomly prepend schemes to match real-world inputs
def add_scheme(u):
    u = str(u).strip()
    if not u.startswith(("http://", "https://")):
        return ("https://" if random.random() > 0.3 else "http://") + u
    return u

random.seed(42)
df_benign_sampled[url_col] = df_benign_sampled[url_col].apply(add_scheme)
df_malicious_sampled[url_col] = df_malicious_sampled[url_col].apply(add_scheme)

df_sample = pd.concat([df_benign_sampled, df_malicious_sampled]).sample(frac=1, random_state=42).reset_index(drop=True)

print(f"Dataset ready: {len(df_sample)} URLs (50% Legitimate, 50% Malicious)")

print("[2/5] Extracting URL features (~15-20s)...")
feature_rows = [features.extract_features(u) for u in df_sample[url_col]]
X = pd.DataFrame(feature_rows, columns=features.FEATURE_NAMES)
y = df_sample['label_binary'].values

print("[3/5] Splitting into 80% train and 20% test...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("[4/5] Training Random Forest Classifier...")
rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train, y_train)

print("[5/5] Evaluating performance...")
y_pred = rf_model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print("\n" + "="*45)
print(f" MODEL ACCURACY: {acc * 100:.2f}%")
print("="*45)
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

os.makedirs("models", exist_ok=True)
model_path = os.path.join("models", "rf_model.pkl")
joblib.dump(rf_model, model_path)
print(f"\nModel re-saved to: {model_path}")