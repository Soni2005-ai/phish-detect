# src/train_model.py
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib, os
from feature_extractor import combine_features, FEATURE_NAMES
from scanner import fetch_html, parse_html_features, get_whois, get_tls_info
from tqdm import tqdm

DATA_PATH = "data/phishing_sample.csv"
MODEL_PATH = "model/model.pkl"

def load_data(path=DATA_PATH):
    df = pd.read_csv(path)
    return df

def prepare_features(df, limit=None):
    X = []
    y = []
    rows = df.itertuples(index=False)
    if limit:
        rows = list(rows)[:limit]
    for row in tqdm(rows, total=(len(df) if not limit else limit)):
        url = row.url
        label = row.label
        status, final_url, html = fetch_html(url)
        html_feats = parse_html_features(html)
        domain = final_url if final_url else url
        try:
            domain_host = domain.split("//")[-1].split("/")[0]
        except:
            domain_host = ''
        who = get_whois(domain_host)
        tls = get_tls_info(domain_host)
        feats = combine_features(final_url or url, html_feats, who, tls)
        X.append(feats)
        y.append(label)
    return np.array(X), np.array(y)

def train(limit=None):
    df = load_data()
    X, y = prepare_features(df, limit=limit)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, preds))
    print(classification_report(y_test, preds))
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({'model': clf}, MODEL_PATH)
    print("Model saved to", MODEL_PATH)

if __name__ == "__main__":
    # optionally pass limit for faster demo: train(limit=100)
    train()
