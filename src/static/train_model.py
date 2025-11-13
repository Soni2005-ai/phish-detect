import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
from feature_extractor import extract_features, FEATURE_NAMES

DATA_PATH = "../data/phishing_sample.csv"
MODEL_PATH = "../model/model.pkl"

def load_data(path=DATA_PATH):
    df = pd.read_csv(path)
    return df

def prepare_features(df):
    X = df['url'].apply(lambda u: extract_features(u))
    X = np.vstack(X.values)
    y = df['label'].values
    return pd.DataFrame(X, columns=FEATURE_NAMES), y

def train():
    df = load_data()
    X, y = prepare_features(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    clf = RandomForestClassifier(n_estimators=150, random_state=42)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)

    print("Accuracy:", accuracy_score(y_test, preds))
    print(classification_report(y_test, preds))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({'model': clf}, MODEL_PATH)

    print("Model saved to", MODEL_PATH)

if __name__ == "__main__":
    train()
