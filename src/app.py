from flask import Flask, request, jsonify, render_template
from src.feature_extractor import combine_features, FEATURE_NAMES
from src.scanner import scan_website
import pickle
import traceback
import os

app = Flask(__name__, template_folder="static", static_folder="static")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.json
        url = data.get("url")

        if not url:
            return jsonify({"error": "URL missing"}), 400

        # Scan website
        scan_data = scan_website(url)

        html_features = scan_data["html"]
        whois_data = scan_data["whois"]
        tls_data = scan_data["tls"]
        model_features = scan_data["ml_features"]

        # Load model
        model_path = os.path.join("model", "model.pkl")
        with open(model_path, "rb") as f:
            model = pickle.load(f)

        X = [list(model_features.values())]
        prediction = model.predict(X)[0]
        confidence = model.predict_proba(X)[0].max() * 100

        result = "PHISHING" if prediction == 1 else "SAFE"

        return jsonify({
            "result": result,
            "confidence": round(confidence, 2),
            "html": html_features,
            "whois": whois_data,
            "tls": tls_data
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
