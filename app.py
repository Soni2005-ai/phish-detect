from flask import Flask, request, jsonify, render_template
from src.feature_extractor import combine_features, FEATURE_NAMES
from src.scanner import scan_website
import traceback
import os
import pickle

app = Flask(__name__, template_folder="src/static", static_folder="src/static")

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

        # Step 1: Extract features
        html_features, whois_data, tls_data, flags = scan_website(url)

        # Step 2: Combine ML features
        model_features = combine_features(html_features, whois_data, tls_data)

        # Step 3: Load ML model
        model_path = os.path.join("model", "model.pkl")
        with open(model_path, "rb") as f:
            model = pickle.load(f)

        prediction = model.predict([model_features])[0]
        confidence = model.predict_proba([model_features])[0].max() * 100

        result = "PHISHING" if prediction == 1 else "SAFE"

        return jsonify({
            "result": result,
            "confidence": round(confidence, 2),
            "html": html_features,
            "whois": whois_data,
            "tls": tls_data,
            "flags": flags
        })

    except Exception as e:
        print("ERROR:", e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
