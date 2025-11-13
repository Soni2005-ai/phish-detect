from flask import Flask, request, jsonify, render_template
from feature_extractor import combine_features, FEATURE_NAMES
from scanner import scan_website
import pickle
import traceback

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

        # Run scanner
        scan_data = scan_website(url)

        html_features = scan_data["html"]
        whois_data = scan_data["whois"]
        tls_data = scan_data["tls"]
        model_features = scan_data["ml_features"]

        # Load ML model
        with open("model/model.pkl", "rb") as f:
            model = pickle.load(f)

        prediction = model.predict([list(model_features.values())])[0]
        confidence = model.predict_proba([list(model_features.values())])[0].max() * 100

        result = "PHISHING" if prediction == 1 else "SAFE"

        return jsonify({
            "result": result,
            "confidence": round(confidence, 2),
            "html": html_features,
            "whois": whois_data,
            "tls": tls_data,
            "flags": []  # placeholder
        })

    except Exception as e:
        print("ERROR:", e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
