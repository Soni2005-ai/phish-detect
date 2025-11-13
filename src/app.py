from src.feature_extractor import combine_features, FEATURE_NAMES
from src.scanner import scan_website


# src/app.py
from flask import Flask, request, jsonify, send_from_directory
import joblib, os, time
from feature_extractor import combine_features, FEATURE_NAMES
from src.scanner import fetch_html, parse_html_features, get_whois, get_tls_info

MODEL_PATH = "model/model.pkl"
app = Flask(__name__, static_folder='static', template_folder='static')

# Load model gracefully
if not os.path.exists(MODEL_PATH):
    print("Warning: model not found. Run training first.")
    model = None
else:
    data = joblib.load(MODEL_PATH)
    model = data['model']

@app.route("/")
def index():
    return send_from_directory('static', 'index.html')

@app.route("/scan", methods=["POST"])
def scan():
    payload = request.get_json() or {}
    url = payload.get("url","").strip()
    if not url:
        return jsonify({"error":"No URL provided"}), 400

    # 1) fetch page and content features
    status, final_url, html = fetch_html(url)
    html_feats = parse_html_features(html)
    domain = final_url if final_url else url
    domain_host = domain.split("//")[-1].split("/")[0]
    who = get_whois(domain_host)
    tls = get_tls_info(domain_host)

    # 2) feature vector for model
    feat_vec = combine_features(final_url or url, html_feats, who, tls)

    # 3) ML prediction (if model exists)
    pred = None
    prob = None
    verdict = "unknown"
    if model:
        prob = float(model.predict_proba([feat_vec])[0].max())
        pred_label = int(model.predict([feat_vec])[0])
        verdict = "phishing" if pred_label==1 else "legitimate"
        # apply simple threshold and heuristics
        if prob < 0.6 and verdict=="legitimate":
            verdict = "suspicious"

    # 4) rule-based flags
    flags = []
    if html_feats.get("password_fields",0) and not tls.get("tls_present",0):
        flags.append("form_with_password_but_no_tls")
    if feat_vec[0] == 1:
        flags.append("ip_in_url")
    if feat_vec[5] >= 1:
        flags.append("suspicious_token_in_url")

    # 5) response
    response = {
        "url": url,
        "final_url": final_url,
        "status": status,
        "verdict": verdict,
        "confidence": prob,
        "flags": flags,
        "html_features": html_feats,
        "whois": who,
        "tls": tls
    }
    return jsonify(response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
