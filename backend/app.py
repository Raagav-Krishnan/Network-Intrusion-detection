import os
import json
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, origins=[
    # local development
    "http://localhost",
    "http://localhost:*",
    "http://127.0.0.1",
    "http://127.0.0.1:*",
    "null",
    # deployed Vercel frontend
    "https://network-intrusion-detection.vercel.app",
    "https://network-intrusion-detection-git-main.vercel.app",
    # any Vercel preview deployments for this project
    r"https://network-intrusion-detection.*\.vercel\.app",
])

IBM_API_KEY       = os.getenv("IBM_API_KEY", "")
WML_DEPLOYMENT_URL = os.getenv("WML_DEPLOYMENT_URL", "")
WML_URL           = os.getenv("WML_URL", "")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "")

# ---------------------------------------------------------------------------
# Temporary startup logging — confirms which region / deployment is active.
# Remove once the eu-gb migration is verified.
# ---------------------------------------------------------------------------
import re as _re
_region_from_url = _re.search(r"(eu-gb|au-syd|us-south|eu-de)", WML_DEPLOYMENT_URL + " " + WML_URL)
print("========== IBM WML CONFIG ==========")
print(f"WML_URL            : {WML_URL}")
print(f"WML_DEPLOYMENT_URL : {WML_DEPLOYMENT_URL}")
print(f"Inferred region    : {_region_from_url.group(1) if _region_from_url else 'unknown'}")
print(f"WATSONX_PROJECT_ID : {'set' if WATSONX_PROJECT_ID else 'MISSING'}")
print(f"IBM_API_KEY        : {'set' if IBM_API_KEY else 'MISSING'}")
print("====================================\n")

# ---------------------------------------------------------------------------
# Exact NSL-KDD feature order required by the WML deployment.
# This is the single source of truth used for every payload construction.
# Confirmed working against the live deployment via debug_model.py.
# ---------------------------------------------------------------------------
NSL_KDD_FIELDS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def validate_record(record: dict, index: int = 0) -> str | None:
    """Return an error message string if any required feature is missing,
    or None if the record is valid."""
    missing = [f for f in NSL_KDD_FIELDS if f not in record]
    if missing:
        prefix = f"Record {index}: " if index else ""
        return (
            f"{prefix}Missing {len(missing)} feature(s): "
            + ", ".join(missing)
        )
    return None


def get_iam_token() -> str:
    """Obtain a short-lived IBM Cloud IAM bearer token."""
    resp = requests.post(
        "https://iam.cloud.ibm.com/identity/token",
        data={
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": IBM_API_KEY,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def score_wml(token: str, values: list) -> dict:
    """Send one or more rows to the WML deployment and return the raw JSON.

    `values` must already be a list-of-lists with columns in NSL_KDD_FIELDS
    order, e.g. [[v0, v1, ...], [v0, v1, ...]]
    """
    payload = {
        "input_data": [
            {
                "fields": NSL_KDD_FIELDS,
                "values": values,
            }
        ]
    }

    resp = requests.post(
        WML_DEPLOYMENT_URL,
        json=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        timeout=60,
    )

    if resp.status_code != 200:
        print("\n========== IBM WML DEBUG ==========")
        print(f"Deployment URL : {WML_DEPLOYMENT_URL}")
        print(f"HTTP status    : {resp.status_code}")
        print("Request payload:")
        print(json.dumps(payload, indent=2))
        print("IBM response body:")
        print(resp.text)
        print("====================================\n")

    resp.raise_for_status()
    return resp.json()


def granite_explain(token: str, record: dict, label: str) -> tuple[str, str]:
    """Return (explanation_text, source) where source is 'watsonx' or
    'fallback'.  Never raises — predictions are always returned even if the
    LLM call fails."""
    flag      = record.get("flag", "")
    protocol  = record.get("protocol_type", "")
    service   = record.get("service", "")
    rerror    = record.get("rerror_rate", record.get("dst_host_rerror_rate", ""))
    srv_rerror = record.get("srv_rerror_rate", record.get("dst_host_srv_rerror_rate", ""))

    prompt = (
        f"A network intrusion detection model classified this traffic record as '{label}'. "
        f"Key fields: flag={flag}, protocol_type={protocol}, service={service}, "
        f"rerror_rate={rerror}, srv_rerror_rate={srv_rerror}. "
        f"In 2-3 plain-English sentences, explain why this traffic was classified as '{label}'."
    )

    body = {
        "model_id": "meta-llama/llama-3-3-70b-instruct",
        "project_id": WATSONX_PROJECT_ID,
        "input": prompt,
        "parameters": {"max_new_tokens": 150, "temperature": 0.2},
    }

    try:
        resp = requests.post(
            f"{WML_URL.rstrip('/')}/ml/v1/text/generation?version=2023-05-29",
            json=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=60,
        )
        resp.raise_for_status()
        results = resp.json().get("results", [{}])
        text = results[0].get("generated_text", "").strip()
        if text:
            return text, "watsonx"
        return "AI explanation service returned an empty response.", "fallback"
    except Exception as exc:
        print(f"[granite_explain] LLM call failed: {exc}")
        return "AI explanation service is temporarily unavailable.", "fallback"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/predict-explain")
def predict_explain():
    body = request.get_json(force=True)
    record = body.get("record", {})
    if not record:
        return jsonify({"error": "Missing 'record' in request body"}), 400

    err = validate_record(record)
    if err:
        return jsonify({"error": err}), 400

    values = [[record[f] for f in NSL_KDD_FIELDS]]

    try:
        token = get_iam_token()
    except Exception as exc:
        return jsonify({"error": f"IAM token error: {exc}"}), 502

    try:
        wml_resp = score_wml(token, values)
    except Exception as exc:
        return jsonify({"error": f"WML scoring error: {exc}"}), 502

    try:
        prediction_row = wml_resp["predictions"][0]["values"][0]
        label       = prediction_row[0]
        probability = prediction_row[1]
    except (KeyError, IndexError) as exc:
        return jsonify({"error": f"Unexpected WML response shape: {exc}"}), 502

    explanation, explanation_source = granite_explain(token, record, label)

    return jsonify({
        "prediction":          label,
        "probability":         probability,
        "explanation":         explanation,
        "explanation_source":  explanation_source,
    })


@app.post("/api/predict")
def predict():
    body = request.get_json(force=True)
    records = body.get("records", [])
    if not records:
        return jsonify({"error": "Missing 'records' in request body"}), 400

    for i, rec in enumerate(records):
        err = validate_record(rec, index=i + 1)
        if err:
            return jsonify({"error": err}), 400

    values = [[rec[f] for f in NSL_KDD_FIELDS] for rec in records]

    try:
        token = get_iam_token()
    except Exception as exc:
        return jsonify({"error": f"IAM token error: {exc}"}), 502

    try:
        wml_resp = score_wml(token, values)
    except Exception as exc:
        return jsonify({"error": f"WML scoring error: {exc}"}), 502

    try:
        rows    = wml_resp["predictions"][0]["values"]
        results = [{"prediction": row[0], "probability": row[1]} for row in rows]
    except (KeyError, IndexError) as exc:
        return jsonify({"error": f"Unexpected WML response shape: {exc}"}), 502

    return jsonify({"results": results})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
