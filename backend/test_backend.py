import sys
from pathlib import Path
import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

BASE = "http://localhost:5000"
passed = 0

SAMPLE_RECORD = {
    "duration": 0, "protocol_type": "tcp", "service": "private",
    "flag": "REJ", "src_bytes": 0, "dst_bytes": 0, "land": 0,
    "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
    "logged_in": 0, "num_compromised": 0, "root_shell": 0,
    "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
    "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    "is_host_login": 0, "is_guest_login": 0, "count": 229,
    "srv_count": 10, "serror_rate": 0.0, "srv_serror_rate": 0.0,
    "rerror_rate": 1.0, "srv_rerror_rate": 1.0, "same_srv_rate": 0.04,
    "diff_srv_rate": 0.06, "srv_diff_host_rate": 0.0,
    "dst_host_count": 255, "dst_host_srv_count": 10,
    "dst_host_same_srv_rate": 0.04, "dst_host_diff_srv_rate": 0.06,
    "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 1.0, "dst_host_srv_rerror_rate": 1.0,
}

# ── Test 1: GET /api/health ───────────────────────────────────────────────────
print("\n── Test 1: GET /api/health ──")
try:
    r = requests.get(f"{BASE}/api/health", timeout=10)
    data = r.json()
    if r.status_code == 200 and data.get("status") == "ok":
        print(f"  ✓ PASS  status={r.status_code}  response={data}")
        passed += 1
    else:
        print(f"  ✗ FAIL  status={r.status_code}  response={data}")
except Exception as e:
    print(f"  ✗ FAIL  exception: {e}")

# ── Test 2: POST /api/predict-explain ────────────────────────────────────────
print("\n── Test 2: POST /api/predict-explain ──")
predict_label = None
try:
    r = requests.post(
        f"{BASE}/api/predict-explain",
        json={"record": SAMPLE_RECORD},
        timeout=120,
    )
    data = r.json()
    if r.status_code == 200 and "prediction" in data and "error" not in data:
        predict_label = data["prediction"]
        prob = data.get("probability", [])
        explanation = data.get("explanation", "")
        print(f"  ✓ PASS  status={r.status_code}")
        print(f"    prediction  : {predict_label}")
        print(f"    probability : {prob}")
        print(f"    explanation : {explanation}")
        passed += 1
    else:
        print(f"  ✗ FAIL  status={r.status_code}  response={data}")
except Exception as e:
    print(f"  ✗ FAIL  exception: {e}")

# ── Test 3: Verify prediction label is "anomaly" ─────────────────────────────
print("\n── Test 3: Prediction label == 'anomaly' ──")
if predict_label is None:
    print("  ✗ FAIL  no prediction returned (Test 2 did not pass)")
elif predict_label.lower() == "anomaly":
    print(f"  ✓ PASS  prediction='{predict_label}' matches expected 'anomaly'")
    passed += 1
else:
    print(f"  ✗ FAIL  prediction='{predict_label}' — expected 'anomaly'")

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{'─'*44}")
print(f"  {passed}/3 tests passed")
print(f"{'─'*44}\n")
sys.exit(0 if passed == 3 else 1)
