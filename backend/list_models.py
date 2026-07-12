import requests

API_KEY = "_o15yiGrk0S7dw1oSHjjh94BGray_VSEYocZgfMgIIpA"
WML_URL = "https://au-syd.ml.cloud.ibm.com"

# Get IAM token
token = requests.post(
    "https://iam.cloud.ibm.com/identity/token",
    data={
        "apikey": API_KEY,
        "grant_type": "urn:ibm:params:oauth:grant-type:apikey"
    }
).json()["access_token"]

# List available foundation models
response = requests.get(
    f"{WML_URL}/ml/v1/foundation_model_specs?version=2023-05-29",
    headers={
        "Authorization": f"Bearer {token}"
    }
)

print("Status Code:", response.status_code)

if response.status_code == 200:
    data = response.json()
    print("\nAvailable Foundation Models:\n")
    for model in data.get("resources", []):
        print(model.get("model_id"))
else:
    print(response.text)