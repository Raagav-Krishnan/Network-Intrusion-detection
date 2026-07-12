import requests
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("IBM_API_KEY")

print("Key loaded (first/last 4 chars):", API_KEY[:4], "..." if API_KEY else "MISSING", API_KEY[-4:] if API_KEY else "")

response = requests.post(
    'https://iam.cloud.ibm.com/identity/token',
    data={"apikey": API_KEY, "grant_type": "urn:ibm:params:oauth:grant-type:apikey"}
)
print("Status:", response.status_code)
print("Body:", response.text)