import requests

API_KEY = "_o15yiGrk0S7dw1oSHjjh94BGray_VSEYocZgfMgIIpA"

DEPLOYMENT_URL = "https://au-syd.ml.cloud.ibm.com/ml/v4/deployments/019f529b-7456-740a-9bed-f138b3ea31c6/predictions?version=2021-05-01"

# ----------------------------
# Get IAM Token
# ----------------------------
token = requests.post(
    "https://iam.cloud.ibm.com/identity/token",
    data={
        "apikey": API_KEY,
        "grant_type": "urn:ibm:params:oauth:grant-type:apikey"
    }
).json()["access_token"]

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# ----------------------------
# TEST INPUTS
# ----------------------------

samples = [

# Normal HTTP traffic
[0,"tcp","http","SF",215,4500,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,5,5,0.0,0.0,0.0,0.0,1.0,0.0,0.0,35,35,1.0,0.0,0.5,0.0,0.0,0.0,0.0,0.0],

# Suspicious connection
[0,"tcp","private","REJ",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,229,10,0.0,0.0,1.0,1.0,0.04,0.06,0.0,255,10,0.04,0.06,0.0,0.0,0.0,0.0,1.0,1.0],

# SYN Flood style
[0,"tcp","private","S0",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255,255,1.0,1.0,0.0,0.0,1.0,0.0,0.0,255,255,1.0,0.0,1.0,0.0,1.0,1.0,0.0,0.0]

]

fields = [
"duration","protocol_type","service","flag",
"src_bytes","dst_bytes","land","wrong_fragment",
"urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted",
"num_root","num_file_creations","num_shells",
"num_access_files","num_outbound_cmds",
"is_host_login","is_guest_login",
"count","srv_count","serror_rate",
"srv_serror_rate","rerror_rate",
"srv_rerror_rate","same_srv_rate",
"diff_srv_rate","srv_diff_host_rate",
"dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate",
"dst_host_diff_srv_rate",
"dst_host_same_src_port_rate",
"dst_host_srv_diff_host_rate",
"dst_host_serror_rate",
"dst_host_srv_serror_rate",
"dst_host_rerror_rate",
"dst_host_srv_rerror_rate"
]

for i,sample in enumerate(samples):

    payload = {
        "input_data":[
            {
                "fields":fields,
                "values":[sample]
            }
        ]
    }

    r = requests.post(
        DEPLOYMENT_URL,
        headers=headers,
        json=payload
    )

    print("="*60)
    print("TEST",i+1)
    print("Status:",r.status_code)

    try:
        print(r.json())
    except:
        print(r.text)