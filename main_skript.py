import requests
import json


# Constants
API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
UPDATE = 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0'
JSON_FILE= 'CVE-Data.json'




def pull():
    response_API = requests.get(API)

    raw_data = response_API.text

    return (response_API, raw_data)

def pull_update():
    response_API = requests.get(API)

    raw_data = response_API.text

    return (response_API, raw_data)

def save_to_json(raw_data):
    with open(JSON_FILE, 'w') as f:
        print(raw_data, file=f) 
#print(data)

if(open(JSON_FILE, "r").read() == None):
    response = pull()
    data = json.loads(response[1])
else:
     with open(JSON_FILE, 'r') as f:
        data = json.load(f)

print(data)