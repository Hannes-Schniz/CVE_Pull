import requests
import json


# Constants
API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
UPDATE = 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0'
JSON_FILE= 'CVE-Data.json'
MD_TEMPLATE='# Description\n%s\n# Published:\n%s'


# pulls the newest data from tha API
def pull():
    response_API = requests.get(API)

    raw_data = response_API.text

    return (response_API, raw_data)

# pulls the newest data from the update API
def pull_update():
    response_API = requests.get(API)

    raw_data = response_API.text

    return (response_API, raw_data)

# writes the data to one JSON file
def save_to_json(raw_data):
    with open(JSON_FILE, 'w') as f:
        print(raw_data, file=f) 

# writes certain data to a Markdown file to use in Vault
def save_to_md(datapoints:list):
    for datapoint in datapoints:
        with open("data/"+datapoint[0]+".md", 'w') as f:
            print(MD_TEMPLATE % (datapoint[1], datapoint[2]), file=f) 

# parses all the information needed and returns a List 
def build_datapoints(data):
    datapoints = []
    for vuln in data:
        datapoint = [vuln["cve"]["id"], "", vuln["cve"]["published"]]
        for description in vuln["cve"]["descriptions"]:
            if description["lang"] == "en":
                datapoint[1] = description["value"]

        datapoints.append(datapoint)
    return datapoints

if(open(JSON_FILE, "r").read() == None):
    response = pull()
    data = json.loads(response[1])
else:
     with open(JSON_FILE, 'r') as f:
        data = json.load(f)

vulns = data["vulnerabilities"]


datapoints = sorted(build_datapoints(vulns))
#print(datapoints)

