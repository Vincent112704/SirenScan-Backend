import requests
import os
from dotenv import load_dotenv
import time
load_dotenv()

VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")


def scan_url(url) -> dict: 
    URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
    try:
        response = requests.post(
            URL_ENDPOINT, 
            headers = {
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'x-apikey': VIRUS_TOTAL_API_KEY, 
            }, 
            data = {'url': url}
        )

        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            results = get_completed_analysis(analysis_id)
            
            # print(results)
            return results
        else: 
            # return f"Error: {response.status_code} - {response.text}"
            return {"error": f"Error: {response.status_code} - {response.text}"}
    except Exception as e:
        return {"error": str(e)}


def scan_file(file_path: str) -> dict:
    FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files"
    HEADER = {
        'accept': 'application/json',
        'x-apikey': VIRUS_TOTAL_API_KEY,
    }

    try: 

        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(FILE_ENDPOINT, headers=HEADER, files=files)
        
        if response.status_code != 200:
            raise Exception(f"VT Upload Error: {response.text}")

        analysis_id = response.json()["data"]["id"]
        print(f"File uploaded successfully. Analysis ID: {analysis_id}")
        analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        for _ in range(30): 
            result = requests.get(analysis_endpoint, headers={'accept': 'application/json', 'x-apikey': VIRUS_TOTAL_API_KEY})
            data = result.json()

            status = data["data"]["attributes"]["status"]
            if status == "completed":
                stats = data["data"]["attributes"]["stats"]
                return {
                    "analysis_id": analysis_id,
                    "stats": stats,
                    "file_name": data["meta"]["file_info"]["name"]
                }

            time.sleep(1)

        raise Exception("VirusTotal file scan timed out")
    except Exception as e:
        return {"error": str(e)} 

# report = scan_file("./src/app/services/CCS 7 Ideation.pdf")
# print(report)
def get_completed_analysis(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUS_TOTAL_API_KEY
    }

    while True:
        response = requests.get(url, headers=headers)
        result = response.json()
        
        status = result.get('data', {}).get('attributes', {}).get('status')
        
        if status == "completed":
            print("Analysis complete!")
            return result
        
        print(f"Status is '{status}'... waiting 10 seconds.")
        time.sleep(10)  # Wait before checking again

# url_report = scan_url("hhttps://neo4j.com/blog/twin4j/this-week-in-neo4j-context-graph-dify-cypher-graphrag-and-more/?mkt_tok=NzEwLVJSQy0zMzUAAAGfjH4ZW_E5IMLeT5a2k0nhZSC9j76UwUbRBdOXKVNpZYMLPabIYAJaxI7-wgS2Q1nnEjFlfLNRQyOek2mzQqBnyecsZJeFUwe7_4AG_IaiN6XR_H4")
# print(url_report)
