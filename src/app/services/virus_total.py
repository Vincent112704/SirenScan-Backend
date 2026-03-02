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

        # Increase max attempts and use exponential backoff
        max_attempts = 60  # Up to 5 minutes
        

        for attempt in range(max_attempts): 
            result = requests.get(analysis_endpoint, headers={'accept': 'application/json', 'x-apikey': VIRUS_TOTAL_API_KEY})
            data = result.json()

            status = data["data"]["attributes"]["status"]
            if status == "completed":
                stats = data["data"]["attributes"]["stats"]
                file_name = data.get("meta", {}).get("file_info", {}).get("name")
                return {
                    "analysis_id": analysis_id,
                    "stats": stats,
                    "file_name": file_name
                }
            
            
            current_wait = min(2 * (1 + attempt // 10), 10) # Adds 0.2s very iteration, waits 10 seconds at most
            time.sleep(current_wait)

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


