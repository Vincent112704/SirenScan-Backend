import requests
import os
import time
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("uvicorn.error")
VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")
REQUEST_TIMEOUT = 30


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
            data = {'url': url},
            timeout=REQUEST_TIMEOUT,
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
            response = requests.post(FILE_ENDPOINT, headers=HEADER, files=files, timeout=60)
        
        if response.status_code != 200:
            raise Exception(f"VT Upload Error: {response.text}")

        analysis_id = response.json()["data"]["id"]
        logger.info(f"File uploaded successfully. Analysis ID: {analysis_id}")
        analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        # Increase max attempts and use exponential backoff
        max_attempts = 60  # Up to 5 minutes
        

        for attempt in range(max_attempts): 
            result = requests.get(analysis_endpoint, headers={'accept': 'application/json', 'x-apikey': VIRUS_TOTAL_API_KEY}, timeout=REQUEST_TIMEOUT)
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
            
            
            wait_time = min(2 * (1 + attempt // 10), 10)
            logger.info(f"File scan status: '{status}' (attempt {attempt + 1}/{max_attempts}), waiting {wait_time}s")
            time.sleep(wait_time)

        raise TimeoutError("VirusTotal file scan timed out after max attempts")
    except Exception as e:
        logger.error(f"File scan failed: {e}")
        return {"error": str(e)}

# report = scan_file("./src/app/services/CCS 7 Ideation.pdf")
# print(report)
def get_completed_analysis(analysis_id, max_retries=30, poll_interval=10):
    """Poll VirusTotal for completed analysis results with a retry limit."""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUS_TOTAL_API_KEY
    }

    for attempt in range(max_retries):
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        result = response.json()
        
        status = result.get('data', {}).get('attributes', {}).get('status')
        
        if status == "completed":
            logger.info(f"VT analysis {analysis_id} complete.")
            return result
        
        logger.info(f"VT analysis status: '{status}' (attempt {attempt + 1}/{max_retries}), waiting {poll_interval}s")
        time.sleep(poll_interval)

    raise TimeoutError(f"VirusTotal analysis {analysis_id} did not complete after {max_retries * poll_interval}s")


