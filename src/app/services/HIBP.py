import requests
import os
from dotenv import load_dotenv

load_dotenv()

HIBP_API_KEY = os.getenv("HIBP_API_KEY")


def HIBP_check(email):
    try:
        api_endpoint = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        header = {
            "hibp-api-key": HIBP_API_KEY,
            "User-Agent": "CS38-Backend-Service/1.0 (contact:tian2x04@gmail.com)", 
        }
        params = {
            "truncateResponse": "false"
        }   
        response = requests.get(api_endpoint, headers=header, params=params,timeout=10)
    
        if response.status_code == 200:
            return response.json()  # breaches found
        elif response.status_code == 404:
            return []
        
    except Exception as e:
        print(f"Error checking HIBP for {email}: {e}")
        return None


# res = HIBP_check("tian2x04@gmail.com")
# print(res)
