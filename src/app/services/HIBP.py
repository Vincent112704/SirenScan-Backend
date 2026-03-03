import requests
import os
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("uvicorn.error")
HIBP_API_KEY = os.getenv("HIBP_API_KEY")


def HIBP_check(email):
    """Check if an email has been involved in known data breaches via HIBP API."""
    try:
        api_endpoint = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        header = {
            "hibp-api-key": HIBP_API_KEY,
            "User-Agent": "CS38-Backend-Service/1.0 (contact:tian2x04@gmail.com)",
        }
        params = {
            "truncateResponse": "false"
        }
        response = requests.get(api_endpoint, headers=header, params=params, timeout=10)

        if response.status_code == 200:
            return response.json()  # breaches found
        elif response.status_code == 404:
            return []  # no breaches
        else:
            logger.warning(f"HIBP returned unexpected status {response.status_code} for {email}")
            return None

    except Exception as e:
        logger.error(f"Error checking HIBP for {email}: {e}")
        return None
