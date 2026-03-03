import resend
import os
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("uvicorn.error")
resend.api_key = os.getenv("RESEND_API_KEY")


def send_email(email_address: str):
    """Send a notification email to the user via Resend."""
    logger.info(f"Sending notification email to: {email_address}")
    params: resend.Emails.SendParams = {
        "from": "SirenScan <devs@sirenscan.online>",
        "to": [email_address],
        "subject": "Your Email Has Been Successfully Processed",
        "html": """
            <p>Hello,</p>

            <p>Your submitted email has been <strong>successfully processed</strong>.</p>

            <p>We've completed all security checks, including:</p>
            <ul>
              <li>VirusTotal analysis</li>
              <li>Phishing detection</li>
              <li>Have I Been Pwned (HIBP) verification</li>
            </ul>

            <p>You can now view the full results and detailed breakdown on our platform:</p>
            <p>
              &#128073; <a href="https://sirenscan.cosedevs.com" target="_blank" rel="noopener noreferrer">
                https://sirenscan.cosedevs.com
              </a>
            </p>

            <p>If you have any questions or need further assistance, feel free to reply to this email.</p>

            <p>Stay safe,<br>
            <strong>SirenScan Team</strong></p>
        """,
        "reply_to": "no-reply@sirenscan.online",
    }
    try:
        response = resend.Emails.send(params)
        logger.info(f"Email sent successfully! Response ID: {response['id']}")
    except Exception as e:
        logger.error(f"Failed to send email to {email_address}: {e}")

