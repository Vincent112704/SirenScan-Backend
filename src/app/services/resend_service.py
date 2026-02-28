import resend
import os
from dotenv import load_dotenv

load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")

def send_email(email_address: str):
  print(f"email: {email_address}")
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
              👉 <a href="siren-scan-frontend.vercel.app" target="_blank" rel="noopener noreferrer">
                siren-scan-frontend.vercel.app
              </a>
            </p>

            <p>If you have any questions or need further assistance, feel free to reply to this email.</p>

            <p>Stay safe,<br>
            <strong>The Template Security Team</strong></p>
        """,
    "reply_to": "no-reply@sirenscan.online"
  }
  try:
    response = resend.Emails.send(params)
    print(f"Email sent successfully! Response ID: {response['id']}")
  except Exception as e:
    print(f"Failed to send email: {e}")

