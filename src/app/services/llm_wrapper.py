from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate


load_dotenv()

LLM = ChatOpenAI(
    model="gpt-4.1-mini",
    temperature=0.2,
    timeout=60,
)

TEMPLATE = """
You are an expert cybersecurity analyst. You are given the following data about an
inbound email that a user forwarded for analysis:

1. Phishing Detection Model Result: {model_report}
2. Email Body (plain text):
{email_body}
3. VirusTotal URL Scan Results (may contain multiple URLs):
{virus_total_report}
4. VirusTotal File/Attachment Scan Results (may contain multiple files):
{virus_total_file_report}

Based on ALL of the evidence above, produce a concise security report with these sections:

1. Overall Threat Assessment — a single verdict (Safe / Suspicious / Dangerous) with a
   brief explanation.
2. Synthesis of Findings — combine the model classification, URL scan results, and file
   scan results into a coherent summary. Highlight agreements and disagreements between
   the sources.
3. Red Flags — list any notable indicators of compromise, suspicious patterns, or
   concerns. If none, state that explicitly.
4. Recommended Action — tell the user exactly what to do with this email (e.g., delete
   immediately, mark as spam, safe to open, proceed with caution).

Write clearly and professionally. Provide the analysis STRICTLY in plain text only.
Do not use Markdown, bolding (**), or headers (#).
"""


def LLM_interface(model_report, virus_total_report, email_body, virus_total_file_report):
    """Generate an LLM synthesis report from all scanning results."""
    synthesis_prompt = PromptTemplate.from_template(TEMPLATE)
    chain = synthesis_prompt | LLM
    response = chain.invoke({
        "model_report": model_report,
        "email_body": email_body,
        "virus_total_report": virus_total_report,
        "virus_total_file_report": virus_total_file_report,
    })
    return response.content




#Sample values for testing
# model_report = "Phishing"

# email_body = """
# From: security@paypaI-alerts.com
# To: vincent@example.com
# Subject: Urgent: Account Suspended

# Dear user,

# We detected unusual activity on your PayPal account.
# To restore access, please verify your identity immediately.

# Verify here: http://paypaI-verification-login[.]com/auth

# Failure to act within 24 hours will result in permanent suspension.

# Regards,
# PayPal Security Team
# """
# virus_total_report = {
#     "scanned_url": "http://paypaI-verification-login.com/auth",
#     "malicious": True,
#     "detection_ratio": "23/94",
#     "engines_detected": [
#         "Google Safebrowsing",
#         "Kaspersky",
#         "BitDefender",
#         "PhishTank"
#     ],
#     "scan_date": "2026-01-21T02:14:33Z"
# }
# pwned_report = {
#     "email_checked": "security@paypaI-alerts.com",
#     "breached": True,
#     "breach_count": 3,
#     "breaches": [
#         {
#             "name": "Collection1",
#             "date": "2019-01-07",
#             "data_types": ["Emails", "Passwords"]
#         },
#         {
#             "name": "Dubsmash",
#             "date": "2019-12-22",
#             "data_types": ["Emails", "Usernames"]
#         },
#         {
#             "name": "MyFitnessPal",
#             "date": "2018-02-01",
#             "data_types": ["Emails", "Passwords"]
#         }
#     ]
# }