from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_classic.chains import LLMChain


load_dotenv()

LLM = ChatOpenAI(
    model="gpt-4.1-mini",
    temperature=0.2   
)

TEMPLATE ="""
        You are an expert cybersecurity analyst. Based on the results from 
        a phishing email detection model: {model_report} that was run on the email body: {email_body},
        a VirusTotal scan: {virus_total_report}, and a virus total file scan: {virus_total_file_report}.

        Produce: 
        1. A synthesis of the findings from all three sources.
        2. Any notable insights or red flags.
        3. Suggested next actions if applicable.
        4. A suggestion for the user on the best course of action regarding the email (e.g., delete, mark as spam, proceed with caution).

        Write clearly and professionally. Provide the analysis STRICTLY in plain text only. Do not use Markdown, bolding (**), or headers (#)
        """


def LLM_interface(model_report, virus_total_report, email_body, virus_total_file_report):
    synthesis_prompt = PromptTemplate.from_template(TEMPLATE)
    llm_chain = LLMChain(llm=LLM, prompt=synthesis_prompt)
    response = llm_chain.invoke(input = {"model_report": model_report, "email_body": email_body, "virus_total_report": virus_total_report, "virus_total_file_report": virus_total_file_report})
    return response["text"]




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