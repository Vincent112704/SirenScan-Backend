import requests


def model_interface1(email_text: str) -> str:
    data = {"inputs": email_text}
    response = requests.post("https://ig7vp8lnan86bmhg.us-east-1.aws.endpoints.huggingface.cloud", json=data)
    res = response.json()[0]["label"]
    
    return "Phishing" if res == "LABEL_1" else "Legitimate"

