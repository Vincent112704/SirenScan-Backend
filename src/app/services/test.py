import requests


def model_interface1(email_text: str) -> str:
    data = {"inputs": email_text[:1000]}  # Truncate to 512 characters for model input
    response = requests.post("https://ig7vp8lnan86bmhg.us-east-1.aws.endpoints.huggingface.cloud", json=data)
    print("Response: ", response)
    print("Response JSON: ", response.json())
    res = response.json()[0]
    label = res['label']
    score = res['score']
    threshold = 0.98

    print(res)
    if label == "LABEL_1" and score >= threshold:   
        return "Phishing"
    else:
        return "legitimate"
    


