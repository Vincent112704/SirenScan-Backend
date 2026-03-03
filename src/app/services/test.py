import requests


def model_interface1(email_text: str) -> str:
    data = {"inputs": email_text[:1000]}  # Truncate to 512 characters for model input
    response = requests.post("https://ig7vp8lnan86bmhg.us-east-1.aws.endpoints.huggingface.cloud", json=data)
    res = response.json()[0]
    label = res['label']
    score = res['score']
    threshold = 0.96

    print(res)
    if label == "LABEL_1" and score >= threshold:   
        return "Phishing"
    else:
        return "legitimate"
    
    
test1 = '''
---------- Forwarded message --------- From: Atome <no-reply@service.atome.ph> Date: Tue, Mar 3, 2026 at 12:05 PM Subject: Transaction Confirmation: CBTL 1789 To: <tian2x04@gmail.com> Dear Vincent Paul, We are pleased to inform you that your payment of ₱195.00 for CBTL 1789 using QR Ph has been successfully processed. You can access your Loan Schedule Agreement via Atome App under Transaction Details once the transaction has been fully processed with the merchant. We look forward to serving you again in the future. Your friends at Atome Card Atome.ph <https://linkmessage.apaylater.com/ss/c/u001.9rMiIu5Qu4YP7GTVnc688ZkULyiolcyZ_x85FmQhcJo/4om/3aNvd_vERVKBibubQq13eA/h0/h001.r7kpirO4KT1xdEY_2ntRmioOSvamVkMXbQuNqyrTj5c> This email and any attachments are confidential and may also be privileged. If you are not the intended recipient, please delete all copies and notify support@atome.ph immediately Copyright 2026 © Atome. All rights reserved
'''
model_interface1(test1)
