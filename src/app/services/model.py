from transformers import BertForSequenceClassification, BertTokenizer
import torch

model_name = 'ElSlay/BERT-Phishing-Email-Model'

# Load the pre-trained model and tokenizer
model = BertForSequenceClassification.from_pretrained(model_name)
tokenizer = BertTokenizer.from_pretrained(model_name)
model.eval()

def model_interface(email_text: str) -> str:
    inputs = tokenizer(email_text, return_tensors="pt", truncation=True, padding='max_length', max_length=512)

    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        predictions = torch.argmax(logits, dim=-1)

    # Interpret the prediction
    result = "Phishing" if predictions.item() == 1 else "Legitimate"
    return result

# Example usage:
# phishing1 = """Subject: Urgent — Account Verification Required\n\nDear user,
# \n\nWe detected unusual activity in your NovaBank account. To prevent suspension, 
# you must verify your identity immediately.\n\nVerify here: http://novabank-secure-login.verify-user.com\n\nFailure to 
# verify within 24 hours will result in permanent account closure.\n\nNovaBank Security Team"
# """

# phishing2 = """
# "Subject: Congratulations! You've Won a Reward\n\nHello,\n\nYour email 
# was randomly selected to receive a ₱50,000 cash reward from StarRewards.\n\nTo claim your 
# prize, confirm your personal details here: http://star-rewards-claim.prize-form.net\n\nHurry! Offer expires today.
# \n\nStarRewards Promotions"
# """

# legit1 = """
# "Subject: Meeting Reminder — Project Sync\n\nHi Aurelius,\n\nJust a reminder 
# that our project sync meeting is scheduled for tomorrow at 3:00 PM via Zoom. 
# Let me know if you need the agenda beforehand.\n\nBest regards,\nDaniel"

# """

# legit2 = """
# "Subject: Your Order Has Shipped\n\nHello,\n\nYour order #48291 from LunaTech 
# Store has been shipped and is on its way. You can track your package using 
# the tracking number provided in your account dashboard.\n\nThank you for shopping with us.
# \n\nLunaTech Support"

# """

# print("Phishing Test 1 Prediction:", model_interface(phishing1))
# print("Phishing Test 2 Prediction:", model_interface(phishing2))
# print("Legitimate Test 1 Prediction:", model_interface(legit1))
# print("Legitimate Test 2 Prediction:", model_interface(legit2))