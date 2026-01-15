from transformers import BertForSequenceClassification, BertTokenizer
import torch

model_name = 'ElSlay/BERT-Phishing-Email-Model'

# Load the pre-trained model and tokenizer
model = BertForSequenceClassification.from_pretrained(model_name)
tokenizer = BertTokenizer.from_pretrained(model_name)
model.eval()

def model_inference(email_text: str) -> str:
    inputs = tokenizer(email_text, return_tensors="pt", truncation=True, padding='max_length', max_length=512)

    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        predictions = torch.argmax(logits, dim=-1)

    # Interpret the prediction
    result = "Phishing" if predictions.item() == 1 else "Legitimate"
    return result