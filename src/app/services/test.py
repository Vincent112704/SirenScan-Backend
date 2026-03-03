import requests
import logging

logger = logging.getLogger("uvicorn.error")

HF_ENDPOINT = "https://ig7vp8lnan86bmhg.us-east-1.aws.endpoints.huggingface.cloud"

# File types the model should consider for context (not used in this file but documented)
SUPPORTED_ATTACHMENT_TYPES = {
    "images": [".jpg", ".jpeg", ".png", ".gif", ".bmp"],
    "media": [".mp4", ".mp3", ".avi"],
    "executables": [".exe", ".dll", ".msi", ".com", ".elf", ".dmg", ".deb", ".rpm"],
    "documents": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt"],
}


def model_interface1(email_text: str) -> str:
    """Classify email text as Phishing or Legitimate using HuggingFace model.

    Handles both flat [{"label": ..., "score": ...}] and nested
    [[{"label": ..., "score": ...}, ...]] response formats from HF endpoints.
    """
    try:
        data = {"inputs": email_text}
        response = requests.post(HF_ENDPOINT, json=data, timeout=30)
        response.raise_for_status()

        raw = response.json()
        logger.info(f"ML model raw response: {raw}")

        # Normalise HuggingFace response into a flat list of {label, score} dicts.
        # Dedicated Inference Endpoints return [[{...}, {...}]] (nested).
        # The Inference API sometimes returns [{...}] (flat).
        predictions = raw
        if predictions and isinstance(predictions[0], list):
            predictions = predictions[0]  # unwrap the outer list

        if not predictions or not isinstance(predictions, list):
            logger.error(f"Unexpected ML model response structure: {raw}")
            return "Unknown"

        # Find the LABEL_1 (phishing) entry specifically
        phishing_score = 0.0
        legitimate_score = 0.0
        for pred in predictions:
            label = pred.get("label", "")
            score = pred.get("score", 0.0)
            if label == "LABEL_1":
                phishing_score = score
            elif label == "LABEL_0":
                legitimate_score = score

        logger.info(f"ML scores — Phishing (LABEL_1): {phishing_score:.4f}, Legitimate (LABEL_0): {legitimate_score:.4f}")

        if phishing_score > legitimate_score:
            return "Phishing"
        return "Legitimate"

    except requests.exceptions.Timeout:
        logger.error("ML model request timed out")
        return "Unknown"
    except Exception as e:
        logger.error(f"ML model inference failed: {e}")
        return "Unknown"

