from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse


router = APIRouter()

@router.post("/mailgun/inbound")
async def inbound_email(request: Request):
    form = await request.form()

    sender = form.get("sender")
    recipient = form.get("recipient")
    subject = form.get("subject")
    body_plain = form.get("body-plain")
    body_html = form.get("body-html")

    print("\n=== MAILGUN INBOUND EMAIL ===")
    print(f"From: {sender}")
    print(f"To: {recipient}")
    print(f"Subject: {subject}")
    print(f"Body (plain):\n{body_plain}")
    print(f"Body (HTML):\n{body_html}")

    # Check for attachments
    attachments = [v for k, v in form.items() if k.startswith("attachment")]
    if attachments:
        print(f"\nAttachments ({len(attachments)} found):")
        for i, file in enumerate(attachments, 1):
            # file is an UploadFile object
            filename = getattr(file, "filename", "unknown")
            print(f"{i}. {filename}")
    else:
        print("\nNo attachments")

    # Return parsed data as JSON
    return JSONResponse({
        "status": "ok",
        "from": sender,
        "to": recipient,
        "subject": subject,
        "body_plain": body_plain,
        "body_html": body_html,
        "attachments": [getattr(f, "filename", None) for f in attachments]
    })
