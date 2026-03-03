from fastapi import APIRouter, Request, UploadFile, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Optional, cast
from app.firebase import db
from app.services.llm_wrapper import LLM_interface
from app.services.virus_total import scan_url, scan_file
from app.services.html_parser import parse_html_content
from app.services.HIBP import HIBP_check
from app.services.email_hasher import hash_email
from app.services.resend_service import send_email
from google.cloud.firestore_v1 import DocumentSnapshot
import logging
import json
import tempfile
import logging
from starlette.datastructures import UploadFile
import tempfile
import os
from app.services.test import model_interface1

logger = logging.getLogger("uvicorn.error")  

router = APIRouter()

@router.post("/mailgun/inbound", response_model=None)
async def inbound_email(request: Request, background_tasks: BackgroundTasks):
    try:
        form = await request.form()
        sender = form.get("sender")
        subject = form.get("subject")
        body_plain = form.get("body-plain")
        body_html = form.get("body-html")
        inbound_id = form.get("token")
        attachment = form.get("attachment-1") 
        
        
        if not all([sender, subject, body_plain, body_html]):
            return JSONResponse(status_code=400, content={"error": "Missing required email fields."})
         
        doc_ref = db.collection("inbound_emails").document(str(inbound_id))
        doc_snapshot = cast(DocumentSnapshot, doc_ref.get())

        if doc_snapshot.exists:
            logger.info(f"Duplicate email received with inbound_id: {inbound_id}. Skipping processing.")
            return JSONResponse(status_code=200, content={"status": "duplicate"})
        
        else:
            
            hashed_email = hash_email(str(sender).lower().strip())
            email_data = {
                "sender": hashed_email,
                "inbound_id": inbound_id,
                "subject": subject,
                "body_plain": body_plain,
                "body_html": body_html, 
                "status": "processed"
            }
            
            doc_ref.set(email_data)

            temp_path = None
            if attachment is not None and isinstance(attachment, UploadFile):
                contents = await attachment.read()
                await attachment.seek(0)
                with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temp:
                    temp.write(contents)
                    temp.flush()
                    temp_path = temp.name
            print(f"Temp file created at: {temp_path}")
            logging.info(f"Temp file created at: {temp_path}")
            background_tasks.add_task(
                process_email_async,
                hashed_email=hashed_email,
                inbound_id=inbound_id,
                sender=sender,
                subject=subject,
                body_plain=body_plain,
                body_html=body_html,
                attachment_path=temp_path
            )

        return JSONResponse(
            status_code=200, 
            content={
                "message": "Inbound email received and is being processed.", 
                "inbound_id": inbound_id
                }
            )
    except Exception as e:
        return JSONResponse({"status": "received", "error": str(e)}, status_code=200)
    


async def process_email_async(
    inbound_id,
    hashed_email,
    sender,
    subject,
    body_plain,
    body_html,
    attachment_path, 
):
    print("Attachment path in async task:", attachment_path)
    logging.info(f"Attachment path in async task: {attachment_path}")
    try:
        print("Starting async processing for email:", inbound_id)
        doc_ref = db.collection("inbound_emails").document(str(inbound_id))
        model_arg = f"Subject: {subject}\n\n{body_plain}"
        model_result = model_interface1(model_arg)
        doc_ref.update({"model_result": model_result})

        file_response = {}
        print(f"Attachment path: {attachment_path}")
        if attachment_path:
            try:
                file_response = scan_file(attachment_path)
                file_response["inbound_email_id"] = inbound_id
                print(file_response)
                db.collection("file_analyses").document().set(file_response)
            finally:
                if attachment_path and os.path.exists(attachment_path):
                    try:
                        os.remove(attachment_path)
                    except Exception as e:
                        logger.error(f"Error removing temp file {attachment_path}: {e}")

        #processing HIBP and saving to DB
        hibp_id = f"hibp_{hashed_email}"
        doc_refHIBP = db.collection("hibp_analyses").document(hibp_id)
        doc_snapshot = cast(DocumentSnapshot, doc_refHIBP.get())
        print( f"Print: Checking HIBP for {doc_snapshot}" )

        if doc_snapshot.exists:
            logging.info(f"Record for {hashed_email} already exists, skipping write.") 
        else:
            HIBP_response = HIBP_check(sender)
            if HIBP_response is None:
                print("HIBP check failed")
                print(HIBP_response)
                return
            
            hibp_analysis = {
                "email": hashed_email,
                "breaches": [
                    {
                        "Name": b["Name"], 
                        "Title": b.get("Title", ""),
                        "Description": b.get("Description", ""),
                        "DataClasses": b.get("DataClasses", []),
                        "BreachDate": b.get("BreachDate", ""),
                    } for b in HIBP_response
                ] 
            }
            logging.info(f"HIBP Analysis: {hibp_analysis}")
            db.collection("hibp_analyses").document(hibp_id).set(hibp_analysis)


        # processing virus total url and saving to DB
        url_analysis = {}
        isURL = parse_html_content(body_html)
        print(f"Extracted URL: {isURL}")
        logging.info(f"logger Extracted URL: {isURL}")
        if isURL:
            url_response = scan_url(isURL)
            url_id = url_response.get("meta",{}).get("url_info", {}).get("id", "")
            url_db_id = f"url_{url_id}"
            print(f"URL analysis ID: {url_db_id}")
            logging.info(f"Logger URL analysis ID: {url_db_id}")
            doc_refVtotal = db.collection("url_analyses").document(url_db_id)
            doc_snapshot = cast(DocumentSnapshot, doc_refVtotal.get())
            print(doc_snapshot)
            print("In isURL if statement block")
            logging.info("In isURL if statement block")
            if not doc_snapshot.exists:
                url_analysis = {
                    "analysis_id": url_response.get("meta",{}).get("url_info", {}).get("id", ""),
                    "url": url_response.get("meta", {}).get("url_info", {}).get("url", ""),
                    "stats": url_response.get("data", {}).get("attributes", {}).get("stats", {}), 
                    "results": url_response.get("data", {}).get("attributes", {}).get("results", {}),
                    "inbound_email_id": inbound_id, 
                    "email_sender": hashed_email
                }
                print(f"Inside URL analysis")
                
                db.collection("url_analyses").document(url_db_id).set(url_analysis)
            else: 
                logging.info(f"Record for URL ID {url_db_id} already exists, skipping write.")
        else: 
            logging.info("No URL found in the email body.")

        #llm synthesis report
        LLM_res = LLM_interface(model_result, json.dumps(url_analysis) if url_analysis else "{}", body_plain, json.dumps(file_response)) #take note of attachments
        doc_ref.update({
            "LLM_synthesis": LLM_res,
            "status": "completed"
            }
        )
        send_email(str(sender))
        logger.info(f"Email {inbound_id} processed successfully")

    except Exception as e:
        import traceback
        import uuid
        from datetime import datetime
        
        error_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        error_message = str(e)
        error_traceback = traceback.format_exc()
        
        # Log with full traceback and context
        logging.error(
            f"Email Processing Failed | Error ID: {error_id} | "
            f"Inbound ID: {inbound_id} | Sender: {sender} | Subject: {subject} | "
            f"Timestamp: {timestamp} | Error: {error_message}\n"
            f"Traceback:\n{error_traceback}"
        )
        
        # Update database with comprehensive error information
        db.collection("inbound_emails").document(inbound_id).update({
            "status": "failed",
            "error": error_message,
            "error_id": error_id,
            "error_traceback": error_traceback,
            "failed_at": timestamp,
            "sender": sender,
            "subject": subject
        })