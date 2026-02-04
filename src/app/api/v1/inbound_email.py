from fastapi import APIRouter, Request, UploadFile
from fastapi.responses import JSONResponse
from typing import cast
from app.firebase import db
from app.services.llm_wrapper import LLM_interface
from app.services.virus_total import scan_url, scan_file
from app.services.html_parser import parse_html_content
from app.services.HIBP import HIBP_check
from app.services.model import model_interface
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

logger = logging.getLogger("uvicorn.error")  
logger.info("This will appear in the console")
router = APIRouter()

@router.post("/mailgun/inbound", response_model=None)
async def inbound_email(request: Request):
    try:
        form = await request.form()
        sender = form.get("sender")
        subject = form.get("subject")
        body_plain = form.get("body-plain")
        body_html = form.get("body-html")
        inbound_id = form.get("token")
        attachment = form.get("attachment-1") 
        logging.info(f"token-Id: {inbound_id}")
        print( f"Print: token-Id: {inbound_id}" )

        if subject is None or body_plain is None or body_html is None:
            return JSONResponse(status_code=400, content={"error": "Missing required email fields."})
        else:

            doc_ref = db.collection("inbound_emails").document(str(inbound_id))
            doc_snapshot = cast(DocumentSnapshot, doc_ref.get())

            if doc_snapshot.exists:
                print( f"Print: Email {inbound_id} already processed, skipping." )
                logging.info(f"Email {inbound_id} already processed, skipping.")
                JSONResponse({"status": "duplicate"})
            else:
                model_arg = f"Subject: {subject}\n\n{body_plain}"
                model_result = model_interface(model_arg)

                hashed_email = hash_email(str(sender).lower().strip())
                #processing email and saving to DB
                email_data = {
                    "sender": hashed_email,
                    "inbound_id": inbound_id,
                    "subject": subject,
                    "body_plain": body_plain,
                    "body_html": body_html, 
                    "model_result": model_result
                }

                doc_ref = db.collection("inbound_emails").document(str(inbound_id))
                doc_ref.set(email_data)
                email_data_id = doc_ref.id
                print( f"Print: Inbound email stored with ID: {email_data}" )
                logging.info(f"Inbound email stored with ID: {email_data}")

                file_response = {}
                print(f"print: file {attachment}")
                print(type(attachment))

                file_response = {}

                if isinstance(attachment, UploadFile):
                    contents = await attachment.read()
                    await attachment.seek(0)
                    print("Now inside isinstance")
                    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temp:
                        temp.write(contents)
                        temp.flush()
                        temp_path = temp.name
                        print(temp_path)

                    try:
                        file_response = scan_file(temp_path)
                        file_response["inbound_email_id"] = inbound_id
                        print(file_response)
                        db.collection("file_analyses").document().set(file_response)
                    finally:
                        os.remove(temp_path)
                
                #processing HIBP and saving to DB
                hibp_id = f"hibp_{hashed_email}"
                doc_ref = db.collection("hibp_analyses").document(hibp_id)
                doc_snapshot = cast(DocumentSnapshot, doc_ref.get())
                print( f"Print: Checking HIBP for {doc_snapshot}" )

                if doc_snapshot.exists:
                    print( f"Print: Record for {hashed_email} already exists, skipping HIBP check." )
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
                    print( f"Print: HIBP Analysis: {hibp_analysis}" )
                    logging.info(f"HIBP Analysis: {hibp_analysis}")
                    db.collection("hibp_analyses").document(hibp_id).set(hibp_analysis)
                    
                # processing virus total url and saving to DB
                url_analysis = {}
                isURL = parse_html_content(body_html)
                logging.info(f"Extracted URL: {isURL}")
                print( f"Print: Extracted URL: {isURL}" )
                if isURL:
                    logging.info(f"Parsed URL result: {isURL} (type={type(isURL)})")
                    
                    url_response = scan_url(isURL)
                    url_id = url_response.get("meta",{}).get("url_info", {}).get("id", "")
                    url_db_id = f"url_{url_id}"
                    doc_ref = db.collection("url_analyses").document(url_db_id)
                    doc_snapshot = cast(DocumentSnapshot, doc_ref.get())
                    print( f"Print: VirusTotal URL Response: {url_response}" )
                    logging.info(f"VirusTotal URL Response: {url_response}")
                    if not doc_snapshot.exists:
                        url_analysis = {
                            "analysis_id": url_response.get("meta",{}).get("url_info", {}).get("id", ""),
                            "url": url_response.get("meta", {}).get("url_info", {}).get("url", ""),
                            "stats": url_response.get("data", {}).get("attributes", {}).get("stats", {}), 
                            "results": url_response.get("data", {}).get("attributes", {}).get("results", {}),
                            "inbound_email_id": inbound_id, 
                            "email_sender": hashed_email
                        }
                        print( f"Print: URL Analysis: {url_analysis}" )
                        logging.info(f"URL Analysis: {url_analysis}")
                        db.collection("url_analyses").document(url_id).set(url_analysis)
                    else: 
                        logging.info(f"Record for URL ID {url_id} already exists, skipping write.")
                        print( f"Print: Record for URL ID {url_id} already exists, skipping write." )
                else: 
                    logging.info("No URL found in the email body.")
                    print( f"Print: No URL found in the email body." )
                
                
                #llm synthesis report
                LLM_res = LLM_interface(model_result, json.dumps(url_analysis) if url_analysis else "{}", body_plain, json.dumps(file_response)) #take note of attachments
                logging.info(f"LLM Synthesis: {LLM_res}")
                print( f"Print: LLM Synthesis: {LLM_res}" )
                db.collection("inbound_emails").document(email_data_id).update({"LLM_synthesis": LLM_res})
                
                send_email(str(sender))
                return JSONResponse(status_code=200, content={"message": "Inbound email processed successfully."})

    except Exception as e:
        return JSONResponse({"status": "received", "error": str(e)}, status_code=200)