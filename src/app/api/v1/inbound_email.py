from fastapi import APIRouter, Request, UploadFile, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import cast
from app.firebase import db
from app.services.llm_wrapper import LLM_interface
from app.services.virus_total import scan_url, scan_file
from app.services.html_parser import parse_html_content
from app.services.HIBP import HIBP_check
from app.services.email_hasher import hash_email
from app.services.resend_service import send_email
from app.services.test import model_interface1
from google.cloud.firestore_v1 import DocumentSnapshot
import asyncio
import json
import logging
import os
import tempfile

logger = logging.getLogger("uvicorn.error")

router = APIRouter()

# Allowed file extensions for VirusTotal scanning
ALLOWED_EXTENSIONS = {
    # Images & Media
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp4", ".mp3", ".avi",
    # Executables
    ".exe", ".dll", ".msi", ".com", ".elf", ".dmg", ".deb", ".rpm",
    # Documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt",
}


def _get_file_extension(filename: str) -> str:
    """Extract and validate file extension from a filename."""
    if not filename:
        return ""
    _, ext = os.path.splitext(filename.lower())
    return ext


@router.post("/mailgun/inbound", response_model=None)
async def inbound_email(request: Request, background_tasks: BackgroundTasks):
    try:
        form = await request.form()
        sender = form.get("sender")
        subject = form.get("subject")
        body_plain = form.get("body-plain")
        body_html = form.get("body-html")
        inbound_id = form.get("token")

        if not all([sender, subject, body_plain, body_html]):
            return JSONResponse(status_code=400, content={"error": "Missing required email fields."})

        if not inbound_id:
            return JSONResponse(status_code=400, content={"error": "Missing inbound token."})

        # Non-blocking Firestore duplicate check
        doc_ref = db.collection("inbound_emails").document(str(inbound_id))
        doc_snapshot = cast(DocumentSnapshot, await asyncio.to_thread(doc_ref.get))

        if doc_snapshot.exists:
            logger.info(f"Duplicate email received with inbound_id: {inbound_id}. Skipping.")
            return JSONResponse(status_code=200, content={"status": "duplicate"})

        hashed_email = hash_email(str(sender).lower().strip())
        email_data = {
            "sender": hashed_email,
            "inbound_id": inbound_id,
            "subject": subject,
            "body_plain": body_plain,
            "body_html": body_html,
            "status": "processing",
        }
        await asyncio.to_thread(doc_ref.set, email_data)

        # --- Collect ALL attachments (Mailgun sends attachment-1, attachment-2, ...) ---
        attachment_paths = []
        attachment_index = 1
        while True:
            attachment = form.get(f"attachment-{attachment_index}")
            if attachment is None:
                break
            if isinstance(attachment, UploadFile):
                original_filename = getattr(attachment, "filename", "") or ""
                ext = _get_file_extension(original_filename)
                if ext and ext in ALLOWED_EXTENSIONS:
                    contents = await attachment.read()
                    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as temp:
                        temp.write(contents)
                        temp.flush()
                        attachment_paths.append(temp.name)
                    logger.info(f"Attachment saved: {original_filename} -> {attachment_paths[-1]}")
                else:
                    logger.warning(f"Skipping attachment '{original_filename}' — unsupported extension '{ext}'")
            attachment_index += 1

        background_tasks.add_task(
            process_email_async,
            hashed_email=hashed_email,
            inbound_id=inbound_id,
            sender=sender,
            subject=subject,
            body_plain=body_plain,
            body_html=body_html,
            attachment_paths=attachment_paths,
        )

        return JSONResponse(
            status_code=200,
            content={
                "message": "Inbound email received and is being processed.",
                "inbound_id": inbound_id,
            },
        )
    except Exception as e:
        logger.error(f"Error handling inbound email: {e}")
        return JSONResponse(status_code=500, content={"error": "Internal server error"})



async def process_email_async(
    inbound_id,
    hashed_email,
    sender,
    subject,
    body_plain,
    body_html,
    attachment_paths: list[str],
):
    try:
        logger.info(f"Starting async processing for email: {inbound_id}")
        doc_ref = db.collection("inbound_emails").document(str(inbound_id))

        # Extract URLs from HTML (fast, no I/O)
        extracted_urls = parse_html_content(body_html)
        model_arg = f"Subject: {subject}\n\n{body_plain}"

        # ---- Define parallel sub-tasks ----

        async def run_model():
            """Classify email with ML model."""
            try:
                result = await asyncio.to_thread(model_interface1, model_arg)
                await asyncio.to_thread(doc_ref.update, {"model_result": result})
                return result
            except Exception as e:
                logger.error(f"ML model task failed: {e}")
                return "Unknown"

        async def _scan_single_file(file_path: str) -> dict:
            """Scan a single attachment file with VirusTotal and clean up."""
            try:
                result = await asyncio.to_thread(scan_file, file_path)
                result["inbound_email_id"] = inbound_id
                await asyncio.to_thread(
                    db.collection("file_analyses").document().set, result
                )
                return result
            except Exception as e:
                logger.error(f"File scan failed for {file_path}: {e}")
                return {"error": str(e)}
            finally:
                if file_path and os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        logger.error(f"Error removing temp file {file_path}: {e}")

        async def run_file_scans():
            """Scan all attachment files with VirusTotal in parallel."""
            if not attachment_paths:
                return []
            results = await asyncio.gather(
                *[_scan_single_file(path) for path in attachment_paths]
            )
            return list(results)

        async def run_hibp_check():
            """Check Have I Been Pwned for sender's email."""
            try:
                hibp_id = f"hibp_{hashed_email}"
                doc_ref_hibp = db.collection("hibp_analyses").document(hibp_id)
                snapshot = cast(
                    DocumentSnapshot, await asyncio.to_thread(doc_ref_hibp.get)
                )
                if snapshot.exists:
                    logger.info(f"HIBP record for {hashed_email} already exists, skipping.")
                    return

                hibp_response = await asyncio.to_thread(HIBP_check, sender)
                if hibp_response is None:
                    logger.error("HIBP check failed")
                    return
                if hibp_response:
                    hibp_analysis = {
                        "email": hashed_email,
                        "breaches": [
                            {
                                "Name": b["Name"],
                                "Title": b.get("Title", ""),
                                "Description": b.get("Description", ""),
                                "DataClasses": b.get("DataClasses", []),
                                "BreachDate": b.get("BreachDate", ""),
                            }
                            for b in hibp_response
                        ],
                    }
                    await asyncio.to_thread(doc_ref_hibp.set, hibp_analysis)
            except Exception as e:
                logger.error(f"HIBP check task failed: {e}")

        async def _scan_single_url(url: str) -> dict:
            """Scan a single URL with VirusTotal."""
            try:
                logger.info(f"Scanning URL: {url}")
                url_response = await asyncio.to_thread(scan_url, url)

                if "error" in url_response:
                    logger.error(f"URL scan failed for {url}: {url_response['error']}")
                    return {}

                url_id = url_response.get("meta", {}).get("url_info", {}).get("id", "")
                url_db_id = f"url_{url_id}"
                doc_ref_vt = db.collection("url_analyses").document(url_db_id)
                snapshot = cast(
                    DocumentSnapshot, await asyncio.to_thread(doc_ref_vt.get)
                )
                if not snapshot.exists:
                    url_analysis = {
                        "analysis_id": url_id,
                        "url": url_response.get("meta", {}).get("url_info", {}).get("url", ""),
                        "stats": url_response.get("data", {}).get("attributes", {}).get("stats", {}),
                        "results": url_response.get("data", {}).get("attributes", {}).get("results", {}),
                        "inbound_email_id": inbound_id,
                        "email_sender": hashed_email,
                    }
                    await asyncio.to_thread(doc_ref_vt.set, url_analysis)
                    return url_analysis
                else:
                    logger.info(f"URL record {url_db_id} already exists, skipping.")
                    return {}
            except Exception as e:
                logger.error(f"URL scan task failed for {url}: {e}")
                return {}

        async def run_url_scans():
            """Scan all extracted URLs with VirusTotal in parallel."""
            if not extracted_urls:
                logger.info("No URLs found in the email body.")
                return []
            results = await asyncio.gather(
                *[_scan_single_url(url) for url in extracted_urls]
            )
            # Filter out empty results
            return [r for r in results if r]

        # ---- Run all independent tasks in parallel ----
        model_result, file_responses, _, url_analyses = await asyncio.gather(
            run_model(),
            run_file_scans(),
            run_hibp_check(),
            run_url_scans(),
        )

        # ---- LLM synthesis (depends on results above) ----
        llm_result = await asyncio.to_thread(
            LLM_interface,
            model_result,
            json.dumps(url_analyses) if url_analyses else "[]",
            body_plain,
            json.dumps(file_responses) if file_responses else "[]",
        )
        await asyncio.to_thread(
            doc_ref.update,
            {"LLM_synthesis": llm_result, "status": "completed"},
        )

        await asyncio.to_thread(send_email, str(sender))
        logger.info(f"Email {inbound_id} processed successfully")

    except Exception as e:
        logger.error(f"Error processing email {inbound_id}: {e}")
        try:
            await asyncio.to_thread(
                db.collection("inbound_emails").document(str(inbound_id)).update,
                {"status": "failed", "error": str(e)},
            )
        except Exception as db_err:
            logger.error(f"Failed to update error status in DB: {db_err}")