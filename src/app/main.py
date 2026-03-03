from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.api.v1.inbound_email import router as mail_router
import logging

logger = logging.getLogger("uvicorn.error")

app = FastAPI(title="SirenScan API", version="1.0.0")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


@app.get("/")
def root():
    return {"message": "SirenScan API is running"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


app.include_router(mail_router, prefix="/api/v1")

