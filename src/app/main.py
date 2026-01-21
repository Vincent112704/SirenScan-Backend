from fastapi import FastAPI
from api.v1.inbound_email import router as mail_router
app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello World"}

app.include_router(mail_router, prefix="/api/v1")