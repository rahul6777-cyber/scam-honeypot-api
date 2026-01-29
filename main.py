from fastapi import FastAPI
from fastapi import FastAPI, Depends
from detector import detect_scam
from responder import generate_reply
from extractor import extract_intel
from security import verify_api_key

app = FastAPI(title="Scam Honeypot API")

@app.get("/")
def root():
    return {"status": "API running"}

@app.post("/webhook/message")
def message(data: dict, api_key: str = Depends(verify_api_key)):
    text = data.get("message", "")
    analysis = detect_scam(text)
    reply = generate_reply(analysis)
    intelligence = extract_intel(text)

    return {
        "status": "authorized",
        "data": data,
        "input_message": text,
        "analysis": analysis,
        "auto_reply": reply,
        "extracted_intelligence": intelligence
    }