# Copyright 2025: NemesisCyberForce
# App: CryptGuardian 
# File: CryptGuardian/api/fastapi_app.py
# Version: 0.1
# Comment: FastAPI-Core
from fastapi import FastAPI, Request
from core.nonce_based import Blockchain

app = FastAPI()
bc = Blockchain()

@app.post("/validate")
async def validate(request: Request):
    data = await request.json()
    try:
        bc.add_block(data["message"])
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}

