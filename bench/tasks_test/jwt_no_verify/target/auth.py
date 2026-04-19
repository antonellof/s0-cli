"""Auth helper that decodes user-supplied JWTs without checking signatures."""

import jwt
from flask import Flask, request

app = Flask(__name__)


@app.route("/me")
def me() -> dict:
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        return {"error": "no token"}, 401
    payload = jwt.decode(token, options={"verify_signature": False})
    return {"user": payload.get("sub", "anonymous")}
