"""Snapshot-restore endpoint. Pickle says hi."""

import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/restore")
def restore() -> str:
    blob = request.args.get("state", "")
    state = pickle.loads(base64.b64decode(blob))
    return f"restored {type(state).__name__}"
