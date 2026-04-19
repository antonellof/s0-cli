"""Static-file server that forgets to validate the requested path."""

import os

from flask import Flask, request

app = Flask(__name__)
STATIC_ROOT = "static"


@app.route("/file")
def serve_file() -> tuple[str, int]:
    name = request.args.get("name", "index.html")
    full_path = os.path.join(STATIC_ROOT, name)
    with open(full_path, encoding="utf-8") as f:
        return f.read(), 200


@app.route("/healthz")
def healthz() -> str:
    return "ok"
