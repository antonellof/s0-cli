"""Two flavors of OS command injection in one tiny Flask app."""

import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping() -> str:
    host = request.args.get("host", "localhost")
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout


@app.route("/lookup")
def lookup() -> str:
    domain = request.args.get("domain", "example.com")
    os.system("dig +short " + domain)
    return "ok"


@app.route("/healthz")
def healthz() -> str:
    return "ok"
