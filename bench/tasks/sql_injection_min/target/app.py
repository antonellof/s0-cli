"""Minimal Flask handler with a textbook SQL injection."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def get_user():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = f"SELECT name, email FROM users WHERE id = {user_id}"
    cur.execute(query)
    row = cur.fetchone()
    return {"row": row}


@app.route("/healthz")
def healthz():
    return "ok"
