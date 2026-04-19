"""Flask views with an XSS sink."""

from flask import Flask, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "stranger")
    html = f"<h1>Hello, {name}!</h1>"
    return html


@app.route("/safe-greet")
def safe_greet():
    from markupsafe import escape
    name = escape(request.args.get("name", "stranger"))
    return f"<h1>Hello, {name}!</h1>"
