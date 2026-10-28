from flask import Flask, jsonify, render_template, request

from config import MAX_CONTENT_LENGTH, MAX_URL_LENGTH, SECRET_KEY
from core.analyzer import analyze_url


def create_app():
    app = Flask(__name__)
    app.config.update(SECRET_KEY=SECRET_KEY, MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH)

    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "PhishLens"})

    @app.post("/api/analyze")
    def analyze():
        if not request.is_json:
            return jsonify({"error": "Request body must be JSON."}), 415
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
            return jsonify({"error": "JSON must contain a string 'url' field."}), 400
        if len(payload["url"]) > MAX_URL_LENGTH:
            return jsonify({"error": "The URL must be 2,048 characters or fewer."}), 413
        result = analyze_url(payload["url"])
        return jsonify(result), 200 if result["status"] == "ok" else 422

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=False)
