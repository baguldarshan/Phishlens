from app import create_app


def test_api_schema_and_security_headers():
    client = create_app().test_client()
    response = client.post("/api/analyze", json={"url": "https://example.com"})
    data = response.get_json()
    assert response.status_code == 200
    assert {"score", "classification", "rules", "features", "disclaimer"} <= data.keys()
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "connect-src 'self'" in response.headers["Content-Security-Policy"]


def test_invalid_api_input():
    client = create_app().test_client()
    assert client.post("/api/analyze", json={}).status_code == 400
    assert client.post("/api/analyze", data="not json").status_code == 415


def test_dashboard_and_health():
    client = create_app().test_client()
    assert client.get("/").status_code == 200
    assert client.get("/api/health").get_json()["status"] == "ok"
