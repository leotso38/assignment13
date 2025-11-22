import uuid

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def register_user(username: str = "testuser", email: str = "test@example.com"):
    payload = {
        "username": username,
        "email": email,
        "first_name": "Test",
        "last_name": "User",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!",
    }
    resp = client.post("/auth/register", json=payload)
    # app may return 200 or 201 depending on how the route is defined
    assert resp.status_code in (200, 201)
    return payload


def login_user(username: str, password: str = "SecurePass123!"):
    resp = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    return data["access_token"]


def auth_headers(token: str):
    return {"Authorization": f"Bearer {token}"}


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "ok"


def test_root_returns_html():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    # Just sanity-check that it’s an HTML page
    assert "<!DOCTYPE html>" in resp.text


def test_register_page_returns_html():
    resp = client.get("/register")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    # Heading from the template
    assert "Create Account" in resp.text


def test_login_page_returns_html():
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    # Template uses "Login" (no space) in title/heading
    assert ("Log in" in resp.text) or ("Login" in resp.text)


def test_browse_calculations_requires_auth():
    # No Authorization header -> should be rejected
    resp = client.get("/calculations")
    assert resp.status_code in (401, 403)


def test_browse_calculations_with_auth():
    # Create and log in a user
    username = "calcuser1"
    email = "calcuser1@example.com"
    register_user(username=username, email=email)
    token = login_user(username=username)

    resp = client.get("/calculations", headers=auth_headers(token))
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_get_calculation_invalid_uuid_with_auth():
    username = "calcuser2"
    email = "calcuser2@example.com"
    register_user(username=username, email=email)
    token = login_user(username=username)

    # invalid UUID format -> should hit 400 branch in get_calculation
    resp = client.get("/calculations/not-a-uuid", headers=auth_headers(token))
    assert resp.status_code == 400
    assert "Invalid calculation id format" in resp.text


def test_get_calculation_not_found_with_auth():
    username = "calcuser3"
    email = "calcuser3@example.com"
    register_user(username=username, email=email)
    token = login_user(username=username)

    # well-formed UUID that does not exist -> should hit 404 branch
    fake_id = str(uuid.uuid4())
    resp = client.get(f"/calculations/{fake_id}", headers=auth_headers(token))
    assert resp.status_code == 404
    assert "Calculation not found" in resp.text
