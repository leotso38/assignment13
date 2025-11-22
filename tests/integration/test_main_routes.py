import uuid
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal, Base, engine
from app.models.user import User
from app.models.calculation import Calculation

# Make sure the test DB has tables (in case not created elsewhere)
Base.metadata.create_all(bind=engine)

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
    # should be HTML
    assert "text/html" in resp.headers.get("content-type", "")


def test_register_page_returns_html():
    resp = client.get("/register", follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    # page should contain the form heading
    assert "Create Account" in resp.text


def test_login_page_returns_html():
    resp = client.get("/login", follow_redirects=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    assert "Log in" in resp.text


def test_full_auth_and_calculation_flow():
    # 1) Register user (JSON endpoint)
    username = "flowuser"
    email = "flowuser@example.com"
    register_user(username=username, email=email)

    # 2) Login
    token = login_user(username=username)

    # 3) Create a calculation
    calc_payload = {
        "operation": "add",
        "operand1": 10,
        "operand2": 5,
    }
    resp = client.post(
        "/calculations/",
        json=calc_payload,
        headers=auth_headers(token),
    )
    assert resp.status_code in (200, 201)
    calc = resp.json()
    calc_id = calc["id"]
    assert calc["result"] == 15

    # 4) List calculations
    resp = client.get("/calculations/", headers=auth_headers(token))
    assert resp.status_code == 200
    items = resp.json()
    assert any(c["id"] == calc_id for c in items)

    # 5) Get single calculation
    resp = client.get(f"/calculations/{calc_id}", headers=auth_headers(token))
    assert resp.status_code == 200
    calc_detail = resp.json()
    assert calc_detail["id"] == calc_id

    # 6) Update calculation
    update_payload = {
        "operation": "multiply",
        "operand1": 3,
        "operand2": 7,
    }
    resp = client.put(
        f"/calculations/{calc_id}",
        json=update_payload,
        headers=auth_headers(token),
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["result"] == 21
    assert updated["operation"] == "multiply"

    # 7) Delete calculation
    resp = client.delete(f"/calculations/{calc_id}", headers=auth_headers(token))
    assert resp.status_code in (200, 204)

    # 8) Confirm it is gone
    resp = client.get(f"/calculations/{calc_id}", headers=auth_headers(token))
    assert resp.status_code == 404


def test_login_invalid_credentials():
    # Make sure a user exists
    register_user(username="badloginuser", email="badlogin@example.com")

    resp = client.post(
        "/auth/login",
        json={"username": "badloginuser", "password": "WrongPassword123"},
    )
    # Should hit the invalid-path in login handler
    assert resp.status_code == 401
    data = resp.json()
    assert data["detail"] == "Invalid username or password"
