import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client(tmp_path) -> TestClient:
    return TestClient(create_app(tmp_path / "test.db"))


def register(client: TestClient, username: str = "anna", email: str = "anna@example.com"):
    return client.post(
        "/api/register",
        json={"username": username, "email": email, "password": "drosaParole1"},
    )


def test_login_page_is_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Pieslēgties" in response.text
    assert "3 līmeņu arhitektūra" in response.text


def test_register_login_me_logout(client: TestClient) -> None:
    assert register(client).status_code == 201

    response = client.post("/api/login", json={"username": "anna", "password": "drosaParole1"})
    assert response.status_code == 200
    headers = {"Authorization": f"Bearer {response.json()['token']}"}

    me = client.get("/api/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["username"] == "anna"

    assert client.post("/api/logout", headers=headers).status_code == 204
    assert client.get("/api/me", headers=headers).status_code == 401


def test_duplicate_username_is_rejected(client: TestClient) -> None:
    register(client)
    assert register(client, email="cits@example.com").status_code == 409


def test_wrong_password_is_rejected(client: TestClient) -> None:
    register(client)
    response = client.post("/api/login", json={"username": "anna", "password": "nepareiza"})
    assert response.status_code == 401


@pytest.mark.parametrize(
    "payload",
    [
        {"username": "a", "email": "a@example.com", "password": "drosaParole1"},
        {"username": "anna", "email": "nav-epasts", "password": "drosaParole1"},
        {"username": "anna", "email": "anna@example.com", "password": "isa"},
    ],
)
def test_invalid_registration_is_rejected(client: TestClient, payload: dict) -> None:
    assert client.post("/api/register", json=payload).status_code == 400


def test_password_is_not_stored_in_plain_text(client: TestClient, tmp_path) -> None:
    register(client)
    with sqlite3.connect(tmp_path / "test.db") as conn:
        stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored != "drosaParole1"
