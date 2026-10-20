import pytest
from fastapi.testclient import TestClient

from app.auth import create_access_token, hash_password
from app.config import Settings
from app.main import create_app
from app.models import User


def fake_resolver(host: str) -> list[str]:
    table = {
        "example.com": ["93.184.215.14"],
        "rebind.test": ["10.0.0.5"],
        "mixed.test": ["93.184.215.14", "10.0.0.5"],
        "lab.local": ["127.0.0.1"],
    }
    return table.get(host, ["93.184.215.14"])


@pytest.fixture
def make_client(tmp_path):
    def _make(**overrides) -> TestClient:
        settings = Settings(database_url=f"sqlite:///{tmp_path}/{len(list(tmp_path.iterdir()))}.db", **overrides)
        app = create_app(settings, resolver=fake_resolver)
        app.state.db.create_all()
        with app.state.db.SessionLocal() as db:
            user = User(email="admin@example.com", password_hash=hash_password("test-password-123456"), role="admin", is_active=True)
            db.add(user)
            db.commit()
            db.refresh(user)
            token, _ = create_access_token(user, settings)
        client = TestClient(app, raise_server_exceptions=False)
        client.headers.update({"Authorization": f"Bearer {token}"})
        client.test_user_id = user.id
        return client

    return _make


@pytest.fixture
def client(make_client):
    return make_client()
