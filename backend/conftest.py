import pytest
from rest_framework.test import APIClient

from apps.accounts.models import User
from common.constants import Role


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def make_user(db):
    def _make(username="alice", email="alice@example.com", password="StrongPass1!", role=Role.USER):
        return User.objects.create_user(username=username, email=email, password=password, role=role)
    return _make


@pytest.fixture
def user(make_user):
    return make_user()


@pytest.fixture
def admin_user(make_user):
    return make_user(username="admin1", email="admin1@example.com", role=Role.ADMIN)


@pytest.fixture
def auth_client(api_client, user):
    from rest_framework_simplejwt.tokens import RefreshToken
    token = RefreshToken.for_user(user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return api_client, user


@pytest.fixture
def admin_client(api_client, admin_user):
    from rest_framework_simplejwt.tokens import RefreshToken
    token = RefreshToken.for_user(admin_user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return api_client, admin_user
