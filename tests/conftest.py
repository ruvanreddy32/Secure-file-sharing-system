"""Shared fixtures for the secure-cloud (paper) tests.  Keys are generated once per session."""

import pytest

from securecloud import rlwe, signature, workflow

_CLOUD_VARS = ("SUPABASE_URL", "SUPABASE_SECRET_KEY", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_KEY",
               "SUPABASE_BUCKET", "SUPABASE_TEST_BUCKET", "DROPBOX_ACCESS_TOKEN",
               "DROPBOX_REFRESH_TOKEN", "DROPBOX_APP_KEY", "DROPBOX_APP_SECRET", "RINGCRYPTER_BACKEND")


@pytest.fixture(autouse=True)
def _hermetic_environment(request, monkeypatch, tmp_path):
    """Unit tests never see real cloud credentials (from the shell or a .env file).
    Tests marked supabase_live / dropbox_live are exempt."""
    monkeypatch.setenv("RINGCRYPTER_TRUST_STORE", str(tmp_path / "trust" / ".trusted_versions.json"))
    if request.node.get_closest_marker("supabase_live") or request.node.get_closest_marker("dropbox_live"):
        return
    monkeypatch.setenv("RINGCRYPTER_NO_DOTENV", "1")
    for var in _CLOUD_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(scope="session")
def owner_rsa():
    return signature.generate_keypair()


@pytest.fixture(scope="session")
def attacker_rsa():
    return signature.generate_keypair()


@pytest.fixture(scope="session")
def recipient_rlwe():
    return rlwe.generate_keypair("P2")


@pytest.fixture(scope="session")
def owner_rlwe():
    return rlwe.generate_keypair("P2")


@pytest.fixture(scope="session")
def other_rlwe():
    return rlwe.generate_keypair("P2")


@pytest.fixture
def protect(owner_rsa, recipient_rlwe):
    """protect(plaintext, name='data.txt', **setup_kwargs) -> ProtectedBundle"""
    def _protect(plaintext: bytes, name: str = "data.txt", **kw) -> workflow.ProtectedBundle:
        bundle, _t = workflow.setup_phase(plaintext, name, owner_rsa, recipient_rlwe.public, **kw)
        return bundle
    return _protect
