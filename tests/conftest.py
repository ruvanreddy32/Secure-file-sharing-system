"""Shared fixtures for the secure-cloud (paper) tests.  Keys are generated once per session."""

import pytest

from securecloud import rlwe, signature, workflow


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
def other_rlwe():
    return rlwe.generate_keypair("P2")


@pytest.fixture
def protect(owner_rsa, recipient_rlwe):
    """protect(plaintext, name='data.txt', **setup_kwargs) -> ProtectedBundle"""
    def _protect(plaintext: bytes, name: str = "data.txt", **kw) -> workflow.ProtectedBundle:
        bundle, _t = workflow.setup_phase(plaintext, name, owner_rsa, recipient_rlwe.public, **kw)
        return bundle
    return _protect
