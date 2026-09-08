"""Writable integration fixtures opt in to the local rehearsal runtime.

Production defaults are tested separately by test_public_readonly, which removes
or overrides this environment variable before importing the public app.
"""

import pytest


@pytest.fixture(autouse=True)
def local_rehearsal_runtime(monkeypatch):
    monkeypatch.setenv("SAB_PUBLIC_MODE", "local")
