"""Configuración general de pruebas para pytest."""

import pytest


@pytest.fixture(autouse=True)
def _forzar_stub_en_tests(monkeypatch):
    """Garantiza que las pruebas unitarias y de API usen el stub sin llamar a APIs externas."""
    monkeypatch.setenv("PHISHGUARD_LLM", "stub")
