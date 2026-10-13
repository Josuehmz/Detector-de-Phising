"""Selección de la implementación del clasificador por LLM."""

from __future__ import annotations

import logging
import os

from app.llm.port import ClasificadorLLM
from app.llm.stub import ClasificadorStub

_log = logging.getLogger(__name__)


def obtener_clasificador() -> ClasificadorLLM:
    """Devuelve la implementación indicada por `PHISHGUARD_LLM` o variables de entorno.

    El valor por defecto es `stub`: el demo arranca en cualquier máquina sin clave
    de API ni conexión. Con `PHISHGUARD_LLM=gemini` o `PHISHGUARD_LLM=claude` se usa
    el modelo real correspondiente. Si no se especifica pero se detecta `GEMINI_API_KEY`
    en el entorno, se activa Gemini automáticamente.
    """
    eleccion = os.getenv("PHISHGUARD_LLM", "").strip().lower()

    if not eleccion and os.getenv("GEMINI_API_KEY"):
        eleccion = "gemini"
    elif not eleccion and os.getenv("ANTHROPIC_API_KEY"):
        eleccion = "claude"
    elif not eleccion:
        eleccion = "stub"

    if eleccion == "gemini":
        try:
            from app.llm.gemini import ClasificadorGemini

            return ClasificadorGemini()
        except Exception as error:  # noqa: BLE001 - cualquier fallo debe degradar, no romper
            _log.warning(
                "No se pudo inicializar el clasificador Gemini (%s). Se usa el stub.", error
            )
            return ClasificadorStub()

    if eleccion == "claude":
        try:
            from app.llm.claude import ClasificadorClaude

            return ClasificadorClaude()
        except Exception as error:  # noqa: BLE001 - cualquier fallo debe degradar, no romper
            _log.warning(
                "No se pudo inicializar el clasificador Claude (%s). Se usa el stub.", error
            )
            return ClasificadorStub()

    if eleccion == "ollama":
        try:
            from app.llm.ollama import ClasificadorOllama

            return ClasificadorOllama()
        except Exception as error:  # noqa: BLE001
            _log.warning(
                "No se pudo inicializar el clasificador Ollama (%s). Se usa el stub.", error
            )
            return ClasificadorStub()

    if eleccion != "stub":
        _log.warning("PHISHGUARD_LLM='%s' no reconocido. Se usa el stub.", eleccion)

    return ClasificadorStub()


__all__ = ["ClasificadorLLM", "ClasificadorStub", "obtener_clasificador"]

