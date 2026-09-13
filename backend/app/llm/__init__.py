"""Selección de la implementación del clasificador por LLM."""

from __future__ import annotations

import logging
import os

from app.llm.port import ClasificadorLLM
from app.llm.stub import ClasificadorStub

_log = logging.getLogger(__name__)


def obtener_clasificador() -> ClasificadorLLM:
    """Devuelve la implementación indicada por `PHISHGUARD_LLM`.

    El valor por defecto es `stub`: el demo tiene que arrancar en la máquina del
    profesor sin clave de API ni conexión. Con `PHISHGUARD_LLM=claude` se usa el
    modelo real, y si su inicialización falla se registra el motivo y se cae al
    stub en vez de tumbar el servicio — pero la respuesta queda marcada con
    `es_stub=True`, así que la degradación nunca pasa inadvertida.
    """
    eleccion = os.getenv("PHISHGUARD_LLM", "stub").strip().lower()

    if eleccion == "claude":
        try:
            from app.llm.claude import ClasificadorClaude

            return ClasificadorClaude()
        except Exception as error:  # noqa: BLE001 - cualquier fallo debe degradar, no romper
            _log.warning(
                "No se pudo inicializar el clasificador Claude (%s). Se usa el stub.", error
            )
            return ClasificadorStub()

    if eleccion != "stub":
        _log.warning("PHISHGUARD_LLM='%s' no reconocido. Se usa el stub.", eleccion)

    return ClasificadorStub()


__all__ = ["ClasificadorLLM", "ClasificadorStub", "obtener_clasificador"]
