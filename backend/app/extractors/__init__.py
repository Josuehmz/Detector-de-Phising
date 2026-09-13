"""Extracción de señales observables del correo.

Cada módulo mira una dimensión distinta y devuelve `list[Senal]`. Ninguno emite
un veredicto: eso es trabajo de `baseline.rules` y del clasificador por LLM.
"""

from app.extractors.adjuntos import extraer_senales_adjunto
from app.extractors.remitente import extraer_senales_remitente
from app.extractors.social import extraer_senales_sociales
from app.extractors.urls import extraer_senales_url, extraer_urls

__all__ = [
    "extraer_senales_adjunto",
    "extraer_senales_remitente",
    "extraer_senales_sociales",
    "extraer_senales_url",
    "extraer_urls",
]
