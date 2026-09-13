"""Orquestador del pipeline.

Es el mapa de la arquitectura de la presentación, en código y en una función:

    ingesta -> extracción de señales -> [reglas | LLM] -> fusión -> veredicto

Deliberadamente no contiene lógica de detección. Todo lo que decide vive en
`extractors/`, `baseline/`, `llm/` y `fusion.py`; aquí solo se conecta, para que
al leerlo se vea el flujo completo sin detalles.
"""

from __future__ import annotations

from app.baseline.rules import evaluar_reglas
from app.extractors import (
    extraer_senales_adjunto,
    extraer_senales_remitente,
    extraer_senales_sociales,
    extraer_senales_url,
)
from app.extractors.urls import fusionar_por_id
from app.llm import ClasificadorLLM, obtener_clasificador
from app.schemas import Analisis, CorreoEntrada, Senal


def extraer_senales(correo: CorreoEntrada) -> list[Senal]:
    """Ejecuta los cuatro extractores y devuelve las señales sin duplicar.

    Los extractores son independientes entre sí a propósito: ninguno necesita el
    resultado de otro, así que se pueden probar y sustituir por separado.
    """
    senales: list[Senal] = []
    senales.extend(extraer_senales_url(correo.cuerpo_texto, correo.cuerpo_html))
    senales.extend(
        extraer_senales_remitente(correo.remitente, correo.reply_to, correo.cabeceras)
    )
    senales.extend(extraer_senales_sociales(correo.asunto, correo.cuerpo_texto))
    senales.extend(extraer_senales_adjunto(correo.adjuntos))
    return fusionar_por_id(senales)


def analizar(correo: CorreoEntrada, clasificador: ClasificadorLLM | None = None) -> Analisis:
    """Analiza un correo de punta a punta.

    El clasificador se puede inyectar para que los tests no dependan de la
    variable de entorno ni de la red.
    """
    from app.fusion import fusionar

    clasificador = clasificador or obtener_clasificador()

    senales = extraer_senales(correo)
    reglas = evaluar_reglas(senales)
    llm = clasificador.clasificar(correo, senales)

    return fusionar(senales, reglas, llm)
