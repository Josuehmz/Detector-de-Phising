"""Pruebas del adaptador real de Gemini.

Ninguna prueba toca la red ni necesita una clave de API.
El cliente se inyecta simulando el SDK de google-genai.
"""

from __future__ import annotations

import pytest

from app.fusion import fusionar
from app.llm.gemini import ClasificadorGemini, _RespuestaModelo
from app.schemas import CorreoEntrada, ResultadoReglas, Senal, Severidad, Veredicto


class _RespuestaFalsa:
    def __init__(self, parsed=None, text=""):
        self.parsed = parsed
        self.text = text


class _ModelsFalso:
    def __init__(self, respuesta=None, error=None):
        self._respuesta = respuesta
        self._error = error
        self.peticiones: list[dict] = []

    def generate_content(self, model: str, contents: str, config: object = None):
        self.peticiones.append({"model": model, "contents": contents, "config": config})
        if self._error:
            raise self._error
        return self._respuesta


class _ClienteFalso:
    def __init__(self, respuesta=None, error=None):
        self.models = _ModelsFalso(respuesta=respuesta, error=error)


def _correo():
    return CorreoEntrada(
        asunto="Urgente: Validar acceso",
        remitente="Seguridad <soporte@ti-empresa.co>",
        cuerpo_texto="Por favor ingrese a su cuenta para verificar sus credenciales.",
        origen="test",
    )


def test_clasificar_mapea_respuesta_correctamente():
    juicio = _RespuestaModelo(
        score=0.88,
        razonamiento="Suplantación de identidad solicitando credenciales corporativas.",
        indicadores=["social_credenciales", "social_autoridad"],
    )
    cliente = _ClienteFalso(respuesta=_RespuestaFalsa(parsed=juicio))
    clasificador = ClasificadorGemini(modelo="gemini-2.5-flash", cliente=cliente)

    resultado = clasificador.clasificar(_correo(), [])

    assert resultado.score == 0.88
    assert resultado.razonamiento == "Suplantación de identidad solicitando credenciales corporativas."
    assert "social_credenciales" in resultado.indicadores
    assert resultado.modelo == "gemini-2.5-flash"
    assert resultado.es_stub is False
    assert resultado.sin_juicio is False


def test_intento_de_manipulacion_agrega_indicador():
    juicio = _RespuestaModelo(
        score=0.95,
        razonamiento="El correo intenta dar instrucciones al modelo.",
        indicadores=["social_urgencia"],
        intento_de_manipulacion=True,
    )
    cliente = _ClienteFalso(respuesta=_RespuestaFalsa(parsed=juicio))
    clasificador = ClasificadorGemini(modelo="gemini-2.5-flash", cliente=cliente)

    resultado = clasificador.clasificar(_correo(), [])

    assert "llm_intento_de_manipulacion" in resultado.indicadores


def test_error_de_api_devuelve_sin_juicio():
    cliente = _ClienteFalso(error=RuntimeError("Google API quota exceeded"))
    clasificador = ClasificadorGemini(modelo="gemini-2.5-flash", cliente=cliente)

    resultado = clasificador.clasificar(_correo(), [])

    assert resultado.sin_juicio is True
    assert "error_de_api:RuntimeError" in (resultado.motivo_sin_juicio or "")
    assert resultado.score == 0.0


def test_fusion_con_gemini_funciona():
    juicio = _RespuestaModelo(
        score=0.90,
        razonamiento="Mensaje fraudulento con pretexto urgente.",
        indicadores=["social_urgencia"],
    )
    cliente = _ClienteFalso(respuesta=_RespuestaFalsa(parsed=juicio))
    clasificador = ClasificadorGemini(modelo="gemini-2.5-flash", cliente=cliente)

    correo = _correo()
    senales = [
        Senal(
            id="social_urgencia",
            categoria="ingenieria_social",
            descripcion="Urgencia detectada",
            severidad=Severidad.MEDIA,
        )
    ]
    reglas = ResultadoReglas(score=0.4, reglas_disparadas=["social_urgencia"])
    llm = clasificador.clasificar(correo, senales)

    analisis = fusionar(senales, reglas, llm)

    assert analisis.veredicto == Veredicto.PHISHING
    assert not any("stub" in adv for adv in analisis.advertencias)
    assert analisis.score > 0.65
