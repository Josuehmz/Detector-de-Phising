"""Pruebas del adaptador de Ollama.

Ninguna levanta Ollama ni toca la red: el cliente HTTP se inyecta. Se ejercita
la construcción de la petición y los cuatro finales posibles.

Lo que NO prueban: que un modelo de 3B clasifique bien. Eso es la evaluación, y
no existe todavía.
"""

from __future__ import annotations

import json

import pytest

from app.llm.ollama import MAX_TOKENS_RESPUESTA, ClasificadorOllama
from app.llm.prompt import MAX_CARACTERES_CUERPO
from app.schemas import CorreoEntrada, Senal, Severidad


class _RespuestaHTTP:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text or json.dumps(self._payload)

    def json(self):
        return self._payload


class _ClienteFalso:
    """Registra la petición y devuelve una respuesta fija, o lanza."""

    def __init__(self, respuesta=None, error=None):
        self._respuesta = respuesta
        self._error = error
        self.peticiones: list[dict] = []
        self.urls: list[str] = []

    def post(self, url, json=None):
        self.urls.append(url)
        self.peticiones.append(json)
        if self._error:
            raise self._error
        return self._respuesta


def _respuesta_ok(score_0_a_10=8, razonamiento="Pretexto de urgencia bancaria.",
                  indicadores=None, manipulacion=False, duracion_ns=42_000_000_000):
    contenido = json.dumps(
        {
            "score_0_a_10": score_0_a_10,
            "razonamiento": razonamiento,
            "indicadores": indicadores or ["social_urgencia"],
            "intento_de_manipulacion": manipulacion,
        }
    )
    return _RespuestaHTTP(
        payload={
            "message": {"role": "assistant", "content": contenido},
            "done": True,
            "total_duration": duracion_ns,
            "eval_count": 120,
        }
    )


def _correo(**kwargs):
    base = dict(
        asunto="Actualice sus datos",
        remitente="Banco <no-reply@banco-falso.info>",
        cuerpo_texto="Confirme su cuenta en http://bit.ly/x antes de 24 horas.",
        origen="test",
    )
    base.update(kwargs)
    return CorreoEntrada(**base)


_SENALES = [
    Senal(
        id="url_acortador",
        categoria="url",
        descripcion="El enlace usa un acortador.",
        severidad=Severidad.ALTA,
        evidencia=["bit.ly"],
    )
]


# ------------------------------------------------------------- La petición


def test_va_al_endpoint_de_chat_de_ollama():
    cliente = _ClienteFalso(_respuesta_ok())
    ClasificadorOllama(cliente=cliente).clasificar(_correo(), _SENALES)

    assert cliente.urls[0].endswith("/api/chat")


def test_el_esquema_viaja_en_format_para_restringir_la_generacion():
    """Es la misma defensa que con Claude: el modelo no puede responder texto
    libre aunque el correo se lo pida."""
    cliente = _ClienteFalso(_respuesta_ok())
    ClasificadorOllama(cliente=cliente).clasificar(_correo(), _SENALES)

    formato = cliente.peticiones[0]["format"]
    assert formato["type"] == "object"
    assert set(formato["properties"]) == {
        "score_0_a_10",
        "razonamiento",
        "indicadores",
        "intento_de_manipulacion",
    }


def test_temperatura_cero_y_semilla_fija_para_que_el_experimento_se_repita():
    """La ventaja metodológica de la vía local: con la API de Claude no se puede
    fijar `temperature`, así que dos pasadas pueden dar métricas distintas."""
    cliente = _ClienteFalso(_respuesta_ok())
    ClasificadorOllama(cliente=cliente).clasificar(_correo(), [])

    opciones = cliente.peticiones[0]["options"]
    assert opciones["temperature"] == 0
    assert opciones["seed"] == 42
    assert opciones["num_predict"] == MAX_TOKENS_RESPUESTA


def test_usa_el_mismo_prompt_que_el_adaptador_de_claude():
    """Si los prompts se separan, la comparación entre modelos deja de medir
    modelos y pasa a medir prompts."""
    from app.llm.prompt import SYSTEM_PROMPT, construir_mensaje

    cliente = _ClienteFalso(_respuesta_ok())
    correo = _correo()
    ClasificadorOllama(cliente=cliente).clasificar(correo, _SENALES)

    mensajes = cliente.peticiones[0]["messages"]
    assert mensajes[0] == {"role": "system", "content": SYSTEM_PROMPT}
    assert mensajes[1]["content"] == construir_mensaje(correo, _SENALES)


def test_el_cuerpo_se_recorta_igual_que_en_la_otra_via():
    cliente = _ClienteFalso(_respuesta_ok())
    largo = "Z" * (MAX_CARACTERES_CUERPO + 5000)
    ClasificadorOllama(cliente=cliente).clasificar(_correo(cuerpo_texto=largo), [])

    assert cliente.peticiones[0]["messages"][1]["content"].count("Z") == MAX_CARACTERES_CUERPO


def test_el_modelo_se_puede_configurar_por_entorno(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_OLLAMA_MODELO", "qwen2.5:7b")
    cliente = _ClienteFalso(_respuesta_ok())
    clasificador = ClasificadorOllama(cliente=cliente)
    resultado = clasificador.clasificar(_correo(), [])

    assert cliente.peticiones[0]["model"] == "qwen2.5:7b"
    assert resultado.modelo == "qwen2.5:7b"


# ------------------------------------------------------------ La respuesta


def test_una_respuesta_valida_se_mapea_y_no_es_stub():
    cliente = _ClienteFalso(_respuesta_ok(score_0_a_10=7))
    resultado = ClasificadorOllama(cliente=cliente).clasificar(_correo(), _SENALES)

    assert resultado.score == 0.7
    assert resultado.es_stub is False
    assert resultado.sin_juicio is False


def test_el_intento_de_manipulacion_se_reporta_igual_que_con_claude():
    cliente = _ClienteFalso(_respuesta_ok(manipulacion=True))
    resultado = ClasificadorOllama(cliente=cliente).clasificar(_correo(), [])

    assert "llm_intento_de_manipulacion" in resultado.indicadores


# -------------------------------------------------------------- Sin juicio


def test_ollama_apagado_se_reporta_como_error_de_api_y_no_tumba_la_peticion():
    cliente = _ClienteFalso(error=ConnectionError("conexión rechazada"))
    resultado = ClasificadorOllama(cliente=cliente).clasificar(_correo(), [])

    assert resultado.sin_juicio is True
    assert resultado.motivo_sin_juicio == "error_de_api:ConnectionError"
    assert "ollama serve" in resultado.razonamiento


def test_modelo_no_descargado_lo_dice_con_el_comando_para_arreglarlo():
    """El fallo más frecuente al empezar. Un 404 seco no ayuda a nadie."""
    cliente = _ClienteFalso(_RespuestaHTTP(status_code=404, text="model not found"))
    resultado = ClasificadorOllama(modelo="llama3.2:3b", cliente=cliente).clasificar(
        _correo(), []
    )

    assert resultado.sin_juicio is True
    assert resultado.motivo_sin_juicio == "error_de_api:HTTP404"
    assert "ollama pull llama3.2:3b" in resultado.razonamiento


def test_un_json_truncado_es_falta_de_juicio_y_no_un_veredicto_de_limpio():
    """Un modelo pequeño puede quedarse sin num_predict a mitad del JSON. Eso no
    puede acabar valiendo score 0, que se leería como 'legítimo'."""
    cliente = _ClienteFalso(
        _RespuestaHTTP(payload={"message": {"content": '{"score_0_a_10": 9, "razona'}})
    )
    resultado = ClasificadorOllama(cliente=cliente).clasificar(_correo(), [])

    assert resultado.sin_juicio is True
    assert resultado.motivo_sin_juicio == "sin_salida_estructurada:esquema_invalido"


def test_una_respuesta_vacia_tampoco_se_confunde_con_un_juicio():
    cliente = _ClienteFalso(_RespuestaHTTP(payload={"message": {"content": ""}}))
    resultado = ClasificadorOllama(cliente=cliente).clasificar(_correo(), [])

    assert resultado.sin_juicio is True


@pytest.mark.parametrize("score_fuera_de_rango", ['{"score_0_a_10": 17, "razonamiento": "x", '
                                                 '"indicadores": [], '
                                                 '"intento_de_manipulacion": false}'])
def test_un_score_fuera_de_rango_se_rechaza_en_vez_de_propagarse(score_fuera_de_rango):
    """El esquema de Ollama restringe el tipo, no el rango. La validación de
    Pydantic es la que impide que un 1.7 llegue a la fusión."""
    cliente = _ClienteFalso(_RespuestaHTTP(payload={"message": {"content": score_fuera_de_rango}}))
    resultado = ClasificadorOllama(cliente=cliente).clasificar(_correo(), [])

    assert resultado.sin_juicio is True


def test_la_escala_de_0_a_10_se_convierte_a_0_a_1_en_el_codigo():
    """Regresión del incidente del 2026-09-29.

    La primera versión pedía un flotante de 0 a 1. El esquema declaraba
    `minimum`/`maximum`, pero la gramática de Ollama restringe estructura y
    tipos, NO rangos numéricos: llama3.2:3b devolvió `9` para un phishing
    evidente, leyendo "score" como la nota habitual sobre 10. Formalmente era un
    número válido y Pydantic lo rechazó, así que los dos correos de la prueba de
    humo acabaron sin juicio.

    Ahora la escala vive en el nombre del campo y la división la hace el código.
    """
    cliente = _ClienteFalso(_respuesta_ok(score_0_a_10=9))
    resultado = ClasificadorOllama(cliente=cliente).clasificar(_correo(), [])

    assert resultado.sin_juicio is False
    assert resultado.score == 0.9

    # Y el esquema que ve el modelo nombra la escala, que es lo único que una
    # gramática no puede malinterpretar.
    assert "score_0_a_10" in cliente.peticiones[0]["format"]["properties"]
