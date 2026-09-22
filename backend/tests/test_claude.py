"""Pruebas del adaptador real de Claude.

**Ninguna toca la red ni necesita una clave de API.** El cliente se inyecta, así
que se ejercita el archivo entero —construcción del mensaje, manejo del rechazo,
mapeo de la respuesta— contra un doble que devuelve lo que cada prueba necesita.

Lo que estas pruebas NO hacen: comprobar que el modelo real clasifique bien. Eso
no es una prueba unitaria, es la evaluación sobre Nazario y SpamAssassin, y
todavía no existe.
"""

from __future__ import annotations

import pytest

from app.fusion import fusionar
from app.llm.claude import MAX_CARACTERES_CUERPO, ClasificadorClaude, _RespuestaModelo
from app.schemas import CorreoEntrada, ResultadoReglas, Senal, Severidad, Veredicto


# --------------------------------------------------------------------- Dobles


class _RespuestaFalsa:
    """Imita lo que el SDK devuelve: `stop_reason`, `stop_details`, `parsed_output`."""

    def __init__(self, *, stop_reason="end_turn", parsed_output=None, model="claude-opus-5",
                 stop_details=None):
        self.stop_reason = stop_reason
        self.parsed_output = parsed_output
        self.model = model
        self.stop_details = stop_details


class _DetallesRechazo:
    def __init__(self, category="cyber", explanation="No puedo analizar este contenido."):
        self.category = category
        self.explanation = explanation


class _ClienteFalso:
    """Registra la petición recibida y devuelve una respuesta fija."""

    def __init__(self, respuesta=None, error=None):
        self._respuesta = respuesta
        self._error = error
        self.peticiones: list[dict] = []
        self.messages = self._Messages(self)

    class _Messages:
        def __init__(self, padre):
            self._padre = padre

        def parse(self, **peticion):
            self._padre.peticiones.append(peticion)
            if self._padre._error:
                raise self._padre._error
            return self._padre._respuesta


def _juicio(score=0.8, razonamiento="Pretexto financiero urgente.", indicadores=None,
            manipulacion=False):
    return _RespuestaModelo(
        score=score,
        razonamiento=razonamiento,
        indicadores=indicadores or ["social_urgencia"],
        intento_de_manipulacion=manipulacion,
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


# ------------------------------------------------------ Construcción del mensaje


def test_el_correo_viaja_dentro_de_delimitadores():
    """La defensa contra inyección de prompt empieza aquí: si el correo no queda
    delimitado, el modelo no puede distinguir dato de instrucción."""
    cliente = _ClienteFalso(_RespuestaFalsa(parsed_output=_juicio()))
    ClasificadorClaude(cliente=cliente).clasificar(_correo(), _SENALES)

    contenido = cliente.peticiones[0]["messages"][0]["content"]
    assert "<correo>" in contenido and "</correo>" in contenido
    assert contenido.index("<correo>") < contenido.index("Confirme su cuenta")
    assert contenido.index("Confirme su cuenta") < contenido.index("</correo>")


def test_las_senales_ya_extraidas_se_le_entregan_al_modelo():
    """El modelo no debe volver a buscar lo que el código ya encontró."""
    cliente = _ClienteFalso(_RespuestaFalsa(parsed_output=_juicio()))
    ClasificadorClaude(cliente=cliente).clasificar(_correo(), _SENALES)

    contenido = cliente.peticiones[0]["messages"][0]["content"]
    assert "url_acortador" in contenido
    assert "El enlace usa un acortador." in contenido


def test_el_cuerpo_se_recorta():
    """El relleno es una 'Z' porque no aparece en el resto de la plantilla: así se
    cuenta el cuerpo y no el texto que lo rodea."""
    cliente = _ClienteFalso(_RespuestaFalsa(parsed_output=_juicio()))
    largo = "Z" * (MAX_CARACTERES_CUERPO + 5000)
    ClasificadorClaude(cliente=cliente).clasificar(_correo(cuerpo_texto=largo), [])

    contenido = cliente.peticiones[0]["messages"][0]["content"]
    assert contenido.count("Z") == MAX_CARACTERES_CUERPO


def test_la_peticion_usa_razonamiento_adaptativo_y_un_techo_alto():
    """Fija los dos parámetros que cambiaron respecto a la primera versión: el
    presupuesto fijo de pensamiento ya no existe, y 2000 tokens truncaban."""
    cliente = _ClienteFalso(_RespuestaFalsa(parsed_output=_juicio()))
    ClasificadorClaude(cliente=cliente).clasificar(_correo(), [])

    peticion = cliente.peticiones[0]
    assert peticion["thinking"] == {"type": "adaptive"}
    assert "budget_tokens" not in str(peticion["thinking"])
    assert peticion["max_tokens"] >= 16000
    assert peticion["output_format"] is _RespuestaModelo


def test_el_esfuerzo_solo_se_envia_si_se_configura(monkeypatch):
    cliente = _ClienteFalso(_RespuestaFalsa(parsed_output=_juicio()))
    ClasificadorClaude(cliente=cliente).clasificar(_correo(), [])
    assert "output_config" not in cliente.peticiones[0]

    monkeypatch.setenv("PHISHGUARD_EFFORT", "medium")
    cliente2 = _ClienteFalso(_RespuestaFalsa(parsed_output=_juicio()))
    ClasificadorClaude(cliente=cliente2).clasificar(_correo(), [])
    assert cliente2.peticiones[0]["output_config"] == {"effort": "medium"}


# ----------------------------------------------------------- Respuesta normal


def test_una_respuesta_normal_se_mapea_y_no_es_stub():
    cliente = _ClienteFalso(_RespuestaFalsa(parsed_output=_juicio(score=0.77)))
    resultado = ClasificadorClaude(cliente=cliente).clasificar(_correo(), _SENALES)

    assert resultado.score == 0.77
    assert resultado.es_stub is False
    assert resultado.sin_juicio is False
    assert resultado.motivo_sin_juicio is None


def test_el_intento_de_manipulacion_se_reporta_como_indicador():
    """No se ignora: un correo que intenta manipular al clasificador es MÁS
    sospechoso, no menos."""
    cliente = _ClienteFalso(_RespuestaFalsa(parsed_output=_juicio(manipulacion=True)))
    resultado = ClasificadorClaude(cliente=cliente).clasificar(_correo(), [])

    assert "llm_intento_de_manipulacion" in resultado.indicadores


def test_se_registra_el_modelo_que_respondio_no_el_que_se_pidio():
    """Si algún día un respaldo contesta, la evaluación tiene que poder notarlo."""
    cliente = _ClienteFalso(_RespuestaFalsa(parsed_output=_juicio(), model="otro-modelo"))
    resultado = ClasificadorClaude(modelo="claude-opus-5", cliente=cliente).clasificar(
        _correo(), []
    )

    assert resultado.modelo == "otro-modelo"


# ------------------------------------------------------------- Sin juicio


@pytest.mark.parametrize(
    "respuesta, motivo_esperado",
    [
        (
            _RespuestaFalsa(stop_reason="refusal", stop_details=_DetallesRechazo()),
            "rechazo_del_modelo:cyber",
        ),
        (_RespuestaFalsa(stop_reason="max_tokens", parsed_output=None), "respuesta_truncada"),
        (
            _RespuestaFalsa(stop_reason="end_turn", parsed_output=None),
            "sin_salida_estructurada:end_turn",
        ),
    ],
)
def test_las_tres_formas_de_quedarse_sin_juicio_se_distinguen(respuesta, motivo_esperado):
    """Rechazo, truncamiento y fallo son cosas distintas y la evaluación tiene que
    poder agruparlas por separado."""
    cliente = _ClienteFalso(respuesta)
    resultado = ClasificadorClaude(cliente=cliente).clasificar(_correo(), [])

    assert resultado.sin_juicio is True
    assert resultado.motivo_sin_juicio == motivo_esperado


def test_un_error_de_api_no_tumba_la_peticion_y_se_distingue_del_rechazo():
    cliente = _ClienteFalso(error=RuntimeError("se cayó la red"))
    resultado = ClasificadorClaude(cliente=cliente).clasificar(_correo(), [])

    assert resultado.sin_juicio is True
    assert resultado.motivo_sin_juicio == "error_de_api:RuntimeError"


def test_sin_juicio_nunca_se_presenta_como_un_score_bajo():
    """El contrato que protege al detector: un correo que el modelo no juzgó no
    puede parecerse a un correo que el modelo consideró limpio."""
    cliente = _ClienteFalso(
        _RespuestaFalsa(stop_reason="refusal", stop_details=_DetallesRechazo())
    )
    resultado = ClasificadorClaude(cliente=cliente).clasificar(_correo(), [])

    assert resultado.sin_juicio is True
    # El score es 0.0 por obligación del esquema, pero quien lo consuma debe
    # mirar `sin_juicio` antes que el número.
    assert resultado.score == 0.0


# ------------------------------------------- Cómo lo trata la fusión


def _reglas(score):
    return ResultadoReglas(score=score, reglas_disparadas=["url_acortador"])


def test_la_fusion_ignora_el_score_del_modelo_cuando_no_hubo_juicio():
    """Si se sumara 0.6 × 0.0, un correo que las reglas puntúan 0.9 caería a 0.36
    y pasaría de 'phishing' a 'sospechoso' por algo que el modelo nunca dijo."""
    cliente = _ClienteFalso(
        _RespuestaFalsa(stop_reason="refusal", stop_details=_DetallesRechazo())
    )
    llm = ClasificadorClaude(cliente=cliente).clasificar(_correo(), [])

    analisis = fusionar(_SENALES, _reglas(0.9), llm)

    assert analisis.score == pytest.approx(0.9)
    assert analisis.veredicto is Veredicto.PHISHING


def test_la_fusion_avisa_de_que_el_veredicto_no_es_del_sistema_con_ia():
    cliente = _ClienteFalso(
        _RespuestaFalsa(stop_reason="refusal", stop_details=_DetallesRechazo())
    )
    llm = ClasificadorClaude(cliente=cliente).clasificar(_correo(), [])

    analisis = fusionar(_SENALES, _reglas(0.5), llm)

    assert any("ÚNICAMENTE del baseline" in aviso for aviso in analisis.advertencias)
    assert any("rechazo_del_modelo:cyber" in aviso for aviso in analisis.advertencias)


def test_sin_juicio_la_confianza_no_se_inventa():
    """La confianza mide acuerdo entre dos fuentes. Con una sola no hay acuerdo
    que medir, y un 0.96 calculado contra un score inexistente sería mentira."""
    cliente = _ClienteFalso(
        _RespuestaFalsa(stop_reason="refusal", stop_details=_DetallesRechazo())
    )
    llm = ClasificadorClaude(cliente=cliente).clasificar(_correo(), [])

    analisis = fusionar(_SENALES, _reglas(0.04), llm)

    assert analisis.confianza == 0.0
