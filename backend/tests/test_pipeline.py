"""Pruebas del baseline, la fusión y el pipeline completo.

Todas usan el stub determinista, así que no hay red ni clave de API y el
resultado es reproducible en cualquier máquina.
"""

from __future__ import annotations

import pytest

from app.baseline.rules import PESOS, evaluar_reglas
from app.eml import parsear_eml
from app.fusion import UMBRAL_PHISHING, UMBRAL_SOSPECHOSO, fusionar
from app.llm.stub import ClasificadorStub
from app.pipeline import analizar, extraer_senales
from app.samples import SAMPLES, obtener_sample
from app.schemas import (
    CorreoEntrada,
    ResultadoLLM,
    ResultadoReglas,
    Senal,
    Severidad,
    Veredicto,
)


def senal(id_senal: str, severidad: Severidad = Severidad.ALTA) -> Senal:
    return Senal(id=id_senal, categoria="url", descripcion="prueba", severidad=severidad)


# ------------------------------------------------------------------ Baseline


def test_sin_senales_el_score_es_cero():
    resultado = evaluar_reglas([])
    assert resultado.score == 0.0
    assert resultado.reglas_disparadas == []


def test_el_score_satura_en_uno():
    # Ocho señales de peso alto suman mucho más que 1.0.
    muchas = [senal(id_senal) for id_senal in list(PESOS)[:8]]
    assert evaluar_reglas(muchas).score == 1.0


def test_una_senal_desconocida_no_mueve_el_score():
    resultado = evaluar_reglas([senal("senal_que_no_existe_todavia")])
    assert resultado.score == 0.0
    assert resultado.reglas_disparadas == []


def test_las_reglas_se_reportan_de_mayor_a_menor_peso():
    resultado = evaluar_reglas([senal("url_ruta_credenciales"), senal("auth_dmarc_falla")])
    assert resultado.reglas_disparadas[0] == "auth_dmarc_falla"


# --------------------------------------------------------------------- Stub


def test_el_stub_siempre_se_marca_como_stub():
    resultado = ClasificadorStub().clasificar(CorreoEntrada(), [])
    assert resultado.es_stub is True


def test_el_stub_es_determinista():
    correo = obtener_sample("bec").correo
    senales = extraer_senales(correo)
    primero = ClasificadorStub().clasificar(correo, senales)
    segundo = ClasificadorStub().clasificar(correo, senales)
    assert primero.model_dump() == segundo.model_dump()


def test_el_stub_no_afirma_certeza_absoluta_de_legitimidad():
    resultado = ClasificadorStub().clasificar(CorreoEntrada(), [])
    assert resultado.score > 0.0


# -------------------------------------------------------------------- Fusión


def _llm(score: float) -> ResultadoLLM:
    return ResultadoLLM(score=score, razonamiento="prueba", modelo="test", es_stub=False)


@pytest.mark.parametrize(
    ("score_comun", "veredicto_esperado"),
    [
        (0.0, Veredicto.LEGITIMO),
        (UMBRAL_SOSPECHOSO - 0.01, Veredicto.LEGITIMO),
        (UMBRAL_SOSPECHOSO, Veredicto.SOSPECHOSO),
        (UMBRAL_PHISHING - 0.01, Veredicto.SOSPECHOSO),
        (UMBRAL_PHISHING, Veredicto.PHISHING),
        (1.0, Veredicto.PHISHING),
    ],
)
def test_umbrales_del_veredicto(score_comun, veredicto_esperado):
    """Con ambas fuentes en el mismo valor, el score final es ese valor.

    Así se prueban los umbrales sin depender de los pesos de la combinación: si
    mañana cambian PESO_LLM y PESO_REGLAS, esta prueba sigue midiendo lo que dice
    medir. Se incluyen los valores justo debajo y justo encima de cada frontera.
    """
    analisis = fusionar([], ResultadoReglas(score=score_comun), _llm(score_comun))
    assert analisis.score == pytest.approx(score_comun)
    assert analisis.veredicto is veredicto_esperado


def test_la_confianza_mide_el_acuerdo_entre_las_dos_fuentes():
    reglas = evaluar_reglas([senal("auth_dmarc_falla")])  # score 0.40
    acuerdo = fusionar([], reglas, _llm(0.40))
    desacuerdo = fusionar([], reglas, _llm(1.0))
    assert acuerdo.confianza == 1.0
    assert desacuerdo.confianza < acuerdo.confianza


def test_escalada_cuando_hay_suplantacion_y_autenticacion_fallida():
    senales = [senal("url_texto_enganoso"), senal("auth_spf_falla")]
    # Aunque el LLM se equivoque y diga que es legítimo, el veredicto no cede.
    analisis = fusionar(senales, evaluar_reglas(senales), _llm(0.0))
    assert analisis.score >= 0.85
    assert analisis.veredicto is Veredicto.PHISHING
    assert any("escalada" in a for a in analisis.advertencias)


def test_el_uso_del_stub_queda_advertido_en_la_respuesta():
    llm_stub = ResultadoLLM(score=0.5, razonamiento="x", modelo="stub", es_stub=True)
    analisis = fusionar([], evaluar_reglas([]), llm_stub)
    assert any("stub" in a.lower() for a in analisis.advertencias)


# ------------------------------------------------------------------ Pipeline


def test_correo_completamente_vacio_no_rompe_el_pipeline():
    analisis = analizar(CorreoEntrada(), ClasificadorStub())
    assert analisis.veredicto is Veredicto.LEGITIMO
    assert 0.0 <= analisis.score <= 1.0


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s.id)
def test_cada_escenario_se_clasifica_del_lado_correcto(sample):
    """El prototipo acierta en los seis casos escritos a mano.

    Esto NO es una métrica del proyecto: son ejemplos elegidos por nosotros. Sirve
    como prueba de regresión — si un cambio en los pesos rompe un escenario del
    informe, se ve aquí — no como evidencia de desempeño.
    """
    analisis = analizar(sample.correo, ClasificadorStub())

    if sample.etiqueta == "phishing":
        assert analisis.veredicto is not Veredicto.LEGITIMO, analisis.explicacion
    else:
        assert analisis.veredicto is not Veredicto.PHISHING, analisis.explicacion


def test_el_spear_phishing_solo_llega_a_sospechoso():
    """Deja constancia del límite que el proyecto quiere medir.

    El escenario 02 está escrito como lo escribiría un atacante con IA: sin
    errores, sin urgencia explícita, con SPF/DKIM/DMARC en `pass` sobre un dominio
    propio. Las señales léxicas y estructurales apenas lo rozan, así que el
    veredicto queda en la banda de revisión humana en vez de en «phishing».

    Es el resultado esperado hoy y NO se debe «arreglar» ajustando pesos hasta que
    pase: eso sería calibrar contra un ejemplo escrito por nosotros. Lo que debe
    cerrar esa brecha es el modelo real en el sprint 4, y esta prueba es el
    marcador contra el que se medirá si lo consiguió.
    """
    analisis = analizar(obtener_sample("spear").correo, ClasificadorStub())
    assert analisis.veredicto is Veredicto.SOSPECHOSO, analisis.explicacion


def test_el_correo_adversarial_no_logra_invertir_el_veredicto():
    """El texto inyectado pide que se clasifique como seguro; no debe conseguirlo."""
    analisis = analizar(obtener_sample("adversarial").correo, ClasificadorStub())
    assert analisis.veredicto is Veredicto.PHISHING


def test_la_explicacion_cita_senales_concretas():
    analisis = analizar(obtener_sample("generico").correo, ClasificadorStub())
    assert "Señales que más pesaron" in analisis.explicacion
    assert analisis.senales


# ----------------------------------------------------------------------- EML


EML_MINIMO = b"""\
From: Soporte <no-reply@ejemplo.top>
To: victima@empresa.com
Subject: Verifique su cuenta
Authentication-Results: mx; spf=fail
Content-Type: text/plain; charset="utf-8"

Su cuenta sera suspendida en 24 horas. Verifique su cuenta en
http://ejemplo.top/login
"""


def test_parseo_de_eml():
    correo = parsear_eml(EML_MINIMO)
    assert correo.asunto == "Verifique su cuenta"
    assert "no-reply@ejemplo.top" in correo.remitente
    assert "suspendida" in correo.cuerpo_texto
    assert correo.cabeceras["authentication-results"].startswith("mx;")
    assert correo.origen == "eml"


def test_un_eml_se_puede_analizar_igual_que_un_correo_estructurado():
    analisis = analizar(parsear_eml(EML_MINIMO), ClasificadorStub())
    assert analisis.veredicto is not Veredicto.LEGITIMO
