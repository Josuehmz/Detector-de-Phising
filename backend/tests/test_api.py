"""Pruebas de la API HTTP, que es el contrato con la extensión.

Si algo de aquí cambia, la extensión deja de funcionar; por eso se prueba la
forma de la respuesta y no solo el código de estado.
"""

from __future__ import annotations

import io

from fastapi.testclient import TestClient

from app.main import app

cliente = TestClient(app)


def test_health_reporta_que_el_clasificador_es_un_stub():
    respuesta = cliente.get("/api/v1/health")
    assert respuesta.status_code == 200
    cuerpo = respuesta.json()
    assert cuerpo["estado"] == "ok"
    assert cuerpo["llm_es_stub"] is True


def test_analyze_devuelve_el_contrato_completo():
    respuesta = cliente.post(
        "/api/v1/analyze",
        json={
            "asunto": "URGENTE: su cuenta sera suspendida en 24 horas",
            "remitente": "Soporte PayPal <x@paypal-falso.top>",
            "cuerpo_texto": "Verifique su cuenta en http://paypal.com.falso.top/login",
            "cabeceras": {"Authentication-Results": "mx; spf=fail; dmarc=fail"},
            "origen": "extension",
        },
    )
    assert respuesta.status_code == 200
    cuerpo = respuesta.json()

    assert cuerpo["veredicto"] == "phishing"
    assert 0.0 <= cuerpo["score"] <= 1.0
    assert cuerpo["senales"], "la extensión necesita las señales para mostrar el detalle"
    assert cuerpo["llm"]["es_stub"] is True
    assert cuerpo["advertencias"], "el uso del stub debe advertirse"


def test_analyze_acepta_un_correo_vacio():
    # La extensión puede enviar un correo del que no logró extraer nada; debe
    # responder un veredicto, no un error.
    respuesta = cliente.post("/api/v1/analyze", json={})
    assert respuesta.status_code == 200
    assert respuesta.json()["veredicto"] == "legitimo"


def test_analyze_rechaza_un_cuerpo_mal_formado():
    respuesta = cliente.post("/api/v1/analyze", json={"asunto": 123, "cuerpo_texto": []})
    assert respuesta.status_code == 422


def test_listar_samples():
    respuesta = cliente.get("/api/v1/samples")
    assert respuesta.status_code == 200
    ids = {s["id"] for s in respuesta.json()}
    assert {"generico", "spear", "bec", "adversarial"} <= ids


def test_analizar_un_sample_por_id():
    respuesta = cliente.get("/api/v1/samples/bec")
    assert respuesta.status_code == 200
    assert respuesta.json()["veredicto"] != "legitimo"


def test_sample_inexistente_da_404():
    assert cliente.get("/api/v1/samples/no-existe").status_code == 404


def test_subida_de_eml():
    eml = (
        b"From: a@b.top\r\nSubject: Verifique su cuenta\r\n"
        b'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
        b"Su cuenta sera suspendida en 24 horas: http://b.top/login\r\n"
    )
    respuesta = cliente.post(
        "/api/v1/analyze/eml",
        files={"archivo": ("correo.eml", io.BytesIO(eml), "message/rfc822")},
    )
    assert respuesta.status_code == 200
    assert respuesta.json()["veredicto"] != "legitimo"


def test_eml_vacio_da_400():
    respuesta = cliente.post(
        "/api/v1/analyze/eml",
        files={"archivo": ("vacio.eml", io.BytesIO(b""), "message/rfc822")},
    )
    assert respuesta.status_code == 400
