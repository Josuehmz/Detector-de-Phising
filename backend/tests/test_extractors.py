"""Pruebas de los extractores de señales.

Cada extractor se prueba aislado, con el caso positivo, el negativo y los casos
de borde (entrada vacía, sin enlaces, dominio legítimo).
"""

from __future__ import annotations

import pytest

from app.extractors.adjuntos import extraer_senales_adjunto
from app.extractors.remitente import (
    distancia_edicion,
    extraer_senales_remitente,
    separar_remitente,
)
from app.extractors.social import extraer_senales_sociales
from app.extractors.urls import dominio_registrable, extraer_senales_url, extraer_urls


def ids(senales) -> set[str]:
    return {s.id for s in senales}


# --------------------------------------------------------------------------- URLs


def test_extraer_urls_quita_la_puntuacion_final():
    texto = "Entra a https://ejemplo.com/login, por favor."
    assert extraer_urls(texto) == ["https://ejemplo.com/login"]


def test_extraer_urls_no_repite():
    texto = "https://a.com y otra vez https://a.com"
    assert extraer_urls(texto) == ["https://a.com"]


def test_texto_sin_urls_no_produce_senales():
    assert extraer_senales_url("Nos vemos el martes.") == []


def test_texto_vacio_no_produce_senales():
    assert extraer_senales_url("") == []
    assert extraer_senales_url("", None) == []


def test_ip_literal_y_puerto_no_estandar():
    senales = ids(extraer_senales_url("http://192.168.1.10:8080/verify"))
    assert "url_ip_literal" in senales
    assert "url_puerto_no_estandar" in senales


def test_marca_en_subdominio_pero_no_en_el_dominio():
    senales = ids(extraer_senales_url("http://paypal.com.verificar.top/login"))
    assert "url_marca_fuera_del_dominio" in senales
    assert "url_tld_sospechoso" in senales


def test_marca_en_su_propio_dominio_no_dispara_la_senal():
    senales = ids(extraer_senales_url("https://www.paypal.com/signin"))
    assert "url_marca_fuera_del_dominio" not in senales


def test_texto_del_enlace_no_coincide_con_el_destino():
    html = '<a href="http://malicioso.top/x">bancolombia.com</a>'
    assert "url_texto_enganoso" in ids(extraer_senales_url("", html))


def test_ancla_sin_dominio_visible_no_dispara_texto_enganoso():
    # "Haz clic aquí" no promete ningún dominio, así que no engaña por sí solo.
    html = '<a href="http://malicioso.top/x">Haz clic aquí</a>'
    assert "url_texto_enganoso" not in ids(extraer_senales_url("", html))


def test_muchos_enlaces_iguales_producen_una_sola_senal():
    texto = " ".join(f"https://bit.ly/a{i}" for i in range(10))
    acortadores = [s for s in extraer_senales_url(texto) if s.id == "url_acortador"]
    assert len(acortadores) == 1
    assert len(acortadores[0].evidencia) == 10


def test_dominio_registrable_es_una_aproximacion_conocida():
    assert dominio_registrable("www.ejemplo.com") == "ejemplo.com"
    assert dominio_registrable("localhost") == "localhost"
    # Limitación documentada: sin Public Suffix List, `com.co` se lee como dominio.
    assert dominio_registrable("bancolombia.com.co") == "com.co"


# ---------------------------------------------------------------------- Remitente


@pytest.mark.parametrize(
    ("a", "b", "esperado"),
    [
        ("", "", 0),
        ("abc", "abc", 0),
        ("abc", "", 3),
        ("paypal.com", "paypa1.com", 1),
        ("gato", "pato", 1),
    ],
)
def test_distancia_edicion(a, b, esperado):
    assert distancia_edicion(a, b) == esperado
    assert distancia_edicion(b, a) == esperado  # es simétrica


def test_separar_remitente():
    nombre, direccion, dominio = separar_remitente("Soporte <ayuda@ejemplo.com>")
    assert (nombre, direccion, dominio) == ("Soporte", "ayuda@ejemplo.com", "ejemplo.com")


def test_remitente_vacio_se_reporta_no_se_ignora():
    assert "remitente_ausente" in ids(extraer_senales_remitente(""))


def test_nombre_invoca_una_marca_que_el_dominio_no_respalda():
    senales = ids(extraer_senales_remitente("Seguridad PayPal <x@otrodominio.xyz>"))
    assert "remitente_marca_sin_respaldo" in senales


def test_cargo_corporativo_desde_correo_gratuito():
    senales = ids(extraer_senales_remitente("Gerente General <g.direccion@gmail.com>"))
    assert "remitente_cargo_en_freemail" in senales


def test_persona_normal_en_gmail_no_es_sospechosa():
    senales = ids(extraer_senales_remitente("Ana Pérez <ana.perez@gmail.com>"))
    assert "remitente_cargo_en_freemail" not in senales


def test_dominio_tipograficamente_parecido():
    senales = ids(extraer_senales_remitente("Netflix <no-reply@netflix.co>"))
    assert "remitente_dominio_parecido" in senales


def test_reply_to_en_otro_dominio():
    senales = ids(
        extraer_senales_remitente("Pagos <pagos@empresa.com>", reply_to="otro@atacante.top")
    )
    assert "remitente_reply_to_distinto" in senales


def test_reply_to_al_mismo_dominio_no_dispara():
    senales = ids(
        extraer_senales_remitente("Pagos <pagos@empresa.com>", reply_to="otro@empresa.com")
    )
    assert "remitente_reply_to_distinto" not in senales


def test_autenticacion_fallida_se_lee_de_las_cabeceras():
    cabeceras = {"Authentication-Results": "mx; spf=fail; dkim=none; dmarc=fail"}
    senales = ids(extraer_senales_remitente("a@b.com", cabeceras=cabeceras))
    assert {"auth_spf_falla", "auth_dmarc_falla"} <= senales


def test_autenticacion_correcta_no_produce_senales_de_falla():
    cabeceras = {"Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass"}
    senales = ids(extraer_senales_remitente("a@b.com", cabeceras=cabeceras))
    assert not any(s.startswith("auth_") and s.endswith("_falla") for s in senales)


def test_sin_cabecera_de_autenticacion_se_marca_como_no_verificable():
    assert "auth_ausente" in ids(extraer_senales_remitente("a@b.com", cabeceras={}))


# --------------------------------------------------------------- Ingeniería social


def test_urgencia_y_amenaza_en_espanol():
    senales = ids(
        extraer_senales_sociales(
            "URGENTE", "Su cuenta sera suspendida en 24 horas si no verifica su cuenta."
        )
    )
    assert {"social_urgencia", "social_amenaza", "social_credenciales"} <= senales


def test_urgencia_y_amenaza_en_ingles():
    senales = ids(
        extraer_senales_sociales(
            "Action required", "Your account will be suspended within 24 hours. Verify your account."
        )
    )
    assert {"social_urgencia", "social_amenaza", "social_credenciales"} <= senales


def test_patron_de_bec():
    senales = ids(
        extraer_senales_sociales(
            "Disponible?",
            "Necesito una transferencia urgente. Por ahora no le comentes a nadie.",
        )
    )
    assert {"social_financiera", "social_confidencialidad"} <= senales


def test_correo_neutro_no_dispara_senales_sociales():
    assert extraer_senales_sociales("Acta de reunión", "Adjunto el acta del martes.") == []


def test_entradas_vacias_no_rompen():
    assert extraer_senales_sociales("", "") == []


def test_la_evidencia_indica_de_donde_salio():
    senales = extraer_senales_sociales("Urgente", "")
    assert senales[0].evidencia[0].startswith("[asunto]")


# ----------------------------------------------------------------------- Adjuntos


def test_sin_adjuntos_no_hay_senales():
    assert extraer_senales_adjunto([]) == []


def test_doble_extension():
    senales = ids(extraer_senales_adjunto(["factura.pdf.exe"]))
    assert {"adjunto_doble_extension", "adjunto_ejecutable"} <= senales


def test_tar_gz_no_es_doble_extension_sospechosa():
    assert "adjunto_doble_extension" not in ids(extraer_senales_adjunto(["backup.tar.gz"]))


def test_documento_con_macros_y_html():
    assert "adjunto_macro" in ids(extraer_senales_adjunto(["informe.xlsm"]))
    assert "adjunto_html" in ids(extraer_senales_adjunto(["documento.htm"]))


def test_pdf_normal_no_dispara_nada():
    assert extraer_senales_adjunto(["acta.pdf"]) == []


def test_archivo_sin_extension_no_rompe():
    assert extraer_senales_adjunto(["README"]) == []
