"""Señales del remitente y de la autenticación del correo.

Quien envía el correo es la primera afirmación que hace el atacante y la más
fácil de falsificar: la cabecera `From` es texto libre. Este módulo contrasta lo
que el correo *dice* ser contra lo que las cabeceras permiten verificar.
"""

from __future__ import annotations

import re
from email.utils import parseaddr

from app.extractors.urls import MARCAS, dominio_registrable
from app.schemas import Senal, Severidad

# Proveedores de correo gratuito. No son sospechosos por sí mismos; lo son cuando
# el nombre visible dice representar a una empresa.
FREEMAIL = frozenset(
    {
        "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yahoo.es",
        "live.com", "aol.com", "protonmail.com", "proton.me", "mail.com",
        "gmx.com", "yandex.com", "icloud.com", "zoho.com",
    }
)

# Dominios legítimos de las marcas más suplantadas, para medir parecido tipográfico.
DOMINIOS_MARCA = (
    "paypal.com", "microsoft.com", "office.com", "outlook.com", "apple.com",
    "google.com", "amazon.com", "netflix.com", "facebook.com", "instagram.com",
    "dhl.com", "fedex.com", "bancolombia.com", "davivienda.com", "bbva.com",
    "nequi.com", "dian.gov.co",
)

# Distancia de edición máxima para considerar que un dominio imita a otro. Con 2
# se atrapa `bancolombla.com` y `paypa1.com`; con 3 empiezan los falsos positivos
# entre marcas de nombre corto.
UMBRAL_PARECIDO = 2

_RE_CARGO = re.compile(
    r"\b(ceo|cfo|cto|gerente|director|presidente|vicepresidente|contador|tesorer[oa]|"
    r"soporte|mesa de ayuda|help ?desk|it|sistemas|n[oó]mina|recursos humanos|rr\.?hh)\b",
    re.IGNORECASE,
)


def distancia_edicion(a: str, b: str) -> int:
    """Distancia de Levenshtein entre dos cadenas.

    Implementada a mano y no con una librería porque es parte de lo que hay que
    sustentar. Usa una sola fila de trabajo: O(len(a) * len(b)) en tiempo y
    O(min(len(a), len(b))) en memoria.
    """
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)

    fila_previa = list(range(len(b) + 1))
    for i, car_a in enumerate(a, start=1):
        fila = [i]
        for j, car_b in enumerate(b, start=1):
            borrado = fila_previa[j] + 1
            insercion = fila[j - 1] + 1
            sustitucion = fila_previa[j - 1] + (car_a != car_b)
            fila.append(min(borrado, insercion, sustitucion))
        fila_previa = fila
    return fila_previa[-1]


def separar_remitente(cabecera_from: str) -> tuple[str, str, str]:
    """Devuelve (nombre visible, dirección completa, dominio) de una cabecera `From`.

    `parseaddr` de la librería estándar se encarga del formato RFC 5322, que tiene
    más casos de los que parece: comillas, comentarios y comas dentro del nombre.
    """
    nombre, direccion = parseaddr(cabecera_from or "")
    dominio = direccion.rsplit("@", 1)[-1].lower() if "@" in direccion else ""
    return nombre.strip(), direccion.strip(), dominio


def _senales_autenticacion(cabeceras: dict[str, str]) -> list[Senal]:
    """Lee el resultado de SPF, DKIM y DMARC de la cabecera `Authentication-Results`.

    El servidor de correo ya hizo esta verificación; aquí solo se interpreta. Es la
    única señal del pipeline que un atacante no puede fabricar desde el contenido.
    """
    senales: list[Senal] = []
    normalizadas = {clave.lower(): valor for clave, valor in cabeceras.items()}
    crudo = normalizadas.get("authentication-results", "").lower()
    if not crudo:
        senales.append(
            Senal(
                id="auth_ausente",
                categoria="autenticacion",
                descripcion=(
                    "El correo no trae cabecera Authentication-Results: no se pudo "
                    "verificar SPF/DKIM/DMARC."
                ),
                severidad=Severidad.INFO,
            )
        )
        return senales

    for mecanismo in ("spf", "dkim", "dmarc"):
        coincidencia = re.search(rf"\b{mecanismo}=(\w+)", crudo)
        if not coincidencia:
            continue
        resultado = coincidencia.group(1)
        if resultado in ("fail", "softfail", "permerror"):
            senales.append(
                Senal(
                    id=f"auth_{mecanismo}_falla",
                    categoria="autenticacion",
                    descripcion=(
                        f"{mecanismo.upper()} no validó el correo (resultado: {resultado}): "
                        "el remitente no está autorizado por el dominio que dice usar."
                    ),
                    severidad=Severidad.ALTA,
                    evidencia=[f"{mecanismo}={resultado}"],
                )
            )
    return senales


def extraer_senales_remitente(
    cabecera_from: str,
    reply_to: str | None = None,
    cabeceras: dict[str, str] | None = None,
) -> list[Senal]:
    """Señales del par (nombre visible, dirección) y de la autenticación."""
    senales: list[Senal] = []
    nombre, direccion, dominio = separar_remitente(cabecera_from)

    if not direccion:
        senales.append(
            Senal(
                id="remitente_ausente",
                categoria="remitente",
                descripcion="El correo no trae una dirección de remitente interpretable.",
                severidad=Severidad.MEDIA,
                evidencia=[cabecera_from[:200]] if cabecera_from else [],
            )
        )
        return senales + _senales_autenticacion(cabeceras or {})

    registrable = dominio_registrable(dominio)
    nombre_bajo = nombre.lower()

    # El nombre visible invoca una marca que el dominio no respalda.
    for marca in sorted(MARCAS):
        if marca in nombre_bajo and marca not in dominio:
            senales.append(
                Senal(
                    id="remitente_marca_sin_respaldo",
                    categoria="remitente",
                    descripcion=(
                        f"El nombre visible dice «{nombre}» pero el correo sale del "
                        f"dominio «{dominio}», que no pertenece a esa marca."
                    ),
                    severidad=Severidad.ALTA,
                    evidencia=[cabecera_from],
                )
            )
            break

    # Pretexto corporativo desde una cuenta gratuita: el patrón de BEC más común.
    if registrable in FREEMAIL and _RE_CARGO.search(nombre_bajo):
        senales.append(
            Senal(
                id="remitente_cargo_en_freemail",
                categoria="remitente",
                descripcion=(
                    f"El nombre visible invoca un cargo corporativo pero la cuenta es "
                    f"de correo gratuito ({registrable})."
                ),
                severidad=Severidad.ALTA,
                evidencia=[cabecera_from],
            )
        )

    # Dominio tipográficamente parecido a una marca, pero distinto.
    for legitimo in DOMINIOS_MARCA:
        if registrable == legitimo:
            break
        distancia = distancia_edicion(registrable, legitimo)
        if 0 < distancia <= UMBRAL_PARECIDO:
            senales.append(
                Senal(
                    id="remitente_dominio_parecido",
                    categoria="remitente",
                    descripcion=(
                        f"El dominio «{registrable}» se parece a «{legitimo}» "
                        f"(distancia {distancia}): posible typosquatting."
                    ),
                    severidad=Severidad.ALTA,
                    evidencia=[registrable, legitimo],
                )
            )
            break

    # Responder lleva a otro dominio: la conversación se desvía al atacante.
    if reply_to:
        _, dir_reply, dom_reply = separar_remitente(reply_to)
        if dir_reply and dominio_registrable(dom_reply) != registrable:
            senales.append(
                Senal(
                    id="remitente_reply_to_distinto",
                    categoria="remitente",
                    descripcion=(
                        f"Las respuestas no van al remitente sino a «{dir_reply}», "
                        "en otro dominio."
                    ),
                    severidad=Severidad.ALTA,
                    evidencia=[f"From: {direccion}", f"Reply-To: {dir_reply}"],
                )
            )

    return senales + _senales_autenticacion(cabeceras or {})
