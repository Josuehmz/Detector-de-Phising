"""Ingesta de archivos `.eml`.

Los datasets de referencia del proyecto (Nazario, SpamAssassin) vienen en este
formato, así que esta es la puerta de entrada para la evaluación por lotes,
además del botón "subir .eml" de la extensión.

Se usa `email` de la librería estándar: decodificar MIME a mano —charsets,
Base64, quoted-printable, multipart anidado— es un problema resuelto y volver a
resolverlo solo añadiría errores.
"""

from __future__ import annotations

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

from app.schemas import CorreoEntrada

# Cabeceras que interesan al pipeline. No se copian todas: el resto es ruido para
# el análisis y, en un correo real, información personal que no hace falta mover.
CABECERAS_RELEVANTES = (
    "authentication-results",
    "received-spf",
    "dkim-signature",
    "return-path",
    "x-mailer",
    "date",
)


def _texto_de(mensaje: EmailMessage) -> tuple[str, str | None]:
    """Devuelve (texto plano, html) del cuerpo, prefiriendo la parte más rica."""
    texto = ""
    html: str | None = None

    parte_texto = mensaje.get_body(preferencelist=("plain",))
    if parte_texto is not None:
        texto = parte_texto.get_content()

    parte_html = mensaje.get_body(preferencelist=("html",))
    if parte_html is not None:
        html = parte_html.get_content()

    # Correo solo-HTML: el pipeline necesita algún texto sobre el que buscar
    # frases de ingeniería social, así que se usa el HTML crudo como respaldo.
    # Los extractores léxicos toleran las etiquetas; el resultado es peor que con
    # texto limpio, y queda anotado como limitación conocida.
    if not texto and html:
        texto = html

    return texto, html


def parsear_eml(contenido: bytes) -> CorreoEntrada:
    """Convierte un `.eml` en la entrada del pipeline.

    `policy.default` es lo que activa la API moderna (`get_body`, decodificación
    automática de charsets); con la política por defecto de compatibilidad el
    resultado llega en bytes crudos.
    """
    mensaje: EmailMessage = BytesParser(policy=policy.default).parsebytes(contenido)

    texto, html = _texto_de(mensaje)

    adjuntos = [
        nombre
        for parte in mensaje.iter_attachments()
        if (nombre := parte.get_filename()) is not None
    ]

    cabeceras = {
        clave: valor
        for clave in CABECERAS_RELEVANTES
        if (valor := mensaje.get(clave)) is not None
    }

    return CorreoEntrada(
        asunto=str(mensaje.get("subject", "")),
        remitente=str(mensaje.get("from", "")),
        reply_to=str(mensaje["reply-to"]) if mensaje.get("reply-to") else None,
        cuerpo_texto=texto,
        cuerpo_html=html,
        cabeceras=cabeceras,
        adjuntos=adjuntos,
        origen="eml",
    )
