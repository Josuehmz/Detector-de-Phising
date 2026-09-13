"""Señales derivadas de los nombres de archivo adjuntos.

El prototipo **no abre ningún adjunto**: solo mira el nombre. Analizar el
contenido implicaría ejecutar o interpretar archivos potencialmente maliciosos,
que está fuera del alcance declarado y exigiría un entorno aislado.
"""

from __future__ import annotations

from app.schemas import Senal, Severidad

# Extensiones que ejecutan código o arrastran a una ejecución con un solo clic.
EXTENSIONES_EJECUTABLES = frozenset(
    {"exe", "scr", "com", "pif", "bat", "cmd", "vbs", "js", "jse", "wsf", "hta",
     "msi", "ps1", "jar", "lnk", "reg"}
)

# Contenedores que se usan para envolver un ejecutable y esquivar el filtro.
EXTENSIONES_CONTENEDOR = frozenset({"zip", "rar", "7z", "iso", "img", "cab", "ace"})

# Ofimática con macros: el vector clásico de carga útil por documento.
EXTENSIONES_MACRO = frozenset({"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"})

# HTML adjunto: abre una página de phishing local, sin dominio que bloquear.
EXTENSIONES_HTML = frozenset({"html", "htm", "shtml", "mhtml"})


def _extension(nombre: str) -> str:
    return nombre.rsplit(".", 1)[-1].lower() if "." in nombre else ""


def _tiene_doble_extension(nombre: str) -> bool:
    """Detecta `factura.pdf.exe`, que Windows muestra como `factura.pdf`.

    Solo cuenta si la penúltima extensión es de un formato de documento: `.tar.gz`
    es legítimo y no debe disparar la señal.
    """
    partes = nombre.lower().split(".")
    if len(partes) < 3:
        return False
    penultima = partes[-2]
    ultima = partes[-1]
    documentos = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "png"}
    return penultima in documentos and ultima in (EXTENSIONES_EJECUTABLES | EXTENSIONES_CONTENEDOR)


def extraer_senales_adjunto(nombres: list[str]) -> list[Senal]:
    """Señales de todos los adjuntos, agrupadas por tipo de riesgo."""
    if not nombres:
        return []

    grupos: list[tuple[str, frozenset[str], Severidad, str]] = [
        (
            "adjunto_ejecutable",
            EXTENSIONES_EJECUTABLES,
            Severidad.ALTA,
            "Hay un adjunto que ejecuta código al abrirse.",
        ),
        (
            "adjunto_macro",
            EXTENSIONES_MACRO,
            Severidad.ALTA,
            "Hay un documento de ofimática con macros habilitadas.",
        ),
        (
            "adjunto_html",
            EXTENSIONES_HTML,
            Severidad.MEDIA,
            "Hay un adjunto HTML: puede abrir un formulario de phishing sin pasar por un dominio bloqueable.",
        ),
        (
            "adjunto_contenedor",
            EXTENSIONES_CONTENEDOR,
            Severidad.BAJA,
            "Hay un archivo comprimido, que impide inspeccionar su contenido desde el filtro.",
        ),
    ]

    senales: list[Senal] = []
    for id_senal, extensiones, severidad, descripcion in grupos:
        coincidencias = [n for n in nombres if _extension(n) in extensiones]
        if coincidencias:
            senales.append(
                Senal(
                    id=id_senal,
                    categoria="adjunto",
                    descripcion=descripcion,
                    severidad=severidad,
                    evidencia=coincidencias[:5],
                )
            )

    dobles = [n for n in nombres if _tiene_doble_extension(n)]
    if dobles:
        senales.append(
            Senal(
                id="adjunto_doble_extension",
                categoria="adjunto",
                descripcion="Un adjunto usa doble extensión para aparentar ser un documento inofensivo.",
                severidad=Severidad.ALTA,
                evidencia=dobles[:5],
            )
        )

    return senales
