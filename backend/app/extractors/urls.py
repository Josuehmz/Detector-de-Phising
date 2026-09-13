"""Señales derivadas de los enlaces del correo.

El enlace es la única parte del phishing que el atacante no puede falsificar del
todo: en algún momento tiene que apuntar a infraestructura que él controla. Por
eso es la fuente de señales más difícil de evadir.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from app.schemas import Senal, Severidad

# Acortadores frecuentes. La lista es corta a propósito: solo los que aparecen en
# los datasets de referencia del proyecto (Nazario, SpamAssassin).
ACORTADORES = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "s.id",
    }
)

# TLD con tasa de abuso desproporcionada respecto a su volumen de registros.
# `.zip` y `.mov` entran porque colisionan con extensiones de archivo.
TLD_SOSPECHOSOS = frozenset(
    {"zip", "mov", "top", "xyz", "tk", "cf", "gq", "ml", "ga", "click", "country", "kim"}
)

# Rutas típicas de una página de captura de credenciales.
RUTAS_CREDENCIALES = (
    "login", "signin", "sign-in", "verify", "verificar", "secure", "seguro",
    "account", "cuenta", "update", "actualizar", "confirm", "confirmar",
    "unlock", "desbloquear", "validate", "password", "contrasena",
)

# Marcas más suplantadas. Sirven para detectar que el nombre de una marca aparece
# en un subdominio o en la ruta, pero no en el dominio registrable.
MARCAS = frozenset(
    {
        "paypal", "microsoft", "office365", "outlook", "apple", "icloud", "google",
        "gmail", "amazon", "netflix", "facebook", "instagram", "whatsapp", "dhl",
        "fedex", "bancolombia", "davivienda", "bbva", "nequi", "daviplata", "dian",
    }
)

_RE_URL = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)
_RE_HREF = re.compile(
    r"<a\b[^>]*href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
_RE_ETIQUETAS = re.compile(r"<[^>]+>")
_RE_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_RE_PARECE_DOMINIO = re.compile(r"^(https?://)?[\w.-]+\.[a-z]{2,}(/|$)", re.IGNORECASE)


def extraer_urls(texto: str, html: str | None = None) -> list[str]:
    """Devuelve las URLs del correo, sin repetir y conservando el orden de aparición."""
    encontradas: list[str] = _RE_URL.findall(texto or "")
    if html:
        encontradas.extend(href for href, _ in _RE_HREF.findall(html))
        encontradas.extend(_RE_URL.findall(_RE_ETIQUETAS.sub(" ", html)))

    vistas: set[str] = set()
    unicas: list[str] = []
    for url in encontradas:
        # La puntuación final de una frase se pega a la URL cuando va en texto plano.
        limpia = url.rstrip(".,;:!?)")
        if limpia and limpia not in vistas:
            vistas.add(limpia)
            unicas.append(limpia)
    return unicas


def dominio_registrable(host: str) -> str:
    """Aproxima el dominio registrable quedándose con las dos últimas etiquetas.

    Es una aproximación deliberada: hacerlo bien exige la Public Suffix List, que
    trata `com.co` o `co.uk` como sufijo. Con esta versión `bancolombia.com.co` se
    lee como `com.co`, lo que degrada la comparación de dominios en correos
    colombianos. Queda anotado como limitación conocida en `docs/arquitectura.md`;
    el sprint de evaluación decide si se añade la dependencia `tldextract`.
    """
    partes = host.lower().strip(".").split(".")
    return ".".join(partes[-2:]) if len(partes) >= 2 else host.lower()


def _analizar_una(url: str) -> list[Senal]:
    """Señales de una sola URL."""
    senales: list[Senal] = []
    try:
        partes = urlparse(url)
        host = (partes.hostname or "").lower()
        puerto = partes.port
    except ValueError:
        # urlparse lanza ValueError con hosts o puertos malformados. Se reporta como
        # señal en vez de descartar el enlace: un enlace que ni siquiera se puede
        # interpretar ya es información sobre el correo.
        return [
            Senal(
                id="url_malformada",
                categoria="url",
                descripcion="El enlace no se pudo interpretar como una URL válida.",
                severidad=Severidad.BAJA,
                evidencia=[url[:200]],
            )
        ]

    if not host:
        return senales

    registrable = dominio_registrable(host)

    if registrable in ACORTADORES:
        senales.append(
            Senal(
                id="url_acortador",
                categoria="url",
                descripcion="El enlace usa un acortador, que oculta el destino real.",
                severidad=Severidad.MEDIA,
                evidencia=[url],
            )
        )

    if _RE_IPV4.match(host):
        senales.append(
            Senal(
                id="url_ip_literal",
                categoria="url",
                descripcion="El enlace apunta a una dirección IP en vez de a un dominio.",
                severidad=Severidad.ALTA,
                evidencia=[url],
            )
        )

    if "xn--" in host:
        senales.append(
            Senal(
                id="url_punycode",
                categoria="url",
                descripcion=(
                    "El dominio usa Punycode: puede imitar una marca con caracteres "
                    "de otro alfabeto."
                ),
                severidad=Severidad.ALTA,
                evidencia=[host],
            )
        )

    tld = registrable.rsplit(".", 1)[-1]
    if tld in TLD_SOSPECHOSOS:
        senales.append(
            Senal(
                id="url_tld_sospechoso",
                categoria="url",
                descripcion=f"El dominio de nivel superior .{tld} concentra una tasa alta de abuso.",
                severidad=Severidad.MEDIA,
                evidencia=[host],
            )
        )

    # Marca en el subdominio o en la ruta, pero no en el dominio registrable:
    # `paypal.com.verificacion-cuenta.top/login` es el patrón clásico.
    contexto = f"{host}{partes.path}".lower()
    for marca in sorted(MARCAS):
        if marca in contexto and marca not in registrable:
            senales.append(
                Senal(
                    id="url_marca_fuera_del_dominio",
                    categoria="url",
                    descripcion=(
                        f"El enlace menciona la marca «{marca}» en el subdominio o la ruta, "
                        f"pero el dominio real es «{registrable}»."
                    ),
                    severidad=Severidad.ALTA,
                    evidencia=[url],
                )
            )
            break

    ruta = partes.path.lower()
    if any(palabra in ruta for palabra in RUTAS_CREDENCIALES):
        senales.append(
            Senal(
                id="url_ruta_credenciales",
                categoria="url",
                descripcion="La ruta del enlace sugiere un formulario de inicio de sesión o verificación.",
                severidad=Severidad.BAJA,
                evidencia=[partes.path[:200]],
            )
        )

    if puerto is not None and puerto not in (80, 443):
        senales.append(
            Senal(
                id="url_puerto_no_estandar",
                categoria="url",
                descripcion=f"El enlace usa el puerto {puerto}, poco habitual en servicios legítimos.",
                severidad=Severidad.MEDIA,
                evidencia=[url],
            )
        )

    return senales


def _detectar_texto_enganoso(html: str) -> list[Senal]:
    """Detecta anclas cuyo texto visible nombra un dominio distinto al del href.

    Es la señal más directa de engaño deliberado: el usuario lee `bancolombia.com`
    y el clic lo lleva a otro sitio. Solo es visible en el HTML, por eso no vive
    dentro del análisis por URL.
    """
    senales: list[Senal] = []
    for href, texto_interno in _RE_HREF.findall(html):
        visible = _RE_ETIQUETAS.sub("", texto_interno).strip()
        # Solo aplica si el texto visible aparenta ser una dirección web; un ancla
        # que dice "haz clic aquí" no promete ningún dominio y no engaña por sí sola.
        if not _RE_PARECE_DOMINIO.match(visible):
            continue
        try:
            host_visible = urlparse(visible if "://" in visible else f"http://{visible}").hostname
            host_real = urlparse(href).hostname
        except ValueError:
            continue
        if not host_visible or not host_real:
            continue
        if dominio_registrable(host_visible) != dominio_registrable(host_real):
            senales.append(
                Senal(
                    id="url_texto_enganoso",
                    categoria="url",
                    descripcion=f"El enlace se muestra como «{host_visible}» pero apunta a «{host_real}».",
                    severidad=Severidad.ALTA,
                    evidencia=[f"{visible} -> {href}"],
                )
            )
    return senales


def fusionar_por_id(senales: list[Senal]) -> list[Senal]:
    """Colapsa señales repetidas acumulando su evidencia.

    Diez enlaces acortados son una señal con diez evidencias, no diez señales. Sin
    esta fusión, un correo con muchos enlaces infla su propio score y el baseline
    deja de ser comparable entre correos de distinta longitud.
    """
    fusionadas: dict[str, Senal] = {}
    for senal in senales:
        previa = fusionadas.get(senal.id)
        if previa is None:
            fusionadas[senal.id] = senal.model_copy(deep=True)
        else:
            for evidencia in senal.evidencia:
                if evidencia not in previa.evidencia:
                    previa.evidencia.append(evidencia)
    return list(fusionadas.values())


def extraer_senales_url(texto: str, html: str | None = None) -> list[Senal]:
    """Señales de todos los enlaces del correo, sin duplicar por id."""
    senales: list[Senal] = []
    for url in extraer_urls(texto, html):
        senales.extend(_analizar_una(url))
    if html:
        senales.extend(_detectar_texto_enganoso(html))
    return fusionar_por_id(senales)
