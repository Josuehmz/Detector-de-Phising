"""API HTTP del prototipo.

Es intencionalmente delgada: recibe, delega en `pipeline.analizar` y responde.
No hay lógica de detección aquí.

El servicio está pensado para correr en `127.0.0.1` durante el demo. No expone
autenticación ni control de acceso porque **no está pensado para desplegarse**:
publicarlo tal cual significaría aceptar correos ajenos en un servicio sin
autenticar. El despliegue en un servidor de correo real está fuera del alcance
declarado del proyecto.
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.eml import parsear_eml
from app.llm import obtener_clasificador
from app.pipeline import analizar
from app.samples import SAMPLES, obtener_sample
from app.schemas import Analisis, CorreoEntrada

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

# Tamaño máximo de un .eml aceptado. Sin este tope, un archivo grande deja el
# proceso sin memoria: el parser carga todo el mensaje en RAM.
MAX_BYTES_EML = 5 * 1024 * 1024

app = FastAPI(
    title="PhishGuard API",
    description=(
        "Prototipo de detección de phishing asistida por IA. "
        "Seminario de Seguridad de la Información 2026-2, Grupo 3."
    ),
    version=__version__,
)

# La extensión llama desde el origen `chrome-extension://<id>`, que cambia en cada
# instalación de desarrollo. Se permite ese esquema completo porque el servicio
# solo escucha en localhost durante el demo; en un despliegue real habría que
# fijar el id de la extensión publicada.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"chrome-extension://.*|moz-extension://.*|http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/api/v1/health")
def health() -> dict[str, object]:
    """Estado del servicio y qué clasificador está activo.

    La extensión lo usa para avisar si el backend no está arriba, y el campo
    `llm_es_stub` es lo que dispara el aviso visible de que los veredictos no son
    resultados reales.
    """
    clasificador = obtener_clasificador()
    return {
        "estado": "ok",
        "version": __version__,
        "clasificador": clasificador.nombre,
        "llm_es_stub": clasificador.nombre.startswith("stub"),
        "modo_llm": os.getenv("PHISHGUARD_LLM", "stub"),
    }


@app.post("/api/v1/analyze", response_model=Analisis)
def analizar_correo(correo: CorreoEntrada) -> Analisis:
    """Analiza un correo ya estructurado (lo que envía la extensión)."""
    return analizar(correo)


@app.post("/api/v1/analyze/eml", response_model=Analisis)
async def analizar_eml(archivo: UploadFile = File(...)) -> Analisis:
    """Analiza un archivo `.eml` subido desde el popup."""
    contenido = await archivo.read()

    if not contenido:
        raise HTTPException(status_code=400, detail="El archivo está vacío.")
    if len(contenido) > MAX_BYTES_EML:
        raise HTTPException(
            status_code=413,
            detail=f"El archivo supera el máximo de {MAX_BYTES_EML // (1024 * 1024)} MB.",
        )

    try:
        correo = parsear_eml(contenido)
    except Exception as error:  # noqa: BLE001 - se devuelve el motivo, no se traga
        raise HTTPException(
            status_code=400, detail=f"No se pudo interpretar el .eml: {error}"
        ) from error

    return analizar(correo)


@app.get("/api/v1/samples")
def listar_samples() -> list[dict[str, str]]:
    """Catálogo de los cinco escenarios de prueba, para el demo sin datos reales."""
    return [
        {"id": s.id, "escenario": s.escenario, "etiqueta": s.etiqueta, "asunto": s.correo.asunto}
        for s in SAMPLES
    ]


@app.get("/api/v1/samples/{sample_id}", response_model=Analisis)
def analizar_sample(sample_id: str) -> Analisis:
    """Analiza uno de los correos de ejemplo por su id."""
    sample = obtener_sample(sample_id)
    if sample is None:
        raise HTTPException(status_code=404, detail=f"No existe el ejemplo «{sample_id}».")
    return analizar(sample.correo)
