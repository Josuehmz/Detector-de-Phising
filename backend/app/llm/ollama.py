"""Adaptador contra un modelo local servido por Ollama.

Se activa con `PHISHGUARD_LLM=ollama`. No necesita clave de API ni conexión a
internet: habla con `http://localhost:11434`, donde Ollama sirve el modelo que
se haya descargado.

Qué gana el proyecto con esta vía, además de que es gratis
----------------------------------------------------------

1. **El correo no sale de la máquina.** El análisis deja de enviar datos
   personales a un tercero, que es el argumento de minimización de datos del
   propio proyecto. Deja de haber un "servicio externo" en el diagrama.

2. **El experimento se vuelve reproducible.** Con la API de Claude no se puede
   fijar `temperature`, así que dos pasadas sobre el mismo corpus pueden dar
   métricas distintas. Aquí sí: `temperature=0` y una semilla fija hacen que la
   misma entrada produzca la misma salida. Para un informe con cifras, eso no es
   un detalle.

Qué se pierde
-------------
Capacidad. Un modelo de 3B respondiendo en español sobre el pretexto de un
correo no juega en la misma liga. Si el resultado es que no supera al baseline,
**eso es un hallazgo y hay que reportarlo como tal**, no maquillarlo cambiando
de modelo hasta que salga bonito.

Variables de entorno
--------------------
- `PHISHGUARD_OLLAMA_URL`    — por defecto `http://localhost:11434`.
- `PHISHGUARD_OLLAMA_MODELO` — por defecto `llama3.2:3b`.
- `PHISHGUARD_OLLAMA_SEED`   — semilla para reproducibilidad. Por defecto 42.
- `PHISHGUARD_OLLAMA_TIMEOUT`— segundos. Por defecto 300: en CPU una respuesta
  puede tardar minutos, y un timeout corto convertiría "lento" en "sin juicio".
"""

from __future__ import annotations

import logging
import os

from pydantic import ValidationError

from app.llm.prompt import (
    SYSTEM_PROMPT,
    RespuestaModelo,
    a_resultado,
    construir_mensaje,
    sin_juicio,
)
from app.schemas import CorreoEntrada, ResultadoLLM, Senal

_log = logging.getLogger(__name__)

URL_POR_DEFECTO = "http://localhost:11434"
MODELO_POR_DEFECTO = "llama3.2:3b"

# En CPU la generación va lenta. 300 s es holgado a propósito: un timeout corto
# se contaría como "el modelo no juzgó", y sería mentira — sí juzgaba, iba lento.
TIMEOUT_POR_DEFECTO = 300

# Techo de tokens generados. La respuesta es un JSON corto; este límite solo
# existe para que un modelo que se atasque repitiéndose no cuelgue la pasada.
MAX_TOKENS_RESPUESTA = 800


def _entero_de_entorno(nombre: str, por_defecto: int) -> int:
    crudo = os.getenv(nombre)
    if not crudo:
        return por_defecto
    try:
        return int(crudo)
    except ValueError:
        _log.warning("%s='%s' no es un entero. Se usa %d.", nombre, crudo, por_defecto)
        return por_defecto


class ClasificadorOllama:
    """Implementación de `ClasificadorLLM` sobre un modelo local de Ollama."""

    def __init__(self, modelo: str | None = None, cliente: object | None = None) -> None:
        self.url = (os.getenv("PHISHGUARD_OLLAMA_URL") or URL_POR_DEFECTO).rstrip("/")
        self.nombre = modelo or os.getenv("PHISHGUARD_OLLAMA_MODELO", MODELO_POR_DEFECTO)
        self._semilla = _entero_de_entorno("PHISHGUARD_OLLAMA_SEED", 42)
        self._timeout = _entero_de_entorno("PHISHGUARD_OLLAMA_TIMEOUT", TIMEOUT_POR_DEFECTO)

        if cliente is None:
            import httpx

            cliente = httpx.Client(timeout=self._timeout)
        self._cliente = cliente

    def _peticion(self, correo: CorreoEntrada, senales: list[Senal]) -> dict:
        return {
            "model": self.nombre,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": construir_mensaje(correo, senales)},
            ],
            "stream": False,
            # El esquema restringe la generación token a token: el modelo no
            # puede salirse del formato aunque el correo se lo pida.
            "format": RespuestaModelo.model_json_schema(),
            "options": {
                # Las dos claves de la reproducibilidad, que con la API de Claude
                # no están disponibles.
                "temperature": 0,
                "seed": self._semilla,
                "num_predict": MAX_TOKENS_RESPUESTA,
            },
        }

    def clasificar(self, correo: CorreoEntrada, senales: list[Senal]) -> ResultadoLLM:
        try:
            respuesta = self._cliente.post(
                f"{self.url}/api/chat", json=self._peticion(correo, senales)
            )
        except Exception as error:  # noqa: BLE001
            _log.warning("No se pudo contactar Ollama en %s: %s", self.url, error)
            return sin_juicio(
                self.nombre,
                f"error_de_api:{type(error).__name__}",
                f"No se pudo contactar Ollama en {self.url}. ¿Está corriendo `ollama serve`?",
            )

        if respuesta.status_code != 200:
            detalle = respuesta.text[:200]
            _log.warning("Ollama respondió %s: %s", respuesta.status_code, detalle)
            return sin_juicio(
                self.nombre,
                f"error_de_api:HTTP{respuesta.status_code}",
                # El fallo más común es pedir un modelo que no se ha descargado.
                f"Ollama respondió {respuesta.status_code}. Si el modelo no está "
                f"descargado: `ollama pull {self.nombre}`.",
            )

        cuerpo = respuesta.json()
        contenido = (cuerpo.get("message") or {}).get("content") or ""

        # Dejar constancia de lo que costó. En CPU esto es el dato que decide si
        # una pasada sobre el corpus es viable o hay que bajar de modelo.
        duracion_s = (cuerpo.get("total_duration") or 0) / 1e9
        if duracion_s:
            _log.info(
                "Ollama %s: %.1f s, %s tokens generados.",
                self.nombre,
                duracion_s,
                cuerpo.get("eval_count", "?"),
            )

        try:
            juicio = RespuestaModelo.model_validate_json(contenido)
        except ValidationError as error:
            # El esquema restringe la generación, pero un modelo pequeño puede
            # quedarse sin `num_predict` a mitad del JSON. Eso es quedarse sin
            # juicio, no un juicio de "legítimo".
            _log.warning("Ollama devolvió algo que no encaja en el esquema: %s", error)
            return sin_juicio(
                self.nombre,
                "sin_salida_estructurada:esquema_invalido",
                "El modelo local no devolvió un juicio utilizable; el veredicto sale "
                "solo del baseline.",
            )

        return a_resultado(juicio, self.nombre)
