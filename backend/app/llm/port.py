"""Puerto del clasificador por modelo de lenguaje.

El pipeline depende de esta interfaz, no de un proveedor concreto. Así el
prototipo corre hoy con un stub determinista, sin red ni clave de API, y en el
sprint 4 se enchufa el adaptador real sin tocar el pipeline ni los tests.

Es la única abstracción que el proyecto introduce por adelantado, y se justifica
porque el cronograma ya dice que va a haber al menos dos implementaciones
(stub y modelo real) y porque los tests necesitan una salida determinista.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.schemas import CorreoEntrada, ResultadoLLM, Senal


@runtime_checkable
class ClasificadorLLM(Protocol):
    """Emite un juicio sobre el correo a partir del texto y las señales extraídas.

    Recibe las señales además del correo porque el LLM no tiene que volver a
    encontrar lo que el código ya encontró: extraer URLs o leer cabeceras es
    trabajo determinista y auditable. Al modelo se le pide lo que el código no
    sabe hacer — juzgar el pretexto, el tono y la coherencia del mensaje.
    """

    nombre: str

    def clasificar(self, correo: CorreoEntrada, senales: list[Senal]) -> ResultadoLLM:
        """Devuelve score [0,1], razonamiento en español e indicadores citados."""
        ...
