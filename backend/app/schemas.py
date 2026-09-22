"""Contratos de datos del pipeline.

Un solo lugar define qué entra y qué sale, para que la extensión, los tests y el
informe hablen del mismo vocabulario.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Veredicto(str, Enum):
    """Etiqueta final que ve el analista.

    Son tres y no dos a propósito: el objetivo del proyecto es clasificación
    binaria (legítimo / phishing), pero un prototipo que solo dice "sí" o "no"
    empuja los casos ambiguos hacia un falso positivo o un falso negativo. La
    zona SOSPECHOSO los aísla para revisión humana. Al evaluar contra el dataset
    se colapsa a binario con la regla documentada en `docs/arquitectura.md`.
    """

    LEGITIMO = "legitimo"
    SOSPECHOSO = "sospechoso"
    PHISHING = "phishing"


class Severidad(str, Enum):
    INFO = "info"
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"


class CorreoEntrada(BaseModel):
    """Correo tal como llega desde la extensión o desde un test."""

    asunto: str = Field(default="", max_length=1000)
    remitente: str = Field(default="", max_length=500, description="Cabecera From completa")
    reply_to: str | None = Field(default=None, max_length=500)
    cuerpo_texto: str = Field(default="", max_length=200_000)
    cuerpo_html: str | None = Field(default=None, max_length=500_000)
    cabeceras: dict[str, str] = Field(default_factory=dict)
    adjuntos: list[str] = Field(default_factory=list, description="Solo nombres de archivo")
    origen: Literal["extension", "popup", "eml", "test"] = "test"


class Senal(BaseModel):
    """Un indicador observable extraído del correo.

    Las señales son *hechos* ("el enlace usa un acortador"), no juicios. El juicio
    lo emiten las reglas y el LLM a partir de ellas. Separarlo permite mostrarle
    al analista en qué se basó el veredicto.
    """

    id: str
    categoria: Literal["url", "remitente", "ingenieria_social", "adjunto", "autenticacion"]
    descripcion: str
    severidad: Severidad
    evidencia: list[str] = Field(default_factory=list)


class ResultadoReglas(BaseModel):
    """Salida del baseline heurístico, la línea base contra la que se compara."""

    score: float = Field(ge=0.0, le=1.0)
    reglas_disparadas: list[str] = Field(default_factory=list)


class ResultadoLLM(BaseModel):
    """Salida del clasificador basado en modelo de lenguaje."""

    score: float = Field(ge=0.0, le=1.0)
    razonamiento: str
    indicadores: list[str] = Field(default_factory=list)
    modelo: str = Field(description="Identificador de la implementación que respondió")
    es_stub: bool = Field(
        default=False,
        description="True cuando el score NO viene de un modelo real. Nunca reportar "
        "métricas como resultado del proyecto si este campo es True.",
    )
    sin_juicio: bool = Field(
        default=False,
        description="True cuando el modelo no llegó a emitir un juicio. En ese caso "
        "`score` NO significa nada y la fusión debe ignorarlo: un correo que el "
        "modelo no juzgó es un dato que falta, no un veredicto de 'legítimo'.",
    )
    motivo_sin_juicio: str | None = Field(
        default=None,
        description="Por qué no hubo juicio, para poder agrupar los casos en la "
        "evaluación: 'rechazo_del_modelo:<categoría>', 'respuesta_truncada' o "
        "'error_de_api:<tipo>'.",
    )


class Analisis(BaseModel):
    """Respuesta completa del pipeline."""

    veredicto: Veredicto
    score: float = Field(ge=0.0, le=1.0)
    confianza: float = Field(ge=0.0, le=1.0)
    explicacion: str
    senales: list[Senal] = Field(default_factory=list)
    reglas: ResultadoReglas
    llm: ResultadoLLM
    advertencias: list[str] = Field(default_factory=list)
