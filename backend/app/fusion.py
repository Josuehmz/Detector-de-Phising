"""Fusión del juicio del LLM con el baseline por reglas.

Ninguna de las dos fuentes decide sola. Las reglas ven lo verificable (SPF, el
dominio real de un enlace) pero no entienden el mensaje; el LLM entiende el
pretexto pero puede equivocarse con seguridad y es influenciable por el propio
correo. Combinarlas con pesos explícitos —y no dejar que una anule a la otra—
es lo que permite explicarle al analista de dónde salió el veredicto.
"""

from __future__ import annotations

from app.baseline.rules import PESOS
from app.schemas import (
    Analisis,
    ResultadoLLM,
    ResultadoReglas,
    Senal,
    Severidad,
    Veredicto,
)

# Pesos de la combinación lineal. Provisionales: fijados por criterio, no
# ajustados sobre datos. Calibrarlos contra el conjunto de validación es tarea
# del sprint 5-6; hasta entonces cualquier métrica es preliminar.
PESO_LLM = 0.6
PESO_REGLAS = 0.4

# Umbrales de la banda. La franja intermedia existe para no forzar un binario
# sobre correos ambiguos; ver la nota en `schemas.Veredicto`.
UMBRAL_PHISHING = 0.65
UMBRAL_SOSPECHOSO = 0.35

# Señales que, combinadas, no admiten un veredicto suave: el dominio dice una
# cosa y la autenticación dice otra. Es el único atajo del sistema y está acotado
# a esta lista corta y explícita para que se pueda defender en la sustentación.
_SUPLANTACION = frozenset(
    {
        "remitente_marca_sin_respaldo",
        "remitente_dominio_parecido",
        "url_texto_enganoso",
        "url_marca_fuera_del_dominio",
    }
)
_AUTENTICACION_FALLIDA = frozenset({"auth_spf_falla", "auth_dkim_falla", "auth_dmarc_falla"})
_PISO_SUPLANTACION_AUTENTICADA = 0.85


def _ordenar_por_peso(senales: list[Senal]) -> list[Senal]:
    """Las señales más determinantes primero, para que la explicación empiece por ellas."""
    orden_severidad = {
        Severidad.ALTA: 3,
        Severidad.MEDIA: 2,
        Severidad.BAJA: 1,
        Severidad.INFO: 0,
    }
    return sorted(
        senales,
        key=lambda s: (PESOS.get(s.id, 0.0), orden_severidad[s.severidad]),
        reverse=True,
    )


def _redactar_explicacion(
    veredicto: Veredicto, senales_ordenadas: list[Senal], llm: ResultadoLLM
) -> str:
    """Arma el texto que ve el analista: primero el juicio, luego en qué se basó."""
    encabezados = {
        Veredicto.PHISHING: "Se clasifica como phishing.",
        Veredicto.SOSPECHOSO: "Requiere revisión humana: hay indicios, pero no concluyentes.",
        Veredicto.LEGITIMO: "No se encontraron indicios suficientes de phishing.",
    }
    partes = [encabezados[veredicto], llm.razonamiento]

    principales = [s for s in senales_ordenadas if PESOS.get(s.id, 0.0) > 0][:4]
    if principales:
        partes.append("Señales que más pesaron:")
        partes.extend(f"• {s.descripcion}" for s in principales)

    return "\n".join(partes)


def fusionar(
    senales: list[Senal], reglas: ResultadoReglas, llm: ResultadoLLM
) -> Analisis:
    """Combina ambas fuentes y produce el análisis final.

    Complejidad: O(n log n) por el ordenamiento de las señales.
    """
    score = PESO_LLM * llm.score + PESO_REGLAS * reglas.score
    advertencias: list[str] = []

    ids = {s.id for s in senales}
    if ids & _SUPLANTACION and ids & _AUTENTICACION_FALLIDA:
        if score < _PISO_SUPLANTACION_AUTENTICADA:
            advertencias.append(
                "Score elevado por regla de escalada: hay suplantación de identidad y además "
                "la autenticación del dominio falló."
            )
        score = max(score, _PISO_SUPLANTACION_AUTENTICADA)

    score = round(min(1.0, score), 4)

    if score >= UMBRAL_PHISHING:
        veredicto = Veredicto.PHISHING
    elif score >= UMBRAL_SOSPECHOSO:
        veredicto = Veredicto.SOSPECHOSO
    else:
        veredicto = Veredicto.LEGITIMO

    # La confianza mide el acuerdo entre las dos fuentes, no la fuerza del score.
    # Que reglas y LLM coincidan es información distinta de que el correo sea
    # peligroso: un correo con score 0.5 donde ambos dicen 0.5 es más informativo
    # que uno donde uno dice 0.1 y el otro 0.9.
    confianza = round(1.0 - abs(llm.score - reglas.score), 4)

    if llm.es_stub:
        advertencias.append(
            "El componente de IA es un stub determinista, no un modelo de lenguaje. "
            "Este veredicto NO es un resultado del proyecto."
        )
    if "llm_intento_de_manipulacion" in llm.indicadores:
        advertencias.append(
            "El correo contiene texto dirigido al clasificador (intento de inyección de prompt)."
        )

    senales_ordenadas = _ordenar_por_peso(senales)

    return Analisis(
        veredicto=veredicto,
        score=score,
        confianza=max(0.0, confianza),
        explicacion=_redactar_explicacion(veredicto, senales_ordenadas, llm),
        senales=senales_ordenadas,
        reglas=reglas,
        llm=llm,
        advertencias=advertencias,
    )
