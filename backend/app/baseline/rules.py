"""Baseline heurístico por reglas.

Este módulo **es el punto de comparación del proyecto**, no un detalle de
implementación: la pregunta de investigación es si el clasificador asistido por
IA supera a un filtro tradicional, y un filtro tradicional es exactamente esto —
una suma ponderada de indicadores con un umbral, el modelo de SpamAssassin.

Por eso el baseline solo mira las señales léxicas y estructurales. Que no
entienda el *significado* del correo no es un defecto a corregir: es la
limitación que el experimento quiere medir.
"""

from __future__ import annotations

from app.schemas import ResultadoReglas, Senal

# Peso de cada señal en el score final. Los valores son un punto de partida fijado
# por criterio experto, NO ajustados sobre datos: calibrarlos con el conjunto de
# entrenamiento es trabajo del sprint de evaluación (S5-S6). Hasta entonces, las
# métricas del baseline son preliminares y así deben reportarse.
PESOS: dict[str, float] = {
    # Autenticación — lo más difícil de falsificar, por eso pesa más.
    "auth_spf_falla": 0.35,
    "auth_dkim_falla": 0.30,
    "auth_dmarc_falla": 0.40,
    "auth_ausente": 0.05,
    # Remitente.
    "remitente_marca_sin_respaldo": 0.35,
    "remitente_dominio_parecido": 0.40,
    "remitente_cargo_en_freemail": 0.30,
    "remitente_reply_to_distinto": 0.30,
    "remitente_ausente": 0.15,
    # URLs.
    "url_texto_enganoso": 0.40,
    "url_marca_fuera_del_dominio": 0.35,
    "url_ip_literal": 0.30,
    "url_punycode": 0.30,
    "url_acortador": 0.15,
    "url_tld_sospechoso": 0.15,
    "url_puerto_no_estandar": 0.10,
    "url_ruta_credenciales": 0.10,
    "url_malformada": 0.05,
    # Ingeniería social.
    "social_credenciales": 0.25,
    "social_amenaza": 0.20,
    "social_confidencialidad": 0.20,
    "social_financiera": 0.20,
    "social_urgencia": 0.15,
    "social_autoridad": 0.10,
    "social_premio": 0.15,
    "social_saludo_generico": 0.05,
    # Adjuntos.
    "adjunto_doble_extension": 0.40,
    "adjunto_ejecutable": 0.35,
    "adjunto_macro": 0.30,
    "adjunto_html": 0.20,
    "adjunto_contenedor": 0.10,
}

# Peso por defecto de una señal que aún no esté en la tabla. Se deja en cero a
# propósito: una señal nueva no debe alterar el score del baseline hasta que
# alguien decida su peso y lo documente.
PESO_DESCONOCIDO = 0.0


def evaluar_reglas(senales: list[Senal]) -> ResultadoReglas:
    """Suma los pesos de las señales presentes y satura el resultado en 1.0.

    La saturación por `min` —y no una sigmoide— es deliberada: mantiene el score
    explicable línea por línea ("estas cuatro reglas suman 0.95"), que es lo que
    el analista necesita ver y lo que se puede defender en la sustentación.

    Complejidad: O(n) sobre el número de señales.
    """
    total = 0.0
    disparadas: list[str] = []

    for senal in senales:
        peso = PESOS.get(senal.id, PESO_DESCONOCIDO)
        if peso > 0:
            total += peso
            disparadas.append(senal.id)

    # Orden descendente por peso: la explicación empieza por lo que más pesó.
    disparadas.sort(key=lambda id_senal: PESOS.get(id_senal, 0.0), reverse=True)

    return ResultadoReglas(score=min(1.0, round(total, 4)), reglas_disparadas=disparadas)
