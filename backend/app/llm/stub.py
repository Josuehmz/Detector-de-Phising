"""Clasificador de sustitución: determinista, sin red y sin clave de API.

ADVERTENCIA PARA EL INFORME
---------------------------
Este stub **no es un modelo de lenguaje**. Existe para que el pipeline completo
—extensión, API, fusión, explicación— se pueda ejecutar y probar hoy, antes del
sprint 4. Sus scores NO son resultados del proyecto y no deben aparecer en
ninguna tabla de métricas: cada respuesta suya lleva `es_stub=True`, y el
pipeline propaga esa marca hasta la respuesta de la API y la interfaz.

Cómo aproxima el juicio del modelo
----------------------------------
En vez de repetir la suma ponderada del baseline —lo que haría la comparación
inútil, porque ambos lados darían lo mismo— razona sobre **arquetipos de
pretexto**: qué historia cuenta el correo. Es una caricatura de lo que se le va
a pedir al modelo real, pero ejercita el mismo camino de código: emite un score
independiente del de las reglas y un razonamiento en prosa.
"""

from __future__ import annotations

from app.schemas import CorreoEntrada, ResultadoLLM, Senal

# Arquetipo -> (señales que lo caracterizan, cuántas hacen falta, score, relato).
# El orden importa: se evalúa de más específico a más genérico.
_ARQUETIPOS: tuple[tuple[str, frozenset[str], int, float, str], ...] = (
    (
        "BEC / fraude del CEO",
        frozenset(
            {
                "remitente_cargo_en_freemail",
                "social_confidencialidad",
                "social_financiera",
                "social_autoridad",
                "remitente_reply_to_distinto",
            }
        ),
        2,
        0.88,
        "El mensaje construye una relación de autoridad y pide una acción financiera "
        "evitando que la víctima consulte con un tercero. Es el guion del fraude del "
        "CEO: no necesita enlaces maliciosos porque el vector es la persona.",
    ),
    (
        "Robo de credenciales suplantando una marca",
        frozenset(
            {
                "url_texto_enganoso",
                "url_marca_fuera_del_dominio",
                "remitente_marca_sin_respaldo",
                "remitente_dominio_parecido",
                "social_credenciales",
            }
        ),
        2,
        0.90,
        "El correo se presenta como una marca conocida y dirige a un formulario de "
        "acceso alojado fuera del dominio de esa marca. El pretexto existe solo para "
        "justificar el clic.",
    ),
    (
        "Presión temporal con amenaza",
        frozenset({"social_urgencia", "social_amenaza", "social_credenciales"}),
        2,
        0.75,
        "El correo combina un plazo corto con una consecuencia negativa. La urgencia "
        "no es informativa: está puesta para impedir que la víctima verifique por "
        "otro canal.",
    ),
    (
        "Entrega de carga útil por adjunto",
        frozenset(
            {"adjunto_doble_extension", "adjunto_ejecutable", "adjunto_macro", "adjunto_html"}
        ),
        1,
        0.80,
        "El objetivo del mensaje es que se abra el adjunto; el texto solo aporta una "
        "excusa verosímil para hacerlo.",
    ),
    (
        "Cebo de premio o reembolso",
        frozenset({"social_premio", "url_acortador", "social_saludo_generico"}),
        2,
        0.65,
        "Ofrece un beneficio que la víctima no solicitó y oculta el destino del "
        "enlace. El saludo impersonal delata un envío masivo.",
    ),
)

# Correo sin ninguna señal fuerte: se parte de una base baja, no de cero, porque
# un clasificador que afirma "legítimo" con certeza absoluta no es honesto.
_BASE_SIN_SENALES = 0.08


class ClasificadorStub:
    """Implementación de `ClasificadorLLM` para desarrollo y pruebas."""

    nombre = "stub-determinista-v1"

    def clasificar(self, correo: CorreoEntrada, senales: list[Senal]) -> ResultadoLLM:
        """Elige el arquetipo de pretexto que mejor encaja con las señales.

        Complejidad: O(a * s) con `a` arquetipos (5, constante) y `s` señales.
        """
        ids_presentes = {senal.id for senal in senales}

        for etiqueta, marcadores, minimo, score, relato in _ARQUETIPOS:
            coincidencias = ids_presentes & marcadores
            if len(coincidencias) >= minimo:
                # Cada señal extra sobre el mínimo sube un poco la confianza, con techo.
                extra = 0.02 * (len(coincidencias) - minimo)
                return ResultadoLLM(
                    score=round(min(0.95, score + extra), 4),
                    razonamiento=f"Pretexto identificado: {etiqueta}. {relato}",
                    indicadores=sorted(coincidencias),
                    modelo=self.nombre,
                    es_stub=True,
                )

        # Sin arquetipo: las señales sueltas mueven poco la aguja.
        score = round(min(0.45, _BASE_SIN_SENALES + 0.07 * len(ids_presentes)), 4)
        if ids_presentes:
            razonamiento = (
                "No se reconoce un pretexto de phishing completo. Hay indicadores "
                "aislados, pero no forman la estructura de un engaño dirigido."
            )
        else:
            razonamiento = (
                "El correo no presenta indicadores de manipulación, suplantación ni "
                "enlaces sospechosos."
            )

        return ResultadoLLM(
            score=score,
            razonamiento=razonamiento,
            indicadores=sorted(ids_presentes),
            modelo=self.nombre,
            es_stub=True,
        )
