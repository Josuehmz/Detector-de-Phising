"""Señales de ingeniería social en el texto del correo.

Esta es la dimensión que el proyecto apuesta a que un LLM hará mejor que las
reglas. El detector léxico de este módulo es deliberadamente literal: busca
frases hechas. Sirve como **baseline** — es lo que un filtro tradicional puede
ver — y su techo es justamente lo que se quiere medir, porque un correo escrito
con IA evita estas frases y aun así manipula.

Cubre español e inglés, que es el alcance declarado del prototipo.
"""

from __future__ import annotations

import re

from app.schemas import Senal, Severidad

# Cada entrada: id de señal -> (severidad, descripción, patrones).
# Los patrones van sin acentos obligatorios donde el usuario suele omitirlos.
_CATEGORIAS: dict[str, tuple[Severidad, str, tuple[str, ...]]] = {
    "social_urgencia": (
        Severidad.MEDIA,
        "El correo presiona con un plazo corto para que la víctima no verifique.",
        (
            r"\b(?:en|dentro de|antes de)\s+(?:las\s+)?\d+\s*(?:horas?|h|minutos?|d[ií]as?)\b",
            r"\binmediatamente\b", r"\bde inmediato\b", r"\burgente\b", r"\bcuanto antes\b",
            r"\bhoy mismo\b", r"\b[uú]ltimo aviso\b", r"\bvence hoy\b", r"\bexpira (?:hoy|en)\b",
            r"\bimmediately\b", r"\burgent\b", r"\bright away\b", r"\bas soon as possible\b",
            r"\bexpires? (?:today|in|within)\b", r"\bfinal notice\b", r"\bwithin \d+ hours?\b",
        ),
    ),
    "social_amenaza": (
        Severidad.ALTA,
        "El correo anuncia una consecuencia negativa si la víctima no actúa.",
        (
            r"\b(?:ser[áa]|sera|quedar[áa])\s+(?:suspendid[oa]|bloquead[oa]|cancelad[oa]|desactivad[oa]|eliminad[oa])\b",
            r"\bsuspensi[óo]n (?:de|permanente)\b", r"\bperder[áa]s? (?:el )?acceso\b",
            r"\bcierre de (?:su )?cuenta\b", r"\bsanci[óo]n\b", r"\bmulta\b", r"\bproceso legal\b",
            r"\b(?:will be|has been) (?:suspended|blocked|disabled|terminated|closed|deleted)\b",
            r"\blose access\b", r"\bpermanent(?:ly)? (?:suspend|clos)\w*\b", r"\blegal action\b",
        ),
    ),
    "social_credenciales": (
        Severidad.ALTA,
        "El correo pide datos de acceso o verificación de identidad.",
        (
            # Se buscan raíces y no formas exactas: el mismo pretexto aparece como
            # "verifique", "verifica", "confirmen", "actualizar". Fijar la conjugación
            # dejaba pasar la mitad de los casos.
            r"\b(?:verif\w+|confirm\w+|actualic\w+|actualiz\w+|valid\w+|reactiv\w+)\s+"
            r"(?:su|tu|sus|tus)\s+"
            r"(?:cuenta|contrase[ñn]a|clave|identidad|informaci[óo]n|datos|credenciales)\b",
            r"\biniciar? sesi[óo]n\b(?=.{0,80}\b(?:aqu[ií]|enlace|aqui)\b)",
            r"\bingrese (?:su|tu) (?:contrase[ñn]a|clave|usuario|c[óo]digo)\b",
            r"\b(?:verify|confirm|update|validate|reactivate)\s+your\s+"
            r"(?:account|password|identity|information|details|credentials)\b",
            r"\bsign in (?:here|now|to)\b", r"\benter your (?:password|credentials|pin)\b",
        ),
    ),
    "social_financiera": (
        Severidad.ALTA,
        "El correo solicita un movimiento de dinero o cambia datos de pago (patrón de BEC).",
        (
            r"\btransferencia (?:bancaria|urgente|inmediata)?\b", r"\bpago (?:urgente|pendiente|inmediato)\b",
            r"\bdatos bancarios\b", r"\bnueva cuenta bancaria\b",
            r"\bactualizar? (?:los )?datos de pago\b", r"\btarjeta de regalo\b", r"\bgift ?cards?\b",
            r"\bfactura adjunta\b", r"\bwire transfer\b", r"\bbank(?:ing)? details? (?:change|update)\b",
            r"\bnew bank account\b", r"\bprocess (?:this|the) payment\b", r"\boverdue invoice\b",
        ),
    ),
    "social_confidencialidad": (
        Severidad.ALTA,
        "El correo pide secreto, lo que impide que la víctima consulte con un tercero.",
        (
            r"\bno (?:le )?(?:comente|comentes|diga|digas|informe)\b",
            r"\bconfidencial\b", r"\bentre nosotros\b", r"\bdiscreci[óo]n\b",
            r"\bno responda por (?:otro|este) medio\b", r"\bno me llames?\b",
            r"\bkeep (?:this|it) (?:confidential|between us|quiet)\b",
            r"\bdo(?:n't| not) (?:tell|discuss|mention)\b", r"\bstrictly confidential\b",
        ),
    ),
    "social_saludo_generico": (
        Severidad.BAJA,
        "El saludo no identifica al destinatario: señal de envío masivo.",
        (
            r"\b(?:estimado|querido|apreciado)\s+(?:cliente|usuario|se[ñn]or|miembro|titular)\b",
            r"\bdear\s+(?:customer|user|client|member|sir|madam|account holder)\b",
            r"\bhola\s+(?:usuario|cliente)\b",
        ),
    ),
    "social_premio": (
        Severidad.MEDIA,
        "El correo ofrece un beneficio inesperado para motivar el clic.",
        (
            r"\bha (?:sido )?(?:ganado|ganador|seleccionado|premiado)\b", r"\bpremio\b",
            r"\breembolso (?:pendiente|disponible|aprobado)\b", r"\bdevoluci[óo]n de impuestos\b",
            r"\byou(?:'ve| have) won\b", r"\bclaim your (?:prize|reward|refund)\b",
            r"\btax refund\b", r"\bfree gift\b",
        ),
    ),
    "social_autoridad": (
        Severidad.MEDIA,
        "El texto invoca una autoridad interna o institucional para no ser cuestionado.",
        (
            r"\b(?:soy|habla) el (?:ceo|gerente|director|presidente)\b",
            r"\bdepartamento de (?:sistemas|ti|it|seguridad|n[óo]mina)\b",
            r"\bmesa de ayuda\b", r"\bsoporte t[ée]cnico\b", r"\badministrador del sistema\b",
            r"\bthis is (?:the )?(?:ceo|cfo|your manager)\b", r"\bit (?:department|helpdesk)\b",
            r"\bsystem administrator\b",
        ),
    ),
}

# Se compilan una vez al importar: el módulo se llama por cada correo analizado.
_COMPILADOS: dict[str, tuple[Severidad, str, tuple[re.Pattern[str], ...]]] = {
    id_senal: (severidad, descripcion, tuple(re.compile(p, re.IGNORECASE) for p in patrones))
    for id_senal, (severidad, descripcion, patrones) in _CATEGORIAS.items()
}


def extraer_senales_sociales(asunto: str, cuerpo: str) -> list[Senal]:
    """Busca frases de manipulación en el asunto y el cuerpo.

    El asunto se analiza junto al cuerpo porque es donde más se concentra la
    urgencia, pero se marca en la evidencia para que el analista sepa de dónde
    salió cada coincidencia.
    """
    fragmentos = [("asunto", asunto or ""), ("cuerpo", cuerpo or "")]
    senales: list[Senal] = []

    for id_senal, (severidad, descripcion, patrones) in _COMPILADOS.items():
        evidencia: list[str] = []
        for origen, texto in fragmentos:
            if not texto:
                continue
            for patron in patrones:
                for encontrado in patron.finditer(texto):
                    marca = f"[{origen}] {encontrado.group(0).strip()}"
                    if marca not in evidencia:
                        evidencia.append(marca)
                    # Una coincidencia por patrón basta: el peso de la señal no
                    # depende de cuántas veces se repita la misma frase.
                    break
        if evidencia:
            senales.append(
                Senal(
                    id=id_senal,
                    categoria="ingenieria_social",
                    descripcion=descripcion,
                    severidad=severidad,
                    evidencia=evidencia[:5],
                )
            )

    return senales
