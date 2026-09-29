# Laboratorio — Diseño y validación de prompts para la comprensión del problema

**Proyecto:** PhishGuard — detección de phishing asistida por IA
**Seminario de Seguridad de la Información, 2026-2 — Grupo 3**
**Fecha:** 2026-09-23 · **Modelo:** Claude Opus 5

> Los prompts se ejecutaron de verdad. Se conserva el primer intento aunque
> salió pobre: sin él no hay evidencia de mejora, que es el 30 % de la rúbrica.

## Etapa 1 — Investigación del problema

### Prompt inicial (v1)

```
Actúa como analista de mercado. Quiero investigar el problema del phishing
por correo electrónico. Responde: ¿qué datos o evidencias existen?, ¿a quiénes
afecta?, ¿qué causas lo generan?, ¿qué soluciones existen y por qué no bastan?
```

### Respuesta (v1), resumida

> El phishing es una de las formas más extendidas de ciberdelito y ha mostrado
> un crecimiento sostenido. La mayoría de las brechas involucra el factor humano
> y el correo sigue siendo el canal preferido. Afecta a organizaciones de todos
> los tamaños y a usuarios individuales: empresas, bancos, hospitales,
> universidades y ciudadanos. Las causas principales son la falta de conciencia
> de los usuarios, la sofisticación creciente de los atacantes y el uso de la
> urgencia como palanca. Existen filtros antispam, listas negras, autenticación
> del remitente (SPF, DKIM, DMARC) y capacitaciones; no bastan porque los
> atacantes se adaptan rápido y basta con que un usuario caiga.

### Validación: por qué no sirve

| Defecto | Consecuencia |
|---|---|
| Ni una cifra con fuente | Nada citable. "Crecimiento sostenido" es una impresión, no un dato |
| Sin recorte geográfico | Un proyecto en Colombia no se sustenta con un promedio mundial |
| "Afecta a todos" | Un usuario que incluye a todos no define a nadie: no se puede diseñar |
| "Falta de conciencia" | Culpa al usuario y no señala ninguna palanca de diseño |
| El porqué del fracaso es circular | "Se adaptan" no dice **qué** deja pasar cada control |

De fondo: el prompt pedía un panorama y eso devolvió. El rol "analista de
mercado" encuadró el phishing como oportunidad comercial, no como fenómeno
técnico medible.

### Prompt refinado (v2)

```
Actúa como analista de amenazas de correo electrónico. Contexto: proyecto
universitario en Colombia que construye un detector de phishing asistido por
IA, usado por una persona sin formación técnica sobre el correo que acaba de
abrir en su webmail.

Responde en máximo 10 líneas, en lista, con estas reglas:
1. Cada cifra con su fuente y su año. Si no tienes fuente citable para un dato,
   dilo explícitamente en vez de estimarlo.
2. Distingue las cifras de informe primario (DBIR, APWG, estudio académico) de
   las de prensa o proveedor con interés comercial.
3. Separa el dato global del colombiano; no los mezcles en una afirmación.
4. En causas, NO incluyas "falta de conciencia del usuario": quiero causas
   sobre las que un software pueda actuar.
5. En soluciones existentes, di el mecanismo concreto por el que cada una
   falla, no que "los atacantes se adaptan".
```

Cinco cambios: rol comercial → técnico; **usuario concreto**; geografía
acotada; **fuente y año con permiso de decir "no sé"** (la contramedida contra
cifras inventadas); y prohibición de la causa-comodín.

### Respuesta (v2)

**Global, fuentes primarias**

- **Verizon DBIR 2026:** el **62 %** de las brechas involucró el factor humano;
  la ingeniería social es el tercer patrón, con el **16 %**, sobre más de 22.000
  brechas confirmadas.
- **APWG:** **1.069.681 ataques** en el 2.º trimestre de 2026 (+10,1 % frente al
  anterior) y **83.951 campañas de correo únicas** frente a 35.583 en el
  trimestre previo. Lo que más crece no es el volumen: es la **variedad**.
- **Heiding, Schneier y Vishwanath (HBR, 2024):** **54 % de clics** en
  spear-phishing automatizado con IA, frente al **12 %** del phishing masivo.

**Colombia, prensa secundaria — verificar antes de citar**

- Se reporta un **aumento del 16 %** en phishing en el primer semestre de 2026 y
  más de **13.000 incidentes** de la DIJIN en 2025. *Son notas de prensa, no el
  informe original; hay que conseguir el boletín del CAI Virtual o el SAFE del
  TicTac.* No tengo fuente primaria colombiana verificada.

**Usuario afectado (el específico)** — la persona que decide sola y en segundos,
sin equipo de seguridad detrás: empleado de pyme, docente, estudiante.

**Causas sobre las que un software puede actuar**

- El correo llega **sin señales visibles**: no se ve el dominio real del enlace,
  ni si SPF/DKIM pasaron, ni si el dominio se registró ayer.
- El veredicto del filtro es **binario y opaco**: si algo pasó, el usuario asume
  que es legítimo y nada le explica por qué.
- La **urgencia del pretexto** es evaluable como texto y hoy no se evalúa.

**Por qué no alcanza lo que existe, con el mecanismo del fallo**

- **Reputación y listas negras:** puntúan dominios *conocidos*. Un dominio
  registrado hace horas no tiene mala reputación: **no tiene ninguna**, y pasa.
- **SPF/DKIM/DMARC:** autentican que el remitente es quien dice ser, no que sea
  honesto. `micro-soft-support.com` los pasa los tres con configuración perfecta.
- **Reglas por palabras clave:** un texto generado por IA no repite plantillas
  conocidas, así que no hay firma que coincidir.
- **Capacitación:** ocurre semanas antes y no está presente en el momento de
  decidir, que es cuando hace falta.

## Etapa 2 — Objetivo de la app

### Prompt

```
Con base en esta investigación [resumen: el usuario decide solo y en segundos;
los controles fallan porque puntúan reputación conocida, autentican al remitente
pero no su honestidad, y dan un veredicto opaco], redacta el objetivo principal
de la aplicación: una sola frase, clara, medible y centrada en el usuario. No
uses "mejorar la seguridad" ni "concientizar": nómbrame qué hace la persona, en
qué momento, y con qué cifra se sabría si funcionó.
```

### Primera versión y su validación

> **v1:** "Desarrollar una herramienta con IA que detecte correos de phishing y
> proteja a los usuarios de fraudes electrónicos."

| Criterio | ¿Cumple? | Por qué |
|---|---|---|
| Claridad | Sí | Describe el producto, no el resultado |
| Relevancia | Parcial | El sistema entrega un juicio; la decisión sigue siendo del usuario |
| Medibilidad | **No** | Ninguna cifra ni instrumento |
| Enfoque en usuario | **No** | El sujeto es la herramienta, no la persona |

### Prompt de mejora

```
Mejora este objetivo para que sea más claro y medible. Dame 3 alternativas,
cada una con un instrumento distinto: la decisión del usuario, el desempeño del
clasificador, y la comprensión de la explicación. Máximo 40 palabras cada una.
```

1. *(decisión)* Que una persona sin formación técnica decida correctamente si el
   correo abierto es phishing, subiendo su acierto sobre un conjunto de prueba
   del 60 % sin la herramienta a al menos 85 % con ella.
2. *(clasificador)* Clasificar con menos del 5 % de falsos positivos, condición
   para que el usuario no aprenda a ignorar las alertas.
3. *(explicación)* Entregar con cada veredicto las señales que lo sustentan, de
   modo que 8 de cada 10 usuarios puedan decir en sus palabras por qué el
   sistema desconfió.

**Por qué la primera como base:** la segunda mide el modelo, y un AUC alto con
el usuario ignorando la alerta no resuelve nada; la tercera mide lo que
distingue a PhishGuard pero deja fuera el resultado. La final toma el esqueleto
de la primera y le suma la explicación de la tercera, porque aquí la explicación
**es** el mecanismo por el que sube el acierto.

### Objetivo final

> **Ayudar a una persona sin formación técnica a decidir, sobre el correo que
> tiene abierto y en menos de treinta segundos, si es phishing —entregándole un
> veredicto con las señales que lo sustentan—, de modo que su tasa de acierto
> pase del 60 % sin la herramienta a un mínimo del 85 % con ella, con menos del
> 5 % de falsos positivos.**

Claridad: dice quién, sobre qué, cuándo y con qué ayuda. Relevancia: ataca las
tres causas accionables. Medibilidad: acierto (60 % → 85 %), tiempo (30 s) y
falsos positivos (< 5 %). Usuario: el sujeto es la persona; el software es el
medio.

> **Pendiente honesto:** el 60 % de línea base es **un supuesto, no una
> medición**. Hay que establecerlo con la misma prueba que después mida el 85 %,
> o el objetivo no es verificable. Es el primer experimento del proyecto.

## Reflexión

Aprendí que el prompt no falla por falta de detalle sino por lo que da por
sentado: el rol "analista de mercado" encuadró el phishing como oportunidad
comercial y esa decisión invisible contaminó toda la respuesta. Lo que más subió
la calidad fue **autorizar al modelo a decir "no tengo fuente para eso"**, porque
sin ese permiso rellena el hueco con una cifra creíble. Prohibir la respuesta
cómoda —"falta de conciencia del usuario"— obligó a causas sobre las que sí
puedo programar. Y el objetivo mejoró cuando dejó de describir el producto y
pasó a describir la decisión de una persona, con un número al lado.

## Fuentes

[Verizon DBIR 2026](https://www.verizon.com/business/resources/reports/dbir/) ·
[APWG Trends Q1 2026](https://docs.apwg.org/reports/apwg_trends_report_q1_2026.pdf)
y [trimestrales](https://apwg.org/trendsreports) · Heiding, Schneier y
Vishwanath, HBR 2024 ·
Colombia, prensa sin verificar:
[Portafolio](https://www.portafolio.co/tecnologia/ciberestafas-crecen-en-colombia-tiendas-falsas-phishing-y-soporte-tecnico-son-nuevas-amenazas-498284)
