# PhishGuard — Detección de phishing asistida por IA

Prototipo del **Seminario de Seguridad de la Información, 2026-2 — Grupo 3**.

Clasifica un correo como legítimo o phishing combinando tres fuentes: análisis
de enlaces y remitente, señales de ingeniería social, y el juicio de un modelo de
lenguaje sobre el pretexto del mensaje. El resultado siempre viene con la
explicación de en qué se basó.

Se usa de dos formas: como **extensión de navegador** sobre el correo abierto en
Gmail, o pegando un correo (o subiendo un `.eml`) en el popup.

> **Estado: inicio del desarrollo.** El pipeline corre de punta a punta, pero el
> componente de IA es hoy un **stub determinista, no un modelo**. Ningún número
> que produzca este prototipo es todavía un resultado del proyecto. Ver
> [Qué falta](#qué-falta).

---

## Cómo ejecutarlo

Requiere **Python 3.12+**. No hace falta clave de API ni conexión a internet.

### 1. Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Comprobar que respondió: <http://127.0.0.1:8000/api/v1/health>
Documentación interactiva de la API: <http://127.0.0.1:8000/docs>

### 2. Extensión

1. Abrir `chrome://extensions` en Chrome o Edge.
2. Activar **Modo de desarrollador**.
3. **Cargar descomprimida** → seleccionar la carpeta `extension/`.

No hay paso de compilación: la extensión es JavaScript plano, precisamente para
que se pueda cargar tal cual está en el repositorio.

### 3. Probarla

- **Sin Gmail:** clic en el icono de la extensión → pestaña **Ejemplos** → elegir
  cualquiera de los cinco escenarios de prueba. Es la vía recomendada para la
  sustentación.
- **Con Gmail:** abrir un correo en <https://mail.google.com> y pulsar el botón
  *Analizar con PhishGuard* abajo a la derecha.
- **Con un archivo:** pestaña **Pegar correo** → *Subir .eml*.

### Pruebas

```bash
cd backend
.venv\Scripts\python -m pytest -q
```

---

## Cómo funciona

```
                    ┌──────────────────────────────┐
  Gmail ───────────►│  Extensión (Chrome MV3)      │
  .eml / pegado ───►│  adaptador → service worker  │
                    └──────────────┬───────────────┘
                                   │ HTTP  POST /api/v1/analyze
                    ┌──────────────▼───────────────┐
                    │  Backend (FastAPI)           │
                    │                              │
                    │  1. Ingesta                  │
                    │  2. Extracción de señales     │
                    │       urls · remitente ·     │
                    │       social · adjuntos      │
                    │            ├──────────┐      │
                    │  3a. Reglas    3b. LLM       │
                    │       (baseline)  (pretexto) │
                    │            └────┬─────┘      │
                    │  4. Fusión ponderada         │
                    │  5. Veredicto explicado      │
                    └──────────────────────────────┘
```

La idea que organiza todo el diseño: **el código extrae y calcula; el modelo solo
juzga**. Sacar las URLs de un correo, leer el resultado de SPF o comparar dos
dominios es trabajo determinista y auditable, y dárselo a un modelo solo añade
una forma de equivocarse. Al modelo se le pide lo único que el código no sabe
hacer: decidir si la historia que cuenta el correo es creíble.

Detalle de las señales, los pesos y las limitaciones conocidas en
[`docs/arquitectura.md`](docs/arquitectura.md).

---

## Estructura

```
backend/
  app/
    schemas.py       Contratos de datos (lo que la extensión y los tests comparten)
    pipeline.py      El flujo completo, sin lógica de detección
    extractors/      urls · remitente · social · adjuntos
    baseline/        Reglas ponderadas — la línea base de la comparación
    llm/             port.py (interfaz) · stub.py (activo) · claude.py (sprint 4)
    fusion.py        Combina reglas + LLM y redacta la explicación
    eml.py           Ingesta de archivos .eml
    samples.py       Los cinco escenarios de prueba
    main.py          API HTTP
  tests/             76 pruebas
extension/
  manifest.json      Manifest V3
  content/           Adaptador de Gmail + overlay del veredicto
  background/        Service worker: el único que habla con el backend
  popup/             Pegar correo · subir .eml · ejemplos
docs/
  arquitectura.md    Decisiones de diseño y limitaciones conocidas
```

---

## Qué falta

Lo que hay hoy es el esqueleto con el baseline funcionando. Lo que falta,
siguiendo el cronograma de la presentación:

| Sprint | Pendiente |
|---|---|
| S2-S3 | Cargar los datasets de referencia (Nazario, SpamAssassin) y anotarlos. |
| S2-S3 | Calibrar los pesos de `baseline/rules.py` contra el conjunto de entrenamiento. Hoy están fijados por criterio, no ajustados. |
| S4 | Activar `app/llm/claude.py` (`PHISHGUARD_LLM=claude`) y afinar el prompt. |
| S5-S6 | Métricas: precisión, recall, F1, AUC y tasas de FP/FN frente al baseline. |
| S5-S6 | Calibrar `PESO_LLM` / `PESO_REGLAS` y los umbrales de la fusión. |
| — | Adaptador de Outlook Web, con la misma firma que el de Gmail. |

Lo que **no** entra, por alcance declarado: vishing y smishing, deepfakes,
entrenar un modelo desde cero, desplegar en un servidor de correo real y la
respuesta automática a incidentes.

---

## Aviso

Los correos de ejemplo son **sintéticos**, escritos para este trabajo. No
provienen de la bandeja de nadie y los dominios de atacante son inventados.

El servicio está pensado para correr en `127.0.0.1` durante el demo y **no tiene
autenticación**: publicarlo tal cual significaría aceptar correos ajenos en un
servicio abierto. Ese despliegue está fuera del alcance del proyecto.
