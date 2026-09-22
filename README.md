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

- **Sin webmail:** clic en el icono de la extensión → pestaña **Ejemplos** →
  elegir cualquiera de los cinco escenarios de prueba. Es la vía recomendada
  para la sustentación.
- **Con un webmail:** abrir un correo y pulsar el botón *Analizar con
  PhishGuard* abajo a la derecha. Ver los proveedores soportados más abajo.
- **Con un archivo:** pestaña **Pegar correo** → *Subir .eml*.

### 4. Activar el modelo real (opcional)

Por defecto el pipeline usa el **stub determinista** y no necesita clave ni red.
Para usar el modelo de verdad:

```bash
export ANTHROPIC_API_KEY=...        # setx en Windows, o `ant auth login`
export PHISHGUARD_LLM=claude
```

| Variable | Por defecto | Para qué |
|---|---|---|
| `PHISHGUARD_LLM` | `stub` | `claude` activa el adaptador real |
| `PHISHGUARD_MODELO` | `claude-opus-5` | Id del modelo |
| `PHISHGUARD_MAX_TOKENS` | `16000` | Techo de la respuesta. Los tokens de razonamiento salen de aquí: un valor bajo trunca en vez de ahorrar |
| `PHISHGUARD_EFFORT` | *(sin definir)* | `low`…`max`. La palanca de costo. **Elegirla midiendo**, no por intuición |
| `PHISHGUARD_FALLBACK` | *(apagado)* | `1` activa el respaldo del servidor ante un rechazo. Apagado a propósito: mezclaría dos modelos en la evaluación, y la API de lotes lo rechaza |

**Si no hay credencial, el arranque lo avisa** y cada análisis devuelve
`sin_juicio`: el veredicto sale solo del baseline y la respuesta lo dice. No hay
forma de creer que la IA está encendida cuando no lo está.

**Cuando el modelo no juzga, no se inventa un veredicto.** Hay tres casos —el
modelo declina el correo, la respuesta se trunca, o la API falla— y los tres
marcan `llm.sin_juicio` con su motivo. La fusión entonces **ignora el score del
modelo** en vez de meter un 0 en la suma ponderada, que arrastraría el veredicto
hacia «legítimo» por algo que el modelo nunca dijo.

### Webmails soportados

| Proveedor | Hosts | Selectores verificados |
|---|---|---|
| Gmail | `mail.google.com` | no |
| Outlook / Hotmail / Live / MSN / M365 | `outlook.live.com`, `outlook.office.com`, `outlook.office365.com`, `outlook.cloud.microsoft` | no |
| Yahoo Mail | `mail.yahoo.com` y subdominios regionales | no |
| Proton Mail | `mail.proton.me` | no |

**«Verificados: no» hay que leerlo literalmente.** Los selectores están escritos
a partir de la estructura conocida de cada producto, pero **ninguno se ha
comprobado contra la página real**. El dato viaja en el código
(`verificado: false` en cada perfil) y llega hasta la interfaz: el panel del
veredicto dice con qué adaptador se extrajo el correo y si está sin verificar.
Mientras eso siga así, un fallo de extracción es tan probable que sea de
nuestros selectores como de un cambio del webmail, y el panel de error también
lo advierte.

Una cuenta `@hotmail.com`, `@live.com` o `@msn.com` no necesita entrada propia:
inicia sesión y termina servida desde `outlook.live.com`, con el mismo DOM.

**Añadir un proveedor** son dos pasos: un archivo en
`extension/content/proveedores/` con sus hosts y sus cinco listas de selectores,
y añadirlo al `manifest.json` (en `matches` y en `js`). Las pruebas fallan si se
hace solo una de las dos cosas.

### Pruebas

```bash
cd backend
.venv\Scripts\python -m pytest -q          # 92 pruebas: pipeline + adaptador de Claude
```

```bash
cd extension
node --test tests/proveedores.test.mjs     # 9 pruebas del enrutado de webmails
```

Las pruebas de la extensión no necesitan instalar nada (usan `node --test`, sin
dependencias) y cubren **a qué perfil se asigna cada host**, no los selectores:
un selector solo se puede validar contra la página real del webmail.

---

## Cómo funciona

```
  Gmail · Outlook   ┌──────────────────────────────┐
  Yahoo · Proton ──►│  Extensión (Chrome MV3)      │
  .eml / pegado ───►│  perfil → adaptador → worker │
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
    llm/             port.py (interfaz) · stub.py (por defecto) · claude.py (modelo real)
    fusion.py        Combina reglas + LLM y redacta la explicación
    eml.py           Ingesta de archivos .eml
    samples.py       Los cinco escenarios de prueba
    main.py          API HTTP
  tests/             92 pruebas (16 del adaptador de Claude, ninguna usa red)
extension/
  manifest.json      Manifest V3
  content/
    adaptador-comun.js   Motor: prueba selectores, arma el `From`, diagnostica
    proveedores/         Un archivo por webmail: hosts + selectores
    adaptador.js         Elige el perfil según el host
    overlay.js           Botón y panel del veredicto (no sabe en qué webmail está)
  background/        Service worker: el único que habla con el backend
  popup/             Pegar correo · subir .eml · ejemplos
  tests/             9 pruebas del enrutado de proveedores
docs/
  arquitectura.md            Decisiones de diseño y limitaciones conocidas
  guion-implementacion-ia.md Guion para explicar el componente de IA
```

---

## Qué falta

Lo que hay hoy es el esqueleto con el baseline funcionando. Lo que falta,
siguiendo el cronograma de la presentación:

| Sprint | Pendiente |
|---|---|
| S2-S3 | Cargar los datasets de referencia (Nazario, SpamAssassin) y anotarlos. |
| S2-S3 | Calibrar los pesos de `baseline/rules.py` contra el conjunto de entrenamiento. Hoy están fijados por criterio, no ajustados. |
| S4 | ~~Escribir el adaptador real~~ **hecho el 2026-09-22**: `app/llm/claude.py` maneja el rechazo del modelo, el truncamiento y el fallo de API por separado, y tiene 16 pruebas sin red. Queda **afinar el prompt contra casos reales** y **elegir `PHISHGUARD_EFFORT` midiendo** sobre una muestra, no por intuición. |
| S5-S6 | Declarar en el informe que **`temperature` ya no se puede fijar**: los resultados con LLM no son reproducibles bit a bit. Mitigación: guardar las respuestas crudas del modelo junto al id de cada correo, para que el análisis sea auditable aunque la ejecución no se repita. |
| S5-S6 | Métricas: precisión, recall, F1, AUC y tasas de FP/FN frente al baseline. |
| S5-S6 | Calibrar `PESO_LLM` / `PESO_REGLAS` y los umbrales de la fusión. |
| — | **Comprobar los selectores de los cuatro webmails contra la página real** y poner `verificado: true` en los perfiles que pasen. Es lo único que hoy separa el soporte multi-dominio de ser utilizable de verdad. |

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
