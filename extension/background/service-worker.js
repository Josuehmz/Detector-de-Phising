/**
 * Service worker: el único punto de la extensión que habla con el backend.
 *
 * Está centralizado aquí a propósito. Si el content script hiciera el `fetch`
 * directamente, la petición saldría desde el origen de mail.google.com y la
 * política de la propia página podría bloquearla; además habría que repetir la
 * misma lógica en el popup. Con un solo emisor, el permiso de host se declara
 * una vez y el resto de la extensión solo intercambia mensajes.
 */

const BACKEND_POR_DEFECTO = "http://127.0.0.1:8000";

/**
 * Techo de espera antes de dar la petición por perdida.
 *
 * Empezó en 30 s, que bastaban con el stub determinista. Dejó de bastar el
 * 2026-09-29, al conectar un modelo local por Ollama: en CPU un análisis tarda
 * entre 50 y 70 segundos, y la primera petición tras arrancar suma además la
 * carga del modelo en memoria. La extensión abortaba a los 30 s y acusaba al
 * backend de no responder cuando el backend estaba trabajando.
 *
 * Tres minutos cubren el caso lento con margen. Sigue habiendo techo a
 * propósito: sin él, un backend caído dejaría la interfaz en "Analizando…"
 * para siempre.
 */
const TIMEOUT_MS_POR_DEFECTO = 180000;

/** Lee la URL del backend configurada, o la de por defecto. */
async function urlBackend() {
  const guardado = await chrome.storage.local.get("backendUrl");
  return (guardado.backendUrl || BACKEND_POR_DEFECTO).replace(/\/+$/, "");
}

/** Techo de espera configurable, para quien corra un modelo aún más lento. */
async function timeoutMs() {
  const guardado = await chrome.storage.local.get("timeoutMs");
  const valor = Number(guardado.timeoutMs);
  return Number.isFinite(valor) && valor > 0 ? valor : TIMEOUT_MS_POR_DEFECTO;
}

/** `fetch` con límite de tiempo: sin esto una petición colgada nunca resuelve. */
async function fetchConTimeout(url, opciones = {}, techoMs) {
  const control = new AbortController();
  const limite = techoMs ?? TIMEOUT_MS_POR_DEFECTO;
  const temporizador = setTimeout(() => control.abort(), limite);
  try {
    return await fetch(url, { ...opciones, signal: control.signal });
  } finally {
    clearTimeout(temporizador);
  }
}

/**
 * Envía un correo al pipeline y devuelve el análisis.
 *
 * Los errores se devuelven como valor (`{ ok: false, error }`) y no como
 * excepción: quien llama es un content script al otro lado de un canal de
 * mensajes, donde una excepción se pierde y deja la interfaz en "analizando…"
 * para siempre.
 */
async function analizar(correo) {
  const base = await urlBackend();
  const techo = await timeoutMs();
  try {
    const respuesta = await fetchConTimeout(
      `${base}/api/v1/analyze`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(correo),
      },
      techo
    );

    if (!respuesta.ok) {
      const detalle = await respuesta.text();
      return { ok: false, error: `El backend respondió ${respuesta.status}: ${detalle.slice(0, 200)}` };
    }
    return { ok: true, analisis: await respuesta.json() };
  } catch (error) {
    if (error.name === "AbortError") {
      // La causa más probable no es que el backend esté caído, sino que esté
      // pensando: con un modelo local en CPU el análisis tarda de verdad.
      return {
        ok: false,
        error:
          `El backend no respondió en ${Math.round(techo / 1000)} s. Si está usando un ` +
          "modelo local, puede estar cargándolo en memoria o analizando todavía; " +
          "compruébalo en la consola del backend y vuelve a intentarlo.",
      };
    }
    return {
      ok: false,
      error: `No se pudo contactar el backend en ${base}. ¿Está corriendo? (${error.message})`,
    };
  }
}

/** Consulta el estado del backend, para avisar antes de que el usuario lo intente. */
async function estado() {
  const base = await urlBackend();
  try {
    // Techo corto y propio: `health` no analiza nada, así que si tarda es que no
    // está. Heredar los tres minutos del análisis dejaría el popup en blanco un
    // buen rato cada vez que el backend estuviera caído.
    const respuesta = await fetchConTimeout(`${base}/api/v1/health`, {}, 5000);
    if (!respuesta.ok) return { ok: false, error: `El backend respondió ${respuesta.status}.` };
    return { ok: true, salud: await respuesta.json() };
  } catch (error) {
    return { ok: false, error: `Backend no disponible en ${base}.` };
  }
}

const MANEJADORES = {
  analizar: (mensaje) => analizar(mensaje.correo),
  estado: () => estado(),
};

chrome.runtime.onMessage.addListener((mensaje, _emisor, responder) => {
  const manejador = MANEJADORES[mensaje?.tipo];
  if (!manejador) {
    responder({ ok: false, error: `Mensaje no reconocido: ${mensaje?.tipo}` });
    return false;
  }
  // `true` mantiene abierto el canal mientras la promesa se resuelve; sin él
  // Chrome cierra el puerto y la respuesta nunca llega.
  manejador(mensaje).then(responder);
  return true;
});
