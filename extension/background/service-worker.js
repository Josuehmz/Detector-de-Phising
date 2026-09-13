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

// El análisis puede tardar si detrás hay un modelo real; 30 s es el techo antes
// de decirle al usuario que algo va mal, en vez de dejar la interfaz colgada.
const TIMEOUT_MS = 30000;

/** Lee la URL del backend configurada, o la de por defecto. */
async function urlBackend() {
  const guardado = await chrome.storage.local.get("backendUrl");
  return (guardado.backendUrl || BACKEND_POR_DEFECTO).replace(/\/+$/, "");
}

/** `fetch` con límite de tiempo: sin esto una petición colgada nunca resuelve. */
async function fetchConTimeout(url, opciones = {}) {
  const control = new AbortController();
  const temporizador = setTimeout(() => control.abort(), TIMEOUT_MS);
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
  try {
    const respuesta = await fetchConTimeout(`${base}/api/v1/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(correo),
    });

    if (!respuesta.ok) {
      const detalle = await respuesta.text();
      return { ok: false, error: `El backend respondió ${respuesta.status}: ${detalle.slice(0, 200)}` };
    }
    return { ok: true, analisis: await respuesta.json() };
  } catch (error) {
    if (error.name === "AbortError") {
      return { ok: false, error: `El backend no respondió en ${TIMEOUT_MS / 1000} s.` };
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
    const respuesta = await fetchConTimeout(`${base}/api/v1/health`);
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
