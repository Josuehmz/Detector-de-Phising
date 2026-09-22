/**
 * Popup: la vía de análisis que no depende de ningún webmail.
 *
 * Existe por tres razones, en orden de importancia:
 *  1. Es el plan B cuando un adaptador se rompe por un cambio de DOM.
 *  2. Permite analizar un `.eml` de los datasets de referencia sin abrir nada.
 *  3. Es lo que se demuestra en la sustentación: no depende de tener una cuenta
 *     de un webmail con un correo de phishing a mano.
 *
 * Como en el overlay, el resultado se pinta con `textContent`: parte de lo que
 * se muestra es contenido del correo analizado, es decir, entrada no confiable.
 */

const BACKEND_POR_DEFECTO = "http://127.0.0.1:8000";

const ETIQUETAS = {
  phishing: { texto: "Phishing", clase: "phishing" },
  sospechoso: { texto: "Sospechoso", clase: "sospechoso" },
  legitimo: { texto: "Sin indicios", clase: "legitimo" },
};

const $ = (id) => document.getElementById(id);

function crear(etiqueta, clase, texto) {
  const el = document.createElement(etiqueta);
  if (clase) el.className = clase;
  if (texto !== undefined) el.textContent = texto;
  return el;
}

// --------------------------------------------------------------- Backend

async function urlBackend() {
  const guardado = await chrome.storage.local.get("backendUrl");
  return (guardado.backendUrl || BACKEND_POR_DEFECTO).replace(/\/+$/, "");
}

async function comprobarEstado() {
  const estado = $("estado");
  const respuesta = await chrome.runtime.sendMessage({ tipo: "estado" });

  if (!respuesta?.ok) {
    estado.textContent = "backend no disponible";
    estado.className = "estado malo";
    return;
  }

  // Que el clasificador sea un stub es la información más importante de toda la
  // interfaz: sin ella alguien podría tomar estos veredictos por resultados.
  const { clasificador, llm_es_stub: esStub } = respuesta.salud;
  estado.textContent = esStub ? `conectado · ${clasificador} (stub)` : `conectado · ${clasificador}`;
  estado.className = esStub ? "estado aviso" : "estado bueno";
}

// -------------------------------------------------------------- Resultado

function mostrarTexto(texto, clase = "") {
  const caja = $("resultado");
  caja.className = "resultado";
  caja.replaceChildren(crear("p", clase, texto));
}

function mostrarAnalisis(analisis) {
  const caja = $("resultado");
  caja.className = "resultado";
  caja.replaceChildren();

  const etiqueta = ETIQUETAS[analisis.veredicto] || ETIQUETAS.sospechoso;

  const veredicto = crear("div", `veredicto ${etiqueta.clase}`);
  veredicto.appendChild(crear("strong", null, etiqueta.texto));
  veredicto.appendChild(crear("span", "score", `riesgo ${Math.round(analisis.score * 100)}%`));
  caja.appendChild(veredicto);

  for (const aviso of analisis.advertencias || []) {
    caja.appendChild(crear("p", "aviso", aviso));
  }

  caja.appendChild(crear("p", "explicacion", analisis.explicacion));

  if (analisis.senales?.length) {
    const detalle = document.createElement("details");
    detalle.appendChild(crear("summary", null, `Señales (${analisis.senales.length})`));
    const lista = crear("ul", "senales");
    for (const senal of analisis.senales) {
      const item = crear("li", `sev-${senal.severidad}`, senal.descripcion);
      if (senal.evidencia?.length) {
        item.appendChild(crear("code", null, senal.evidencia.join(" · ")));
      }
      lista.appendChild(item);
    }
    detalle.appendChild(lista);
    caja.appendChild(detalle);
  }

  caja.appendChild(
    crear(
      "p",
      "pie",
      `reglas ${analisis.reglas.score.toFixed(2)} · IA ${analisis.llm.score.toFixed(
        2
      )} · acuerdo ${analisis.confianza.toFixed(2)}`
    )
  );
}

// ----------------------------------------------------------------- Acciones

async function analizarPegado() {
  const correo = {
    asunto: $("asunto").value.trim(),
    remitente: $("remitente").value.trim(),
    cuerpo_texto: $("cuerpo").value,
    origen: "popup",
  };

  if (!correo.asunto && !correo.cuerpo_texto && !correo.remitente) {
    mostrarTexto("Pega al menos el cuerpo del correo.", "error");
    return;
  }

  mostrarTexto("Analizando…");
  const respuesta = await chrome.runtime.sendMessage({ tipo: "analizar", correo });
  if (respuesta?.ok) mostrarAnalisis(respuesta.analisis);
  else mostrarTexto(respuesta?.error || "Error desconocido.", "error");
}

/**
 * El `.eml` se sube directo desde el popup, sin pasar por el service worker.
 *
 * Es la excepción a "solo el service worker habla con el backend": un `FormData`
 * con un `File` no sobrevive a `chrome.runtime.sendMessage`, que serializa a JSON
 * y convertiría el archivo en un objeto vacío. El popup ya corre en el origen de
 * la extensión, así que el permiso de host aplica igual.
 */
async function analizarEml(archivo) {
  mostrarTexto(`Analizando ${archivo.name}…`);

  const formulario = new FormData();
  formulario.append("archivo", archivo);

  try {
    const respuesta = await fetch(`${await urlBackend()}/api/v1/analyze/eml`, {
      method: "POST",
      body: formulario,
    });
    if (!respuesta.ok) {
      const detalle = await respuesta.json().catch(() => ({}));
      mostrarTexto(detalle.detail || `El backend respondió ${respuesta.status}.`, "error");
      return;
    }
    mostrarAnalisis(await respuesta.json());
  } catch (error) {
    mostrarTexto(`No se pudo contactar el backend: ${error.message}`, "error");
  }
}

async function cargarEjemplos() {
  const lista = $("lista-ejemplos");
  try {
    const respuesta = await fetch(`${await urlBackend()}/api/v1/samples`);
    const ejemplos = await respuesta.json();

    lista.replaceChildren();
    for (const ejemplo of ejemplos) {
      const item = document.createElement("li");
      const boton = crear("button", "ejemplo");
      boton.appendChild(crear("span", "escenario", ejemplo.escenario));
      boton.appendChild(crear("span", "asunto-ejemplo", ejemplo.asunto || "(sin asunto)"));
      boton.addEventListener("click", () => analizarEjemplo(ejemplo.id));
      item.appendChild(boton);
      lista.appendChild(item);
    }
  } catch {
    lista.replaceChildren(crear("li", "error", "No se pudieron cargar los ejemplos."));
  }
}

async function analizarEjemplo(id) {
  mostrarTexto("Analizando…");
  try {
    const respuesta = await fetch(`${await urlBackend()}/api/v1/samples/${id}`);
    if (!respuesta.ok) {
      mostrarTexto(`El backend respondió ${respuesta.status}.`, "error");
      return;
    }
    mostrarAnalisis(await respuesta.json());
  } catch (error) {
    mostrarTexto(`No se pudo contactar el backend: ${error.message}`, "error");
  }
}

// -------------------------------------------------------------------- Arranque

function activarPestanas() {
  for (const pestana of document.querySelectorAll(".pestana")) {
    pestana.addEventListener("click", () => {
      for (const otra of document.querySelectorAll(".pestana")) {
        otra.classList.toggle("activa", otra === pestana);
      }
      $("panel-pegar").classList.toggle("oculto", pestana.dataset.panel !== "pegar");
      $("panel-ejemplos").classList.toggle("oculto", pestana.dataset.panel !== "ejemplos");
      if (pestana.dataset.panel === "ejemplos") cargarEjemplos();
    });
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  $("backend").value = await urlBackend();
  $("backend").addEventListener("change", async (evento) => {
    await chrome.storage.local.set({ backendUrl: evento.target.value.trim() });
    comprobarEstado();
  });

  $("analizar").addEventListener("click", analizarPegado);
  $("eml").addEventListener("change", (evento) => {
    const archivo = evento.target.files?.[0];
    if (archivo) analizarEml(archivo);
  });

  activarPestanas();
  comprobarEstado();
});
