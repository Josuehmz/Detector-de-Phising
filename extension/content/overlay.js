/**
 * Interfaz dentro de Gmail: el botón de análisis y el panel de resultado.
 *
 * Dos decisiones de diseño que conviene poder sustentar:
 *
 * 1. **El análisis se dispara con un clic, nunca solo.** Analizar cada correo al
 *    abrirlo significaría enviar toda la bandeja de entrada a un servicio
 *    externo sin que nadie lo pida. Para una herramienta de seguridad eso es
 *    inaceptable: el usuario decide qué mensaje sale de su cliente de correo.
 *
 * 2. **Todo el contenido se inserta con `textContent`, nunca con `innerHTML`.**
 *    El panel muestra fragmentos del correo analizado como evidencia, y ese
 *    correo es entrada del atacante. Construirlo con `innerHTML` convertiría a
 *    la extensión en el vehículo de la inyección que pretende detectar.
 */

(() => {
  "use strict";

  const ID_PANEL = "phishguard-panel";

  const ETIQUETAS = {
    phishing: { texto: "Phishing", clase: "pg-phishing" },
    sospechoso: { texto: "Sospechoso", clase: "pg-sospechoso" },
    legitimo: { texto: "Sin indicios", clase: "pg-legitimo" },
  };

  let idAnalizado = null;

  /** Atajo para crear un elemento con clase y texto, siempre por `textContent`. */
  function crear(etiqueta, clase, texto) {
    const el = document.createElement(etiqueta);
    if (clase) el.className = clase;
    if (texto !== undefined) el.textContent = texto;
    return el;
  }

  function panel() {
    let el = document.getElementById(ID_PANEL);
    if (el) return el;

    el = crear("div", "pg-panel");
    el.id = ID_PANEL;
    document.body.appendChild(el);
    return el;
  }

  function limpiar(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
  }

  function cabecera(titulo) {
    const barra = crear("div", "pg-cabecera");
    barra.appendChild(crear("span", "pg-titulo", titulo));

    const cerrar = crear("button", "pg-cerrar", "×");
    cerrar.title = "Cerrar";
    cerrar.addEventListener("click", () => panel().remove());
    barra.appendChild(cerrar);

    return barra;
  }

  function mostrarMensaje(titulo, texto, clase = "") {
    const el = limpiar(panel());
    el.appendChild(cabecera(titulo));
    el.appendChild(crear("p", `pg-mensaje ${clase}`, texto));
  }

  function mostrarAnalisis(analisis) {
    const el = limpiar(panel());
    const etiqueta = ETIQUETAS[analisis.veredicto] || ETIQUETAS.sospechoso;

    el.appendChild(cabecera("PhishGuard"));

    const veredicto = crear("div", `pg-veredicto ${etiqueta.clase}`);
    veredicto.appendChild(crear("span", "pg-veredicto-texto", etiqueta.texto));
    veredicto.appendChild(
      crear("span", "pg-score", `riesgo ${Math.round(analisis.score * 100)}%`)
    );
    el.appendChild(veredicto);

    // Las advertencias van arriba del todo: la más importante es que el juicio
    // salió de un stub y no de un modelo.
    for (const aviso of analisis.advertencias || []) {
      el.appendChild(crear("p", "pg-aviso", aviso));
    }

    el.appendChild(crear("p", "pg-explicacion", analisis.explicacion));

    if (analisis.senales?.length) {
      const detalle = document.createElement("details");
      detalle.className = "pg-detalle";
      detalle.appendChild(
        crear("summary", null, `Señales detectadas (${analisis.senales.length})`)
      );

      const lista = crear("ul", "pg-senales");
      for (const senal of analisis.senales) {
        const item = crear("li", `pg-senal pg-sev-${senal.severidad}`);
        item.appendChild(crear("span", "pg-senal-desc", senal.descripcion));
        if (senal.evidencia?.length) {
          item.appendChild(crear("code", "pg-evidencia", senal.evidencia.join(" · ")));
        }
        lista.appendChild(item);
      }
      detalle.appendChild(lista);
      el.appendChild(detalle);
    }

    const pie = crear("div", "pg-pie");
    pie.appendChild(
      crear(
        "span",
        null,
        `reglas ${analisis.reglas.score.toFixed(2)} · IA ${analisis.llm.score.toFixed(
          2
        )} · acuerdo ${analisis.confianza.toFixed(2)}`
      )
    );
    el.appendChild(pie);
  }

  async function analizarCorreoAbierto() {
    const correo = window.PhishGuardAdaptador.extraerCorreoAbierto();

    if (!correo) {
      mostrarMensaje(
        "PhishGuard",
        "No se pudo leer el correo abierto. Gmail pudo haber cambiado su estructura: " +
          "usa el popup de la extensión para pegar el correo a mano.",
        "pg-error"
      );
      return;
    }

    mostrarMensaje("PhishGuard", "Analizando…");

    const respuesta = await chrome.runtime.sendMessage({ tipo: "analizar", correo });
    if (respuesta?.ok) {
      mostrarAnalisis(respuesta.analisis);
    } else {
      mostrarMensaje("PhishGuard", respuesta?.error || "Error desconocido.", "pg-error");
    }
  }

  /** Inserta el botón flotante si hay un correo abierto y aún no está puesto. */
  function asegurarBoton() {
    const id = window.PhishGuardAdaptador.idMensajeAbierto();

    if (!id) {
      document.getElementById("phishguard-boton")?.remove();
      document.getElementById(ID_PANEL)?.remove();
      idAnalizado = null;
      return;
    }

    // Al cambiar de mensaje se cierra el panel del anterior: dejar visible el
    // veredicto de otro correo es peor que no mostrar ninguno.
    if (id !== idAnalizado) {
      document.getElementById(ID_PANEL)?.remove();
      idAnalizado = id;
    }

    if (document.getElementById("phishguard-boton")) return;

    const boton = crear("button", "pg-boton", "Analizar con PhishGuard");
    boton.id = "phishguard-boton";
    boton.addEventListener("click", analizarCorreoAbierto);
    document.body.appendChild(boton);
  }

  // Gmail es una SPA: no hay recarga de página al abrir un correo, así que la
  // única forma de enterarse es observar el DOM. El observador se limita a la
  // región de contenido para no reaccionar a cada repintado de la barra lateral.
  function observar() {
    const objetivo = document.querySelector('div[role="main"]') || document.body;
    new MutationObserver(() => asegurarBoton()).observe(objetivo, {
      childList: true,
      subtree: true,
    });
    asegurarBoton();
  }

  observar();
})();
