/**
 * Interfaz dentro del webmail: el botón de análisis y el panel de resultado.
 *
 * No sabe en qué webmail corre. Todo lo que necesita saber se lo da
 * `window.PhishGuardAdaptador`, que `adaptador.js` publica tras elegir el perfil
 * del host. Gracias a eso, añadir Outlook o Yahoo no tocó una línea de este
 * archivo salvo los textos, que ahora nombran al proveedor detectado.
 *
 * Tres decisiones de diseño que conviene poder sustentar:
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
 *
 * 3. **El botón está siempre, y el fallo se explica.** La primera versión solo
 *    mostraba el botón cuando reconocía un mensaje abierto: si los selectores
 *    del webmail cambiaban, no aparecía nada y el usuario no tenía forma de
 *    saber si la extensión estaba instalada, si el backend estaba caído o si el
 *    DOM había cambiado. Un fallo silencioso es peor que un fallo.
 */

(() => {
  "use strict";

  // Sin adaptador no hay nada que hacer: estamos en un host que ningún perfil
  // reconoce. Pintar el botón igualmente solo produciría un clic sin respuesta.
  const adaptador = window.PhishGuardAdaptador;
  if (!adaptador) return;

  const ID_PANEL = "phishguard-panel";
  const ID_BOTON = "phishguard-boton";

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
    return el;
  }

  // --------------------------------------------------------------- Diagnóstico

  /**
   * Panel de fallo de extracción.
   *
   * Muestra qué campo no se pudo leer y con qué selectores se intentó. Sirve
   * para dos cosas: que el usuario sepa que la extensión sí está viva, y que
   * quien mantenga el adaptador sepa exactamente qué selector actualizar.
   */
  function mostrarFalloDeExtraccion(resultado) {
    const el = limpiar(panel());
    el.appendChild(cabecera("PhishGuard · no se pudo leer el correo"));

    const fallidos = resultado.diagnostico.filter((d) => !d.ok);
    const hayCuerpo = Boolean(resultado.parcial?.cuerpo_texto);

    el.appendChild(
      crear(
        "p",
        "pg-mensaje",
        fallidos.length === resultado.diagnostico.length
          ? `No hay ningún correo abierto, o la estructura de ${adaptador.nombre} cambió por completo.`
          : `${adaptador.nombre} cambió su estructura y faltan campos que el análisis necesita.`
      )
    );

    // Mientras el perfil no esté comprobado contra la página real, un fallo de
    // extracción es tan probable que sea del perfil como del webmail. Decirlo
    // evita que se persiga un cambio de DOM que nunca ocurrió.
    if (!adaptador.verificado) {
      el.appendChild(
        crear(
          "p",
          "pg-aviso",
          `El perfil de ${adaptador.nombre} todavía no se ha comprobado contra la ` +
            "página real, así que el fallo puede estar en los selectores de esta " +
            "extensión y no en un cambio del webmail."
        )
      );
    }

    const lista = crear("ul", "pg-senales");
    for (const campo of resultado.diagnostico) {
      const item = crear("li", `pg-senal ${campo.ok ? "pg-sev-baja" : "pg-sev-alta"}`);
      item.appendChild(crear("span", "pg-senal-desc", `${campo.ok ? "✓" : "✗"} ${campo.campo}`));
      if (!campo.ok) {
        item.appendChild(crear("code", "pg-evidencia", campo.selectores.join(" , ")));
      }
      lista.appendChild(item);
    }
    el.appendChild(lista);

    // Sin remitente no hay análisis completo, pero el usuario puede pedir uno
    // parcial a sabiendas. Es una decisión suya, explícita, y queda marcada.
    if (hayCuerpo) {
      const aviso = crear(
        "p",
        "pg-aviso",
        "Se puede analizar solo el texto visible, pero sin remitente no se evalúa " +
          "suplantación ni autenticación: un veredicto «sin indicios» no significaría nada."
      );
      el.appendChild(aviso);

      const boton = crear("button", "pg-boton-inline", "Analizar solo el texto visible");
      boton.addEventListener("click", () => enviarAlBackend(resultado.parcial, true));
      el.appendChild(boton);
    }

    el.appendChild(
      crear(
        "p",
        "pg-mensaje",
        "Alternativa fiable: abre el popup de la extensión y pega el correo a mano."
      )
    );
  }

  // ----------------------------------------------------------------- Resultado

  function mostrarAnalisis(analisis, esParcial = false) {
    const el = limpiar(panel());
    const etiqueta = ETIQUETAS[analisis.veredicto] || ETIQUETAS.sospechoso;

    el.appendChild(cabecera("PhishGuard"));

    const veredicto = crear("div", `pg-veredicto ${etiqueta.clase}`);
    veredicto.appendChild(crear("span", "pg-veredicto-texto", etiqueta.texto));
    veredicto.appendChild(
      crear("span", "pg-score", `riesgo ${Math.round(analisis.score * 100)}%`)
    );
    el.appendChild(veredicto);

    if (esParcial) {
      el.appendChild(
        crear(
          "p",
          "pg-aviso",
          "ANÁLISIS PARCIAL: solo se analizó el texto visible. Sin remitente ni " +
            "cabeceras, las señales de suplantación y autenticación no se evaluaron."
        )
      );
    }

    // Las advertencias van arriba: la más importante es que el juicio salió de
    // un stub y no de un modelo.
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
    // De qué adaptador salió el texto analizado. Con varios webmails soportados,
    // un veredicto raro puede venir de una extracción mala y no del pipeline;
    // sin esta línea no habría forma de distinguirlo mirando el panel.
    pie.appendChild(
      crear(
        "span",
        null,
        `adaptador: ${adaptador.nombre}${adaptador.verificado ? "" : " · sin verificar"}`
      )
    );
    el.appendChild(pie);
  }

  // ------------------------------------------------------------------- Acciones

  async function enviarAlBackend(correo, esParcial = false) {
    mostrarMensaje("PhishGuard", "Analizando…");

    let respuesta;
    try {
      respuesta = await chrome.runtime.sendMessage({ tipo: "analizar", correo });
    } catch (error) {
      // Pasa cuando la extensión se recarga con la pestaña abierta: el content
      // script viejo queda huérfano y su canal ya no existe.
      mostrarMensaje(
        "PhishGuard",
        `Se perdió la conexión con la extensión (${error.message}). Recarga la pestaña de ${adaptador.nombre}.`,
        "pg-error"
      );
      return;
    }

    if (respuesta?.ok) mostrarAnalisis(respuesta.analisis, esParcial);
    else mostrarMensaje("PhishGuard", respuesta?.error || "Error desconocido.", "pg-error");
  }

  async function analizarCorreoAbierto() {
    const resultado = adaptador.extraerCorreoAbierto();

    if (!resultado.ok) {
      mostrarFalloDeExtraccion(resultado);
      return;
    }
    await enviarAlBackend(resultado.correo);
  }

  /**
   * Inserta el botón flotante.
   *
   * Se pone SIEMPRE que el host tenga adaptador, haya o no un mensaje
   * reconocido. Si no lo hay, el usuario lo pulsa y recibe una explicación;
   * antes no recibía nada.
   */
  function asegurarBoton() {
    const id = adaptador.idMensajeAbierto();

    // Al cambiar de mensaje se cierra el panel del anterior: dejar visible el
    // veredicto de otro correo es peor que no mostrar ninguno.
    if (id !== idAnalizado) {
      document.getElementById(ID_PANEL)?.remove();
      idAnalizado = id;
    }

    if (document.getElementById(ID_BOTON)) return;

    const boton = crear("button", "pg-boton", "Analizar con PhishGuard");
    boton.id = ID_BOTON;
    boton.addEventListener("click", analizarCorreoAbierto);
    document.body.appendChild(boton);
  }

  // Los cuatro webmails son SPA: no hay recarga de página al abrir un correo,
  // así que la única forma de enterarse es observar el DOM. El observador se
  // limita a la región de contenido cuando existe, para no reaccionar a cada
  // repintado de la barra lateral. Cada perfil declara cuál es esa región,
  // porque no todos usan `div[role="main"]`.
  function observar() {
    const objetivo =
      window.PhishGuardComun.primero(document, adaptador.raizObservada) || document.body;
    new MutationObserver(() => asegurarBoton()).observe(objetivo, {
      childList: true,
      subtree: true,
    });
    asegurarBoton();
  }

  observar();
  console.log(
    `[PhishGuard] overlay activo en ${adaptador.nombre} — botón abajo a la derecha`
  );
})();
