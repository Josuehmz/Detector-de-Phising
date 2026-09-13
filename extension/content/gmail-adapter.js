/**
 * Adaptador de Gmail: traduce el DOM del webmail al contrato del backend.
 *
 * ADVERTENCIA DE FRAGILIDAD — léase antes de confiar en esto
 * ----------------------------------------------------------
 * Gmail no publica una API de DOM. Las clases que se usan aquí (`h2.hP`,
 * `span.gD`, `div.a3s`…) están ofuscadas y Google las cambia sin avisar. Este
 * archivo se va a romper; la pregunta es cuándo.
 *
 * Dos decisiones lo hacen soportable:
 *
 * 1. **Todo el conocimiento de Gmail vive aquí.** El resto de la extensión solo
 *    llama a `extraerCorreoAbierto()`. Añadir Outlook es escribir otro adaptador
 *    con la misma firma.
 *
 * 2. **Cuando falla, DICE QUÉ falló.** La primera versión devolvía `null` y la
 *    interfaz no mostraba nada, lo que confunde «no hay correo abierto» con
 *    «los selectores cambiaron» — y deja al usuario sin forma de averiguarlo.
 *    Ahora devuelve un diagnóstico por campo.
 *
 * Lo que NO cambia: sin remitente no se emite un veredicto normal. Analizar un
 * correo del que no se pudo leer el remitente daría «legítimo» por ausencia de
 * señales, que es el peor error posible en un detector de phishing. El usuario
 * puede pedir explícitamente un análisis parcial, y queda marcado como tal.
 */

(() => {
  "use strict";

  // Cada campo lista varios selectores: se prueban en orden y gana el primero
  // que dé contenido. Es la forma barata de sobrevivir a un cambio parcial.
  const SELECTORES = {
    contenedor: [
      "div.adn.ads",
      "div[data-legacy-message-id]",
      "div[data-message-id]",
      "div.gs",
      'div[role="listitem"]',
    ],
    asunto: ["h2.hP", "h2[data-thread-perm-id]", 'div[role="main"] h2'],
    remitente: ["span.gD", "span[email]", "span.go"],
    cuerpo: ["div.a3s", "div.ii.gt", 'div[dir="ltr"].ii', "div.msg"],
    adjuntos: ["span.aV3", "div.aQA span.aV3", "span.aZo"],
  };

  /** Primer elemento que exista de una lista de selectores. */
  function primero(raiz, selectores) {
    for (const selector of selectores) {
      let elemento = null;
      try {
        elemento = raiz.querySelector(selector);
      } catch {
        // Un selector inválido no debe tumbar la extracción entera.
        continue;
      }
      if (elemento) return elemento;
    }
    return null;
  }

  /**
   * Reconstruye la cabecera `From` a partir del nombre visible y la dirección.
   *
   * Gmail muestra el nombre y esconde la dirección en un atributo, que es
   * justo la mitad que el pipeline necesita para detectar la suplantación.
   */
  function leerRemitente(raiz) {
    const span = primero(raiz, SELECTORES.remitente);
    if (!span) return null;

    // `email` es el atributo habitual; algunas vistas ponen la dirección entre
    // ángulos dentro del texto (`Nombre <a@b.com>`), así que se intenta también.
    let direccion = span.getAttribute("email") || "";
    if (!direccion) {
      const enAngulos = (span.textContent || "").match(/<([^>]+@[^>]+)>/);
      if (enAngulos) direccion = enAngulos[1];
    }
    if (!direccion) return null;

    const nombre = (span.getAttribute("name") || span.textContent || "")
      .replace(/<[^>]*>/g, "")
      .trim();
    return nombre ? `${nombre} <${direccion}>` : direccion;
  }

  /**
   * Extrae el correo abierto.
   *
   * Devuelve `{ ok: true, correo }`, o `{ ok: false, diagnostico, parcial }`
   * donde `diagnostico` dice qué selector falló y `parcial` es lo que sí se pudo
   * leer, por si el usuario decide analizarlo de todos modos.
   */
  function extraerCorreoAbierto() {
    const contenedor = primero(document, SELECTORES.contenedor) || document;
    const usandoDocumento = contenedor === document;

    const cuerpoEl = primero(contenedor, SELECTORES.cuerpo);
    const remitente = leerRemitente(contenedor);
    const asuntoEl = primero(document, SELECTORES.asunto);

    const diagnostico = [
      {
        campo: "contenedor del mensaje",
        ok: !usandoDocumento,
        selectores: SELECTORES.contenedor,
      },
      { campo: "cuerpo", ok: Boolean(cuerpoEl), selectores: SELECTORES.cuerpo },
      { campo: "remitente", ok: Boolean(remitente), selectores: SELECTORES.remitente },
      { campo: "asunto", ok: Boolean(asuntoEl), selectores: SELECTORES.asunto },
    ];

    let adjuntos = [];
    try {
      adjuntos = [...document.querySelectorAll(SELECTORES.adjuntos.join(","))]
        .map((el) => el.textContent.trim())
        .filter(Boolean);
    } catch {
      adjuntos = [];
    }

    const correo = {
      asunto: asuntoEl ? asuntoEl.textContent.trim() : "",
      remitente: remitente || "",
      cuerpo_texto: cuerpoEl ? cuerpoEl.innerText.trim() : "",
      cuerpo_html: cuerpoEl ? cuerpoEl.innerHTML : null,
      // Las cabeceras de autenticación (SPF/DKIM/DMARC) NO están en el DOM de
      // Gmail: viven en "Mostrar original", en otra página. El pipeline lo nota
      // y emite `auth_ausente`, así que la carencia queda registrada en el
      // análisis en vez de pasar por "todo en orden".
      cabeceras: {},
      adjuntos,
      origen: "extension",
    };

    // El mínimo para un veredicto con sentido es cuerpo + remitente.
    if (cuerpoEl && remitente) return { ok: true, correo, diagnostico };

    return { ok: false, diagnostico, parcial: correo };
  }

  /** Identidad estable del mensaje abierto, para no reanalizar lo mismo. */
  function idMensajeAbierto() {
    const contenedor = primero(document, SELECTORES.contenedor);
    if (!contenedor) return null;
    return (
      contenedor.getAttribute("data-legacy-message-id") ||
      contenedor.getAttribute("data-message-id") ||
      primero(document, SELECTORES.asunto)?.textContent.trim() ||
      "mensaje-abierto"
    );
  }

  // Los content scripts de una misma pestaña comparten un mundo aislado, así que
  // este objeto es la superficie que `overlay.js` consume. No toca la página.
  window.PhishGuardAdaptador = { extraerCorreoAbierto, idMensajeAbierto, SELECTORES };

  // Marca visible en la consola: si esto no aparece, el content script ni se
  // cargó, y el problema está en la instalación, no en los selectores.
  console.log("[PhishGuard] adaptador de Gmail cargado");
})();
