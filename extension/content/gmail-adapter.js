/**
 * Adaptador de Gmail: traduce el DOM del webmail al contrato del backend.
 *
 * ADVERTENCIA DE FRAGILIDAD — léase antes de confiar en esto
 * ----------------------------------------------------------
 * Gmail no publica una API de DOM. Las clases que se usan aquí (`h2.hP`,
 * `span.gD`, `div.a3s`…) están ofuscadas y Google las cambia sin avisar. Este
 * archivo se va a romper; la pregunta es cuándo.
 *
 * Por eso el diseño lo aísla todo aquí: el resto de la extensión no sabe nada de
 * Gmail y habla solo con `extraerCorreoAbierto()`. Añadir Outlook es escribir
 * otro adaptador con la misma firma, y cuando un selector deje de funcionar, la
 * extracción devuelve `null` y la interfaz ofrece pegar el correo a mano en vez
 * de mostrar un análisis hecho sobre datos incompletos.
 *
 * Ese último punto no es cosmético: analizar un correo del que no se pudo leer el
 * remitente produciría un veredicto de "legítimo" por ausencia de señales, que es
 * el peor error posible en un detector de phishing.
 */

(() => {
  "use strict";

  // Cada campo lista varios selectores: se prueban en orden y gana el primero
  // que dé contenido. Es la forma barata de sobrevivir a un cambio parcial.
  const SELECTORES = {
    contenedor: ["div.adn.ads", 'div[role="listitem"][data-legacy-message-id]'],
    asunto: ["h2.hP", 'h2[data-thread-perm-id]'],
    remitenteNombre: ["span.gD"],
    cuerpo: ["div.a3s", 'div[dir="ltr"].ii'],
    adjuntos: ["span.aV3", 'div[role="listitem"] span.aQA'],
  };

  /** Primer elemento que exista de una lista de selectores. */
  function primero(raiz, selectores) {
    for (const selector of selectores) {
      const elemento = raiz.querySelector(selector);
      if (elemento) return elemento;
    }
    return null;
  }

  /**
   * Reconstruye la cabecera `From` a partir del nombre visible y el atributo
   * `email` que Gmail deja en el `span` del remitente.
   *
   * Gmail muestra el nombre y esconde la dirección, que es exactamente la mitad
   * que el pipeline necesita para detectar la suplantación. Sin el atributo
   * `email` no hay análisis de remitente posible, así que su ausencia se trata
   * como fallo de extracción y no como un campo vacío más.
   */
  function leerRemitente(contenedor) {
    const span = primero(contenedor, SELECTORES.remitenteNombre);
    if (!span) return null;

    const direccion = span.getAttribute("email") || "";
    if (!direccion) return null;

    const nombre = (span.getAttribute("name") || span.textContent || "").trim();
    return nombre ? `${nombre} <${direccion}>` : direccion;
  }

  /**
   * Extrae el correo abierto, o `null` si no hay ninguno o el DOM cambió.
   *
   * Devuelve el HTML además del texto porque hay una señal —el enlace cuyo texto
   * visible no coincide con su destino— que solo existe en el marcado.
   */
  function extraerCorreoAbierto() {
    const contenedor = primero(document, SELECTORES.contenedor);
    if (!contenedor) return null;

    const cuerpoEl = primero(contenedor, SELECTORES.cuerpo);
    const remitente = leerRemitente(contenedor);
    if (!cuerpoEl || !remitente) return null;

    const asuntoEl = primero(document, SELECTORES.asunto);
    const adjuntos = [...document.querySelectorAll(SELECTORES.adjuntos.join(","))]
      .map((el) => el.textContent.trim())
      .filter(Boolean);

    return {
      asunto: asuntoEl ? asuntoEl.textContent.trim() : "",
      remitente,
      cuerpo_texto: cuerpoEl.innerText.trim(),
      cuerpo_html: cuerpoEl.innerHTML,
      // Las cabeceras de autenticación (SPF/DKIM/DMARC) NO están en el DOM de
      // Gmail: viven en "Mostrar original", en otra página. El pipeline lo nota
      // y emite la señal `auth_ausente`, así que la carencia queda registrada en
      // el análisis en vez de pasar por "todo en orden".
      cabeceras: {},
      adjuntos,
      origen: "extension",
    };
  }

  /** Identidad estable del mensaje abierto, para no reanalizar lo mismo. */
  function idMensajeAbierto() {
    const contenedor = primero(document, SELECTORES.contenedor);
    if (!contenedor) return null;
    return (
      contenedor.getAttribute("data-legacy-message-id") ||
      contenedor.getAttribute("data-message-id") ||
      primero(document, SELECTORES.asunto)?.textContent.trim() ||
      null
    );
  }

  // Los content scripts de una misma pestaña comparten un mundo aislado, así que
  // este objeto es la superficie que `overlay.js` consume. No toca la página.
  window.PhishGuardAdaptador = { extraerCorreoAbierto, idMensajeAbierto };
})();
