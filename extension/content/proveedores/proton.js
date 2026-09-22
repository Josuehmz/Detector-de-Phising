/**
 * Perfil de Proton Mail.
 *
 * El caso que justifica que el motor admita lectura propia del cuerpo
 * -------------------------------------------------------------------
 * Proton no pinta el cuerpo del correo en el documento principal: lo mete en un
 * `<iframe>`. Es una decisión de seguridad suya y buena —aísla el HTML del
 * atacante del resto de la aplicación—, pero significa que `querySelector`
 * sobre `document` nunca va a encontrar el texto del mensaje.
 *
 * Por eso el perfil trae `leerCuerpo` propio: baja al `contentDocument` del
 * iframe. Si el navegador lo bloquea por origen, la excepción sube al motor
 * común, que la traduce en «no se pudo leer el cuerpo» con su diagnóstico, en
 * vez de en un análisis a medias. Esa es justo la diferencia entre fallar y
 * fallar en silencio.
 *
 * `verificado: false`: selectores sin comprobar contra la página real. En este
 * perfil la advertencia pesa más que en los otros, porque si el iframe resulta
 * ser de origen cruzado el cuerpo no se podrá leer nunca, y eso no se sabe
 * hasta probarlo en Proton de verdad.
 */

(() => {
  "use strict";

  const comun = window.PhishGuardComun;

  /**
   * Lee el cuerpo desde el iframe del mensaje.
   *
   * Devuelve `null` si no hay iframe o si aún no tiene documento; lanza si el
   * navegador niega el acceso, y de eso se encarga el motor.
   */
  function leerCuerpoEnIframe(raiz, selectores) {
    const marco = comun.primero(raiz, selectores) || comun.primero(document, selectores);
    if (!marco) return null;

    const documento = marco.contentDocument;
    if (!documento || !documento.body) return null;

    return {
      texto: (documento.body.innerText || documento.body.textContent || "").trim(),
      html: documento.body.innerHTML || null,
    };
  }

  comun.registrar({
    id: "proton",
    nombre: "Proton Mail",
    verificado: false,
    hosts: [/(^|\.)mail\.proton\.me$/, /(^|\.)mail\.protonmail\.com$/],
    atributosId: ["data-message-id", "data-shortcut-target", "id"],
    raizObservada: ["main", 'div[role="main"]'],
    leerCuerpo: leerCuerpoEnIframe,
    selectores: {
      contenedor: [
        'article[data-shortcut-target="message-container"]',
        "div.message-container",
        "article",
      ],
      asunto: [
        '[data-testid="conversation-header:subject"]',
        "h1.message-conversation-summary-header",
        "main h1",
      ],
      remitente: [
        '[data-testid="message-header:from"]',
        "span.item-senderdetails",
        'span[title*="@"]',
      ],
      // Aquí los selectores apuntan al IFRAME, no al cuerpo: los consume
      // `leerCuerpoEnIframe`, no el lector genérico.
      cuerpo: ['iframe[title]', "div.message-content iframe", "iframe"],
      adjuntos: ['[data-testid="attachment-item:name"]', "span.attachment-item-name"],
    },
  });
})();
