/**
 * Perfil de Yahoo Mail.
 *
 * Yahoo es el caso más cómodo de los cuatro: marca casi todo con atributos
 * `data-test-id`, puestos ahí para sus propias pruebas automatizadas. Eso no es
 * una API pública —pueden cambiarlos igual— pero es bastante más estable que
 * una clase generada por el empaquetador.
 *
 * Los dominios de Yahoo son por región (`mail.yahoo.com`, `es.mail.yahoo.com`,
 * `mail.yahoo.co.uk`…), todos con la misma interfaz. La expresión cubre el TLD
 * y el código de país opcional, y sigue anclada al final del host.
 *
 * `verificado: false`: selectores sin comprobar contra la página real.
 */

(() => {
  "use strict";

  window.PhishGuardComun.registrar({
    id: "yahoo",
    nombre: "Yahoo Mail",
    verificado: false,
    hosts: [/(^|\.)mail\.yahoo\.[a-z]{2,3}(\.[a-z]{2})?$/],
    atributosId: ["data-test-id", "data-test-msg-id", "id"],
    raizObservada: ['div[data-test-id="message-view"]', 'div[role="main"]'],
    selectores: {
      contenedor: [
        'div[data-test-id="message-view-body"]',
        'div[data-test-id="message-view"]',
        'div[data-test-id="message-group-view-scroller"]',
        "article",
      ],
      asunto: [
        '[data-test-id="message-subject"]',
        'div[data-test-id="message-view"] h1',
        'h1[data-test-id="subject"]',
      ],
      remitente: [
        '[data-test-id="message-from"] span[title]',
        'span[data-test-id="email-pill"]',
        '[data-test-id="message-from"]',
        'span[title*="@"]',
      ],
      cuerpo: [
        '[data-test-id="message-view-body-content"]',
        '[data-test-id="message-body"]',
        "div.msg-body",
      ],
      adjuntos: [
        '[data-test-id="attachment-card-title"]',
        '[data-test-id="attachment-name"]',
      ],
    },
  });
})();
