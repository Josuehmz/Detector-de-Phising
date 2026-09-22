/**
 * Perfil de Outlook Web — cubre Hotmail, Live, MSN y Microsoft 365.
 *
 * Por qué un solo perfil para tantas marcas
 * -----------------------------------------
 * «Hotmail», «Live» y «MSN» ya no son productos con interfaz propia: una cuenta
 * `@hotmail.com` inicia sesión y termina en `outlook.live.com`, con el mismo
 * Outlook Web que una cuenta `@outlook.com`. Las cuentas corporativas y
 * educativas de Microsoft 365 caen en `outlook.office.com` /
 * `outlook.office365.com`, y Microsoft está moviendo el producto a
 * `outlook.cloud.microsoft`. Son hosts distintos con el mismo DOM, así que se
 * listan todos y comparten selectores.
 *
 * Diferencia real con Gmail: Outlook no expone la dirección en un atributo
 * propio como `email`. La pone en `title` o en `aria-label` del elemento del
 * remitente, normalmente con el formato «Nombre <a@b.com>» o solo la dirección.
 * El motor común ya prueba `title`, `aria-label` y el texto, así que este
 * perfil no necesita lectura propia del remitente.
 *
 * `verificado: false`: los selectores salen de la estructura documentada de
 * Outlook Web (atributos `data-app-section`, `data-testid` y los roles ARIA que
 * Microsoft mantiene por accesibilidad, que son más estables que sus clases
 * generadas), pero NO se han comprobado contra la página real.
 */

(() => {
  "use strict";

  window.PhishGuardComun.registrar({
    id: "outlook",
    nombre: "Outlook / Hotmail",
    verificado: false,
    hosts: [
      /(^|\.)outlook\.live\.com$/,
      /(^|\.)outlook\.office\.com$/,
      /(^|\.)outlook\.office365\.com$/,
      /(^|\.)outlook\.cloud\.microsoft$/,
      /(^|\.)outlook\.com$/,
    ],
    atributosId: ["data-convid", "data-message-id", "id"],
    raizObservada: ['div[role="main"]'],
    selectores: {
      contenedor: [
        'div[data-app-section="ConversationContainer"]',
        'div[data-app-section="MessageBody"]',
        "div[data-convid]",
        'div[role="main"] div[role="document"]',
        "div.ReadMsgContainer",
      ],
      asunto: [
        'div[role="main"] div[role="heading"][aria-level="2"]',
        'span[data-testid="message-subject"]',
        'div[role="main"] [role="heading"]',
        'div[role="main"] h1',
      ],
      remitente: [
        'span[data-testid="SenderPersona"]',
        'div[data-testid="message-header"] span[title]',
        'span[title*="@"]',
        'button[title*="@"]',
        'span[aria-label*="@"]',
      ],
      cuerpo: [
        'div[data-testid="message-body"]',
        'div[aria-label="Message body"]',
        'div[aria-label="Cuerpo del mensaje"]',
        '[id^="UniqueMessageBody"]',
        "div.PlainTextBody",
        'div[role="document"]',
      ],
      adjuntos: [
        'div[data-testid="attachment-well"] span[title]',
        'button[data-testid="AttachmentTile"] span[title]',
        'div[aria-label*="Attachment"] span[title]',
        'div[aria-label*="Datos adjuntos"] span[title]',
      ],
    },
  });
})();
