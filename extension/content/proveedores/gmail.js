/**
 * Perfil de Gmail.
 *
 * ADVERTENCIA DE FRAGILIDAD — común a todos los perfiles
 * ------------------------------------------------------
 * Ningún webmail publica una API de DOM. Las clases que se usan aquí (`h2.hP`,
 * `span.gD`, `div.a3s`…) están ofuscadas y Google las cambia sin avisar. Este
 * perfil se va a romper; la pregunta es cuándo.
 *
 * Por eso cada campo lista varios selectores: se prueban en orden y gana el
 * primero que dé contenido. Es la forma barata de sobrevivir a un cambio
 * parcial. Y por eso el motor común, cuando no encuentra algo, dice qué
 * selector falló en vez de devolver un correo a medias.
 *
 * `verificado: false` significa que los selectores están escritos a partir de
 * la estructura conocida del producto pero NO se han comprobado contra la
 * página real. El dato viaja hasta la interfaz: quien lea un veredicto sabe con
 * qué adaptador se extrajo y si ese adaptador está confirmado.
 */

(() => {
  "use strict";

  window.PhishGuardComun.registrar({
    id: "gmail",
    nombre: "Gmail",
    verificado: false,
    hosts: [/(^|\.)mail\.google\.com$/],
    atributosId: ["data-legacy-message-id", "data-message-id"],
    raizObservada: ['div[role="main"]'],
    selectores: {
      contenedor: [
        "div.adn.ads",
        "div[data-legacy-message-id]",
        "div[data-message-id]",
        "div.gs",
        'div[role="listitem"]',
      ],
      asunto: ["h2.hP", "h2[data-thread-perm-id]", 'div[role="main"] h2'],
      // `span.gD` expone la dirección en el atributo `email`; el motor común lo
      // lee antes que `title` o el texto.
      remitente: ["span.gD", "span[email]", "span.go"],
      cuerpo: ["div.a3s", "div.ii.gt", 'div[dir="ltr"].ii', "div.msg"],
      adjuntos: ["span.aV3", "div.aQA span.aV3", "span.aZo"],
    },
  });
})();
