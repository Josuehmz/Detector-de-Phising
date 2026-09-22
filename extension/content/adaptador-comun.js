/**
 * Motor común de los adaptadores de webmail.
 *
 * Por qué existe este archivo
 * ---------------------------
 * La primera versión solo soportaba Gmail y todo el conocimiento del webmail
 * vivía en un único archivo. Al añadir Outlook quedó claro que casi nada de ese
 * archivo era conocimiento de Gmail: era el mismo procedimiento —probar
 * selectores en orden, reconstruir la cabecera `From`, decidir si hubo lo
 * mínimo para un veredicto y explicar qué falló— aplicado a unos selectores
 * concretos.
 *
 * Así que el procedimiento vive aquí y cada webmail aporta solo lo que de
 * verdad lo distingue: sus hosts y sus selectores. Añadir un proveedor nuevo es
 * un archivo de ~30 líneas en `proveedores/`, no una copia del adaptador.
 *
 * Lo que NO cambia respecto a la versión de un solo proveedor:
 *
 * - Sin remitente no se emite un veredicto normal. Un correo del que no se pudo
 *   leer el remitente daría «legítimo» por ausencia de señales, que es el peor
 *   error posible en un detector de phishing.
 * - Cuando falla, dice QUÉ falló, campo por campo y con los selectores que se
 *   intentaron. Un fallo silencioso es peor que un fallo.
 */

(() => {
  "use strict";

  /** Primer elemento que exista de una lista de selectores. */
  function primero(raiz, selectores) {
    for (const selector of selectores || []) {
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

  /** Todos los elementos que casen con cualquiera de los selectores. */
  function todos(raiz, selectores) {
    const encontrados = [];
    for (const selector of selectores || []) {
      try {
        encontrados.push(...raiz.querySelectorAll(selector));
      } catch {
        continue;
      }
    }
    return encontrados;
  }

  /** Extrae la primera dirección de correo que aparezca en un texto. */
  function direccionEn(texto) {
    const coincidencia = (texto || "").match(
      /[^\s<>()[\],;:"]+@[^\s<>()[\],;:"]+\.[a-z]{2,}/i
    );
    return coincidencia ? coincidencia[0] : "";
  }

  /**
   * Reconstruye la cabecera `From` a partir del nombre visible y la dirección.
   *
   * Todos los webmails muestran el nombre y esconden la dirección en algún
   * atributo, que es justo la mitad que el pipeline necesita para detectar la
   * suplantación. Cambia el atributo, no la idea: Gmail usa `email`, Outlook y
   * Yahoo usan `title`, y varios exponen `aria-label`. Se prueban todos y, como
   * último recurso, se busca la dirección en el propio texto.
   */
  function leerRemitenteGenerico(raiz, selectores) {
    for (const elemento of todos(raiz, selectores)) {
      const direccion =
        elemento.getAttribute("email") ||
        direccionEn(elemento.getAttribute("title")) ||
        direccionEn(elemento.getAttribute("aria-label")) ||
        direccionEn(elemento.textContent);

      if (!direccion) continue;

      const nombre = (elemento.getAttribute("name") || elemento.textContent || "")
        .replace(/<[^>]*>/g, "")
        .replace(direccion, "")
        .trim();

      return nombre ? nombre + " <" + direccion + ">" : direccion;
    }
    return null;
  }

  /** Lectura estándar del cuerpo: texto visible + HTML del mismo elemento. */
  function leerCuerpoGenerico(raiz, selectores) {
    const elemento = primero(raiz, selectores);
    if (!elemento) return null;
    return {
      texto: (elemento.innerText || elemento.textContent || "").trim(),
      html: elemento.innerHTML || null,
    };
  }

  /**
   * Elige el perfil que corresponde a un hostname.
   *
   * Se compara con expresiones regulares ancladas al final del host y no con
   * `includes`: `mail.google.com.phishing.example` contiene «mail.google.com» y
   * no debe activar el adaptador de Gmail. Una extensión de seguridad que se
   * deja engañar por un subdominio no se puede defender en una sustentación.
   */
  function elegirPerfil(hostname, perfiles) {
    const host = (hostname || "").toLowerCase();
    return (
      (perfiles || []).find((perfil) => perfil.hosts.some((rx) => rx.test(host))) || null
    );
  }

  /**
   * Convierte un perfil de proveedor en el adaptador que consume `overlay.js`.
   *
   * El contrato de salida es idéntico al que tenía el adaptador de Gmail, para
   * que la interfaz no sepa en qué webmail está corriendo.
   */
  function crearAdaptador(perfil) {
    const selectores = perfil.selectores;

    function extraerCorreoAbierto() {
      const contenedor = primero(document, selectores.contenedor) || document;
      const usandoDocumento = contenedor === document;

      const leerCuerpo = perfil.leerCuerpo || leerCuerpoGenerico;
      const leerRemitente = perfil.leerRemitente || leerRemitenteGenerico;

      let cuerpo = null;
      try {
        cuerpo = leerCuerpo(contenedor, selectores.cuerpo, api);
      } catch {
        // Un proveedor con lectura propia (p. ej. a través de un iframe) puede
        // lanzar; se trata como «no se pudo leer», no como caída del adaptador.
        cuerpo = null;
      }

      const remitente = leerRemitente(contenedor, selectores.remitente, api);
      const asuntoEl = primero(document, selectores.asunto);

      const diagnostico = [
        {
          campo: "contenedor del mensaje",
          ok: !usandoDocumento,
          selectores: selectores.contenedor,
        },
        { campo: "cuerpo", ok: Boolean(cuerpo && cuerpo.texto), selectores: selectores.cuerpo },
        { campo: "remitente", ok: Boolean(remitente), selectores: selectores.remitente },
        { campo: "asunto", ok: Boolean(asuntoEl), selectores: selectores.asunto },
      ];

      const adjuntos = todos(document, selectores.adjuntos)
        .map((el) => (el.getAttribute("title") || el.textContent || "").trim())
        .filter(Boolean);

      const correo = {
        asunto: asuntoEl ? asuntoEl.textContent.trim() : "",
        remitente: remitente || "",
        cuerpo_texto: cuerpo ? cuerpo.texto : "",
        cuerpo_html: cuerpo ? cuerpo.html : null,
        // Las cabeceras de autenticación (SPF/DKIM/DMARC) NO están en el DOM de
        // ningún webmail: viven detrás de «ver original», en otra vista. El
        // pipeline lo nota y emite `auth_ausente`, así que la carencia queda
        // registrada en el análisis en vez de pasar por «todo en orden».
        cabeceras: {},
        adjuntos: [...new Set(adjuntos)],
        origen: "extension",
      };

      // El mínimo para un veredicto con sentido es cuerpo + remitente.
      if (correo.cuerpo_texto && remitente) return { ok: true, correo, diagnostico };

      return { ok: false, diagnostico, parcial: correo };
    }

    /** Identidad estable del mensaje abierto, para no reanalizar lo mismo. */
    function idMensajeAbierto() {
      const contenedor = primero(document, selectores.contenedor);
      if (!contenedor) return null;

      for (const atributo of perfil.atributosId || []) {
        const valor = contenedor.getAttribute(atributo);
        if (valor) return valor;
      }
      const asuntoEl = primero(document, selectores.asunto);
      return (asuntoEl && asuntoEl.textContent.trim()) || "mensaje-abierto";
    }

    return {
      id: perfil.id,
      nombre: perfil.nombre,
      raizObservada: perfil.raizObservada || ['div[role="main"]'],
      extraerCorreoAbierto,
      idMensajeAbierto,
      SELECTORES: selectores,
    };
  }

  const api = {
    primero,
    todos,
    direccionEn,
    leerRemitenteGenerico,
    leerCuerpoGenerico,
    crearAdaptador,
    elegirPerfil,
    registrar(perfil) {
      window.PhishGuardProveedores.push(perfil);
      return perfil;
    },
  };

  window.PhishGuardProveedores = window.PhishGuardProveedores || [];
  window.PhishGuardComun = api;
})();
