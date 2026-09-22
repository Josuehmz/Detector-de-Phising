/**
 * Selección del adaptador según el webmail en el que estemos.
 *
 * Se carga después del motor y de los perfiles, así que `PhishGuardProveedores`
 * ya está lleno. Su único trabajo es elegir uno y publicar la misma superficie
 * que antes exponía el adaptador de Gmail, para que `overlay.js` no tenga que
 * saber en qué producto corre.
 *
 * Si ningún perfil reconoce el host, NO se publica adaptador. `overlay.js`
 * comprueba eso y no inyecta nada: una extensión que pinta un botón en una
 * página que no sabe leer solo consigue que el usuario pulse y no pase nada.
 */

(() => {
  "use strict";

  const comun = window.PhishGuardComun;
  const perfil = comun.elegirPerfil(location.hostname, window.PhishGuardProveedores);

  if (!perfil) {
    console.log(
      "[PhishGuard] " +
        location.hostname +
        " no coincide con ningún proveedor conocido; el overlay no se activa."
    );
    return;
  }

  window.PhishGuardAdaptador = comun.crearAdaptador(perfil);
  window.PhishGuardAdaptador.verificado = perfil.verificado === true;

  console.log(
    "[PhishGuard] adaptador de " +
      perfil.nombre +
      " cargado" +
      (perfil.verificado ? "" : " (selectores SIN verificar contra la página real)")
  );
})();
