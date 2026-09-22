/**
 * Pruebas del enrutado de proveedores de la extensión.
 *
 * Qué prueban y qué NO
 * --------------------
 * Prueban lo único de la extensión que es lógica pura y verificable sin un
 * navegador: **a qué perfil se asigna un host**, y que el manifiesto y los
 * perfiles no se contradigan.
 *
 * NO prueban los selectores. Un selector solo se puede validar contra la página
 * real del webmail, y ninguno de los cuatro perfiles se ha comprobado ahí
 * todavía (`verificado: false`). Decirlo importa: una suite verde aquí no
 * significa que la extensión sepa leer un correo de Outlook.
 *
 * Se ejecutan sin instalar nada, desde `extension/`:
 *
 *     node --test tests/proveedores.test.mjs
 *
 * Los archivos de `content/` son scripts clásicos, no módulos, así que se
 * cargan en un contexto de `node:vm` con un `window` de mentira. Es la forma de
 * probarlos sin convertir la extensión a módulos ni añadir un empaquetador a un
 * proyecto que a propósito se carga descomprimido.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const RAIZ = path.resolve(import.meta.dirname, "..");

const ARCHIVOS_PERFILES = [
  "content/proveedores/gmail.js",
  "content/proveedores/outlook.js",
  "content/proveedores/yahoo.js",
  "content/proveedores/proton.js",
];

/** Carga el motor y los perfiles en un contexto aislado y devuelve su `window`. */
function cargarProveedores() {
  const contexto = vm.createContext({
    window: {},
    console: { log() {}, warn() {} },
  });

  for (const relativo of ["content/adaptador-comun.js", ...ARCHIVOS_PERFILES]) {
    const archivo = path.join(RAIZ, relativo);
    vm.runInContext(fs.readFileSync(archivo, "utf8"), contexto, { filename: archivo });
  }
  return contexto.window;
}

const manifiesto = JSON.parse(fs.readFileSync(path.join(RAIZ, "manifest.json"), "utf8"));

/** `https://*.mail.yahoo.com/*` -> `sub.mail.yahoo.com` (un host concreto que probar). */
function hostDeMatch(match) {
  return new URL(match.replace("://*.", "://sub.")).hostname;
}

test("cada host del manifiesto tiene un perfil que lo reconoce", () => {
  const { PhishGuardComun, PhishGuardProveedores } = cargarProveedores();

  for (const match of manifiesto.content_scripts[0].matches) {
    const host = hostDeMatch(match);
    const perfil = PhishGuardComun.elegirPerfil(host, PhishGuardProveedores);
    assert.ok(
      perfil,
      `El manifiesto inyecta la extensión en ${host} pero ningún perfil lo reconoce: ` +
        "el usuario vería el botón y al pulsarlo no pasaría nada."
    );
  }
});

test("todos los perfiles están declarados en el manifiesto", () => {
  const declarados = manifiesto.content_scripts[0].js;
  for (const archivo of ARCHIVOS_PERFILES) {
    assert.ok(
      declarados.includes(archivo),
      `${archivo} existe pero el manifiesto no lo carga: su webmail quedaría sin soporte.`
    );
  }
});

test("el motor se carga antes que los perfiles, y la selección después", () => {
  const js = manifiesto.content_scripts[0].js;
  const motor = js.indexOf("content/adaptador-comun.js");
  const seleccion = js.indexOf("content/adaptador.js");
  const overlay = js.indexOf("content/overlay.js");

  assert.equal(motor, 0, "El motor común define `registrar`; si no va primero, los perfiles fallan.");
  for (const perfil of ARCHIVOS_PERFILES) {
    const posicion = js.indexOf(perfil);
    assert.ok(posicion > motor && posicion < seleccion, `${perfil} está fuera de orden.`);
  }
  assert.ok(seleccion < overlay, "El overlay lee el adaptador ya elegido.");
});

test("cada host conocido va a su proveedor", () => {
  const { PhishGuardComun, PhishGuardProveedores } = cargarProveedores();
  const elegir = (host) =>
    PhishGuardComun.elegirPerfil(host, PhishGuardProveedores)?.id ?? null;

  assert.equal(elegir("mail.google.com"), "gmail");
  assert.equal(elegir("outlook.live.com"), "outlook");
  assert.equal(elegir("outlook.office.com"), "outlook");
  assert.equal(elegir("outlook.office365.com"), "outlook");
  assert.equal(elegir("outlook.cloud.microsoft"), "outlook");
  assert.equal(elegir("mail.yahoo.com"), "yahoo");
  assert.equal(elegir("es.mail.yahoo.com"), "yahoo");
  assert.equal(elegir("mail.proton.me"), "proton");
});

test("una cuenta de Hotmail cae en el perfil de Outlook", () => {
  // No hay host `hotmail.com` que soportar: una cuenta @hotmail.com inicia
  // sesión y termina sirviéndose desde outlook.live.com. Esta prueba fija esa
  // suposición, para que se note el día que Microsoft la cambie.
  const { PhishGuardComun, PhishGuardProveedores } = cargarProveedores();
  const perfil = PhishGuardComun.elegirPerfil("outlook.live.com", PhishGuardProveedores);

  assert.equal(perfil.id, "outlook");
  assert.match(perfil.nombre, /Hotmail/);
});

test("un host que solo CONTIENE el dominio de un webmail no lo activa", () => {
  // La prueba que justifica usar expresiones ancladas y no `includes`. Un
  // atacante que registre `mail.google.com.phishing.example` no debe conseguir
  // que una extensión de seguridad se comporte como si estuviera en Gmail.
  const { PhishGuardComun, PhishGuardProveedores } = cargarProveedores();
  const elegir = (host) => PhishGuardComun.elegirPerfil(host, PhishGuardProveedores);

  assert.equal(elegir("mail.google.com.phishing.example"), null);
  assert.equal(elegir("outlook.live.com.evil.test"), null);
  assert.equal(elegir("notmail.google.com.attacker.test"), null);
  assert.equal(elegir("example.com"), null);
  assert.equal(elegir(""), null);
});

test("el host se compara sin distinguir mayúsculas", () => {
  const { PhishGuardComun, PhishGuardProveedores } = cargarProveedores();
  const perfil = PhishGuardComun.elegirPerfil("MAIL.GOOGLE.COM", PhishGuardProveedores);
  assert.equal(perfil?.id, "gmail");
});

test("ningún perfil se declara verificado mientras no se compruebe en la página real", () => {
  // Fija una limitación conocida, igual que la prueba del 0,496 en el backend.
  // El día que alguien compruebe un perfil contra su webmail y ponga
  // `verificado: true`, esta prueba falla y obliga a actualizar la lista de
  // pendientes en vez de dejar el cambio sin registrar.
  const { PhishGuardProveedores } = cargarProveedores();

  assert.equal(PhishGuardProveedores.length, 4);
  for (const perfil of PhishGuardProveedores) {
    assert.equal(
      perfil.verificado,
      false,
      `El perfil ${perfil.id} dice estar verificado; actualiza la documentación del proyecto.`
    );
  }
});

test("todo perfil trae los cinco campos de selectores que el motor consulta", () => {
  const { PhishGuardProveedores } = cargarProveedores();

  for (const perfil of PhishGuardProveedores) {
    for (const campo of ["contenedor", "asunto", "remitente", "cuerpo", "adjuntos"]) {
      const lista = perfil.selectores[campo];
      assert.ok(
        Array.isArray(lista) && lista.length > 0,
        `El perfil ${perfil.id} no define selectores para «${campo}».`
      );
    }
  }
});
