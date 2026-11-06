// Host unit tests for web/app.js OATH fail-closed contract (no browser, no board).
// Run: node --test web/totp.test.cjs
//
// Contract under test:
//  1. sem sessão hardware viva -> sem código (estado vazio/bloqueado);
//  2. segredo OATH nunca é persistido nem armazenado (sem disco/prefs,
//     sem campo `secret` no store em memória);
//  3. códigos vêm SOMENTE de release pontual do device (verbatim,
//     sem computação local de TOTP no app).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function loadLib() {
  const src = fs.readFileSync(__dirname + "/app.js", "utf8");
  const noop = () => {};
  const fakeEl = () => ({ addEventListener: noop, style: {}, textContent: "" });
  const sandbox = {
    module: { exports: {} },
    document: {
      addEventListener: noop,
      getElementById: () => null,
      querySelectorAll: () => [],
      createElement: fakeEl,
    },
    window: {},
    navigator: {},
    setInterval: () => 0,
    crypto: {},
  };
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox, { filename: "app.js" });
  return vm.runInContext("module.exports", sandbox);
}

const LIVE = { connected: true, provisioned: true, unlocked: true };
const OFFLINE = { connected: false, provisioned: false, unlocked: false };
const LOCKED = { connected: true, provisioned: true, unlocked: false };

function deviceRelease() {
  return [
    { issuer: "Example", account: "user@example.com", code: "123456", remainingSeconds: 17 },
  ];
}

test("sem sessão (desconectado) -> sem código", () => {
  const lib = loadLib();
  const out = lib.setOathReleases(deviceRelease(), OFFLINE);
  assert.equal(out.length, 0);
  assert.equal(lib.getOathReleases().length, 0);
  assert.equal(lib.isOathLive(OFFLINE), false);
});

test("sem sessão (cofre bloqueado) -> sem código", () => {
  const lib = loadLib();
  const out = lib.setOathReleases(deviceRelease(), LOCKED);
  assert.equal(out.length, 0);
  assert.equal(lib.getOathReleases().length, 0);
  assert.equal(lib.isOathLive(LOCKED), false);
});

test("link ausente/inválido -> sem código", () => {
  const lib = loadLib();
  assert.equal(lib.setOathReleases(deviceRelease(), null).length, 0);
  assert.equal(lib.setOathReleases(deviceRelease(), undefined).length, 0);
  assert.equal(lib.setOathReleases("123456", LIVE).length, 0);
  assert.equal(lib.getOathReleases().length, 0);
});

test("com sessão viva -> libera códigos verbatim do device", () => {
  const lib = loadLib();
  const out = lib.setOathReleases(deviceRelease(), LIVE);
  assert.equal(out.length, 1);
  assert.equal(out[0].code, "123456");
  assert.equal(out[0].account, "user@example.com");
  assert.equal(lib.isOathLive(LIVE), true);
});

test("segredo nunca entra no store (campo secret é descartado)", () => {
  const lib = loadLib();
  const out = lib.setOathReleases(
    [{ account: "x", code: "654321", secret: "JBSWY3DPEHPK3PXP", remainingSeconds: 10 }],
    LIVE,
  );
  assert.equal(out.length, 1);
  assert.equal("secret" in out[0], false);
  assert.equal(JSON.stringify(out).includes("JBSWY3DPEHPK3PXP"), false);
});

test("código não-numérico do device é rejeitado (nada vivo)", () => {
  const lib = loadLib();
  assert.equal(lib.setOathReleases([{ account: "x", code: "344017 " }], LIVE).length, 0);
  assert.equal(lib.setOathReleases([{ account: "x", code: "abcdef" }], LIVE).length, 0);
  assert.equal(lib.getOathReleases().length, 0);
});

test("app não inventa TOTP local: sem API de computação exportada", () => {
  const lib = loadLib();
  for (const name of ["totpRfc6238", "generateMockTotp", "base32Decode", "sha1Bytes", "hmacSha1", "OATH_DEMO_ENABLED"]) {
    assert.equal(lib[name], undefined, `${name} não deve existir`);
  }
  assert.equal(typeof lib.OATH_LOCKED_PLACEHOLDER, "string");
});

test("segredo nunca em disco/prefs: app.js sem persistência nem segredo embutido", () => {
  const src = fs.readFileSync(__dirname + "/app.js", "utf8");
  assert.match(src, /nunca armazena segredos|never stores/i);
  assert.doesNotMatch(src, /localStorage/);
  assert.doesNotMatch(src, /sessionStorage/);
  assert.doesNotMatch(src, /JBSWY3DPEHPK3PXP/);
  assert.doesNotMatch(src, /KRSXG5CTMVRXEZLU/);
});

test("index.html pré-JS nunca exibe código vivo", () => {
  const html = fs.readFileSync(__dirname + "/index.html", "utf8");
  assert.doesNotMatch(html, />\d{3} \d{3}</);
  assert.doesNotMatch(html, /data-code="\d+"/);
  assert.match(html, /SEM SESSÃO/);
});
