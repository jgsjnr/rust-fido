// Host unit test for web/app.js TOTP RFC 6238 (no browser, no board).
// Run: node --test web/totp.test.cjs
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
  // Provide minimal browser stubs so top-level DOM code is not executed:
  // app.js only defines functions at load; nothing runs until called.
  vm.runInContext(src, sandbox, { filename: "app.js" });
  // The module.exports assignment runs inside the VM context; read it back.
  return vm.runInContext("module.exports", sandbox);
}

const SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"

test("RFC 6238 SHA-1 vectors (8 digits)", () => {
  const lib = loadLib();
  assert.equal(lib.totpRfc6238(SECRET_B32, 59, 8, 30), "94287082");
  assert.equal(lib.totpRfc6238(SECRET_B32, 1111111109, 8, 30), "07081804");
  assert.equal(lib.totpRfc6238(SECRET_B32, 1234567890, 8, 30), "89005924");
});

test("RFC 6238 6-digit truncation", () => {
  const lib = loadLib();
  assert.equal(lib.totpRfc6238(SECRET_B32, 59, 6, 30), "287082");
  assert.equal(lib.totpRfc6238(SECRET_B32, 1111111109, 6, 30), "081804");
});

test("demo disabled by default; mock is DEMO-only", () => {
  const lib = loadLib();
  assert.equal(lib.OATH_DEMO_ENABLED, false);
});

test("invalid secret fails closed", () => {
  const lib = loadLib();
  assert.throws(() => lib.totpRfc6238("!!!", 59, 6, 30), /invalid secret/);
});
