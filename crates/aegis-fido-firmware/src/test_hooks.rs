//! Manifesto dos gatilhos de teste (TEST-hooks): nomes inertes + tripwire.
//!
//! CI-GREP: TEST-HOOK-MANIFEST — este arquivo é a ÚNICA fonte de nomes
//! `TEST_*` fora de `#[cfg(test)]`. Regras:
//!
//! 1. Nomes aqui são SÓ strings (nenhum comportamento). Comportamento de
//!    teste vive SEMPRE atrás de `#[cfg(feature = "test-mode")]` no
//!    handler (ver `docs/test-hooks.md` p/ o mapa handler-por-hook).
//! 2. Release (`test-mode` OFF, default) NÃO contém nenhum handler: o
//!    `scripts/check-release-clean.py` prova por strings do artefato.
//! 3. Hook novo = constante aqui + handler gated + linha em
//!    `docs/test-hooks.md` + marca `CI-GREP: TEST-HOOK` no handler.
//!    O teste `manifest_bate_com_docs` quebra se faltar doc.
//!
//! Comportamento de teste NUNCA entra em release; na dúvida, gateia.

extern crate alloc;

/// Todos os comandos de texto aceitos SÓ em firmware test-mode (D1/UART).
pub const TEST_COMMANDS: &[&str] = &[
    "TEST_UP",
    "TEST_DOWNLOAD",
    "TEST_PAIRING_OPEN",
    "TEST_PAIRING_OPEN_300",
    "TEST_LIFETIME_DUMP",
    "TEST_LED_STATE",
    "TEST_LED_RED",
    "TEST_LED_GREEN",
    "TEST_LED_BLUE",
    "TEST_LED_OFF",
    "TEST_LED_RELEASE",
];

/// Bypasses de gate que só existem com `test-mode` (via `cfg!`, sem handler).
pub const TEST_BYPASSES: &[&str] = &[
    "binding_bypass",
    "release_bypass",
    "devkey_persist",
    "ota_test_key",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Tripwire: cada hook precisa estar documentado em `docs/test-hooks.md`.
    /// Quebrou? Adicione o hook na tabela `Hook | Handler gated | Release`.
    #[test]
    fn manifest_bate_com_docs() {
        let md = include_str!("../../../docs/test-hooks.md");
        for cmd in TEST_COMMANDS {
            assert!(
                md.contains(cmd),
                "hook {cmd} sem linha em docs/test-hooks.md"
            );
        }
        for b in TEST_BYPASSES {
            assert!(md.contains(b), "bypass {b} sem linha em docs/test-hooks.md");
        }
    }

    #[test]
    fn sem_duplicata_nem_vazio() {
        for (i, a) in TEST_COMMANDS.iter().enumerate() {
            assert!(!a.is_empty());
            for b in &TEST_COMMANDS[..i] {
                assert!(a != b, "duplicata {a}");
            }
        }
    }
}
