//! T-UI-02 LED so sob comando autenticado (GEN-DEVICE).
//!
//! Motivo: o LED indica estado de seguranca (UP/Auth/erro); comando
//! falsificavel permite spoofing da indicacao e phishing fisico (secao 9).
//!
//! - Cada `LedCommand` carrega `tag = HMAC-SHA256(chave, dominio||efeito||
//!   cor||nonce)`; sem tag valida nao ha efeito (fail-closed).
//! - Nonce estritamente monotonico: replay e reordenacao sao negados.
//! - Nao edita `led.rs`: converte para `LedEffect` via `to_effect`.
//! - Chave do comando apaga na queda do `LedPolicy`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::led::{Color, LedEffect};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Dominio da tag (separa este protocolo de outros HMACs do device).
pub const LED_DOMAIN: &[u8] = b"AEGIS-LED-v1";
/// Maior codigo de efeito aceito (0=Off 1=Solid 2=Prompt 3=Sucesso 4=Erro).
pub const LED_MAX_EFFECT: u8 = 4;

/// Comando de LED autenticado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedCommand {
    pub effect: u8,
    pub color: [u8; 3],
    pub nonce: u64,
    pub tag: [u8; 32],
}

/// Erros de autorizacao. Sem cor/chave nas variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedAuthError {
    BadTag,
    Replay,
    StaleNonce,
    UnknownEffect,
}

/// Politica: guarda a chave e o ultimo nonce aceito.
pub struct LedPolicy {
    key: [u8; 32],
    last_nonce: u64,
}

impl LedPolicy {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, last_nonce: 0 }
    }

    /// Calcula a tag de um comando (lado do emissor autorizado).
    pub fn tag_for(&self, effect: u8, color: [u8; 3], nonce: u64) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(&self.key).expect("chave de 32 bytes");
        m.update(LED_DOMAIN);
        m.update(&[effect]);
        m.update(&color);
        m.update(&nonce.to_be_bytes());
        m.finalize().into_bytes().into()
    }

    /// Autoriza e converte em efeito; atualiza o nonce (uso unico ordenado).
    pub fn authorize(&mut self, cmd: &LedCommand) -> Result<LedEffect, LedAuthError> {
        if cmd.effect > LED_MAX_EFFECT {
            return Err(LedAuthError::UnknownEffect);
        }
        let expect = self.tag_for(cmd.effect, cmd.color, cmd.nonce);
        if !ct_eq(&expect, &cmd.tag) {
            return Err(LedAuthError::BadTag);
        }
        if cmd.nonce == self.last_nonce {
            return Err(LedAuthError::Replay);
        }
        if cmd.nonce < self.last_nonce {
            return Err(LedAuthError::StaleNonce);
        }
        self.last_nonce = cmd.nonce;
        Ok(to_effect(cmd.effect, cmd.color))
    }
}

impl Drop for LedPolicy {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn to_effect(effect: u8, color: [u8; 3]) -> LedEffect {
    match effect {
        0 => LedEffect::Off,
        1 => LedEffect::Solid(Color::new(color[0], color[1], color[2])),
        2 => LedEffect::PromptTouch,
        3 => LedEffect::AuthSuccessPulse,
        4 => LedEffect::ErrorFlash,
        _ => LedEffect::Off,
    }
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> LedPolicy {
        LedPolicy::new([0x11u8; 32])
    }

    fn cmd_for(pol: &LedPolicy, effect: u8, color: [u8; 3], nonce: u64) -> LedCommand {
        LedCommand {
            effect,
            color,
            nonce,
            tag: pol.tag_for(effect, color, nonce),
        }
    }

    #[test]
    fn valid_command_maps_effect() {
        let mut pol = policy();
        let cmd = cmd_for(&pol, 1, [255, 0, 0], 1);
        assert_eq!(
            pol.authorize(&cmd),
            Ok(LedEffect::Solid(Color::new(255, 0, 0)))
        );
        let cmd = cmd_for(&pol, 3, [0, 0, 0], 2);
        assert_eq!(pol.authorize(&cmd), Ok(LedEffect::AuthSuccessPulse));
    }

    #[test]
    fn forged_tag_denied() {
        let mut pol = policy();
        let mut cmd = cmd_for(&pol, 3, [0, 0, 0], 1);
        cmd.tag[0] ^= 0x01;
        assert_eq!(pol.authorize(&cmd), Err(LedAuthError::BadTag));
        // Tag zerada (comando "nao autenticado") tambem falha.
        cmd.tag = [0u8; 32];
        assert_eq!(pol.authorize(&cmd), Err(LedAuthError::BadTag));
        // Cor adulterada invalida a tag.
        let mut cmd = cmd_for(&pol, 1, [255, 0, 0], 1);
        cmd.color = [0, 255, 0];
        assert_eq!(pol.authorize(&cmd), Err(LedAuthError::BadTag));
    }

    #[test]
    fn replay_and_reorder_denied() {
        let mut pol = policy();
        let cmd = cmd_for(&pol, 4, [0, 0, 0], 5);
        pol.authorize(&cmd).expect("primeiro uso");
        assert_eq!(pol.authorize(&cmd), Err(LedAuthError::Replay));
        let old = cmd_for(&pol, 4, [0, 0, 0], 4);
        assert_eq!(pol.authorize(&old), Err(LedAuthError::StaleNonce));
    }

    #[test]
    fn unknown_effect_denied() {
        let mut pol = policy();
        let cmd = cmd_for(&pol, 9, [0, 0, 0], 1);
        assert_eq!(pol.authorize(&cmd), Err(LedAuthError::UnknownEffect));
    }
}
