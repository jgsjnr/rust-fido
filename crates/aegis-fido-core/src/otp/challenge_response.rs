extern crate alloc;

use alloc::vec::Vec;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha1::Sha1;
use zeroize::Zeroize;

use crate::oath::presence::{PresenceError, PresenceVerifier};

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotIndex {
    Slot1 = 1,
    Slot2 = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeResponseError {
    SlotNotConfigured,
    TouchRequired,
    TouchTimeout,
    InvalidChallengeLength,
    CryptoError,
}

/// Configuration for a YubiKey Challenge-Response slot
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChallengeResponseSlot {
    pub key: Vec<u8>,
    pub require_touch: bool,
    pub is_configured: bool,
}

impl ChallengeResponseSlot {
    pub fn new(key: &[u8], require_touch: bool) -> Self {
        Self {
            key: key.to_vec(),
            require_touch,
            is_configured: true,
        }
    }

    /// Process a challenge and return the 20-byte HMAC-SHA1 response
    pub fn calculate<P: PresenceVerifier>(
        &self,
        challenge: &[u8],
        presence: &mut P,
    ) -> Result<[u8; 20], ChallengeResponseError> {
        if !self.is_configured {
            return Err(ChallengeResponseError::SlotNotConfigured);
        }

        if self.require_touch {
            match presence.wait_for_presence(3000) {
                Ok(true) => {}
                Ok(false) => return Err(ChallengeResponseError::TouchRequired),
                Err(PresenceError::Timeout) => return Err(ChallengeResponseError::TouchTimeout),
                Err(_) => return Err(ChallengeResponseError::TouchRequired),
            }
        }

        let mut mac =
            HmacSha1::new_from_slice(&self.key).map_err(|_| ChallengeResponseError::CryptoError)?;
        mac.update(challenge);
        let result = mac.finalize().into_bytes();

        let mut resp = [0u8; 20];
        resp.copy_from_slice(&result);
        Ok(resp)
    }
}

/// Dual-slot Challenge-Response Manager (Slot 1 & Slot 2)
#[derive(Debug, Clone, Default)]
pub struct ChallengeResponseManager {
    pub slot1: ChallengeResponseSlot,
    pub slot2: ChallengeResponseSlot,
}

impl ChallengeResponseManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn configure_slot(&mut self, slot: SlotIndex, key: &[u8], require_touch: bool) {
        let slot_ref = match slot {
            SlotIndex::Slot1 => &mut self.slot1,
            SlotIndex::Slot2 => &mut self.slot2,
        };
        *slot_ref = ChallengeResponseSlot::new(key, require_touch);
    }

    pub fn clear_slot(&mut self, slot: SlotIndex) {
        let slot_ref = match slot {
            SlotIndex::Slot1 => &mut self.slot1,
            SlotIndex::Slot2 => &mut self.slot2,
        };
        *slot_ref = ChallengeResponseSlot::default();
    }

    pub fn process_challenge<P: PresenceVerifier>(
        &self,
        slot: SlotIndex,
        challenge: &[u8],
        presence: &mut P,
    ) -> Result<[u8; 20], ChallengeResponseError> {
        match slot {
            SlotIndex::Slot1 => self.slot1.calculate(challenge, presence),
            SlotIndex::Slot2 => self.slot2.calculate(challenge, presence),
        }
    }
}

// ============================================================================
// Ed25519 challenge-response via WinUSB bulk + AEGN envelope + app verify.
// Só Ed25519 (sem RSA, sem secure boot). Reusa `ed25519-dalek` das curvas
// existentes e o framing AEGN (MAGIC + VER + min len) do vault/bridge.
// Fluxo: device gera challenge 32B via TRNG -> assina Ed25519 (64B) ->
// envelope AEGN (101B) via WinUSB bulk -> app valida envelope + verifica.
// ============================================================================

/// Tamanho do challenge anti-replay (TRNG 32B, mesmo de `binding`).
pub const ED25519_CHALLENGE_LEN: usize = 32;
/// Assinatura Ed25519 raw (64B, mesmo formato de `crypto::curves`).
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Pubkey Ed25519 (32B).
pub const ED25519_PUBKEY_LEN: usize = 32;
/// Magic do envelope de verificação (AEGN, byte-idêntico ao vault/bridge).
pub const CHALLENGE_ENVELOPE_MAGIC: [u8; 4] = [0x41, 0x45, 0x47, 0x4E];
/// Versão do envelope de verificação (0x01, mesma do AEGN v1).
pub const CHALLENGE_ENVELOPE_VERSION: u8 = 0x01;
/// Envelope mínimo: MAGIC[4] + VER[1] + challenge[32] + sig[64].
pub const CHALLENGE_ENVELOPE_MIN_LEN: usize = 4 + 1 + 32 + 64;
/// Tamanho do payload verificado: challenge[32] + sig[64].
pub const CHALLENGE_VERIFIED_PAYLOAD_LEN: usize = 32 + 64;

/// Erro tipado do challenge Ed25519 (sem panics, sem stringly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519ChallengeError {
    InvalidChallengeLength,
    InvalidSignature,
    InvalidPublicKey,
    InvalidEnvelope,
    NoActiveChallenge,
    Replay,
    CryptoError,
}

impl core::fmt::Display for Ed25519ChallengeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidChallengeLength => write!(f, "invalid challenge length"),
            Self::InvalidSignature => write!(f, "invalid ed25519 signature"),
            Self::InvalidPublicKey => write!(f, "invalid ed25519 public key"),
            Self::InvalidEnvelope => write!(f, "invalid challenge envelope"),
            Self::NoActiveChallenge => write!(f, "no active challenge"),
            Self::Replay => write!(f, "challenge already used"),
            Self::CryptoError => write!(f, "challenge crypto failure"),
        }
    }
}

/// Gerente do challenge Ed25519 (lado device; RAM, zeroize no Drop).
///
/// Guarda o segredo Ed25519 (32B) + último challenge ativo (uso único).
/// `new_challenge` invalida o anterior; `respond_active` assina e consome.
pub struct Ed25519ChallengeManager {
    secret: [u8; ED25519_CHALLENGE_LEN],
    active: Option<[u8; ED25519_CHALLENGE_LEN]>,
}

impl Drop for Ed25519ChallengeManager {
    fn drop(&mut self) {
        self.secret.zeroize();
        if let Some(ref mut c) = self.active {
            c.zeroize();
        }
        self.active = None;
    }
}

impl Ed25519ChallengeManager {
    /// Reconstrói a partir do seed de 32B (provisionado em fábrica).
    pub fn from_seed(seed: &[u8; ED25519_CHALLENGE_LEN]) -> Self {
        Self {
            secret: *seed,
            active: None,
        }
    }

    /// Gera segredo fresco via TRNG (mesmo padrão de `KeyPair::generate`).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut secret = [0u8; ED25519_CHALLENGE_LEN];
        rng.fill_bytes(&mut secret);
        Self {
            secret,
            active: None,
        }
    }

    /// Pubkey Ed25519 (32B) para provisionar no app (verificação).
    pub fn verifying_key_bytes(&self) -> [u8; ED25519_PUBKEY_LEN] {
        let sk = SigningKey::from_bytes(&self.secret);
        sk.verifying_key().to_bytes()
    }

    /// Challenge ativo atual (cópia, sem borrow).
    pub fn active_challenge(&self) -> Option<[u8; ED25519_CHALLENGE_LEN]> {
        self.active
    }

    /// Emite challenge 32B via TRNG; invalida o anterior (só o último vale).
    pub fn new_challenge<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> [u8; ED25519_CHALLENGE_LEN] {
        let mut challenge = [0u8; ED25519_CHALLENGE_LEN];
        rng.fill_bytes(&mut challenge);
        if let Some(ref mut old) = self.active {
            old.zeroize();
        }
        self.active = Some(challenge);
        challenge
    }

    /// Assina o challenge ativo e retorna o envelope AEGN (101B).
    /// Consome o challenge (uso único; replay posterior nega com `Replay`).
    pub fn respond_active(&mut self) -> Result<Vec<u8>, Ed25519ChallengeError> {
        let challenge = match self.active {
            Some(c) => c,
            None => return Err(Ed25519ChallengeError::Replay),
        };
        let sk = SigningKey::from_bytes(&self.secret);
        let sig = sk.sign(&challenge);
        let envelope = seal_challenge_envelope(&challenge, &sig.to_bytes());
        if let Some(ref mut active) = self.active {
            active.zeroize();
        }
        self.active = None;
        Ok(envelope)
    }

    /// Limpa o challenge ativo sem responder (aborta a sessão).
    pub fn clear(&mut self) {
        if let Some(ref mut c) = self.active {
            c.zeroize();
        }
        self.active = None;
    }
}

/// Monta o envelope de verificação: MAGIC[4] + VER[1] + challenge[32] + sig[64].
pub fn seal_challenge_envelope(
    challenge: &[u8; ED25519_CHALLENGE_LEN],
    signature: &[u8; ED25519_SIGNATURE_LEN],
) -> Vec<u8> {
    let mut env = Vec::with_capacity(CHALLENGE_ENVELOPE_MIN_LEN);
    env.extend_from_slice(&CHALLENGE_ENVELOPE_MAGIC);
    env.push(CHALLENGE_ENVELOPE_VERSION);
    env.extend_from_slice(challenge);
    env.extend_from_slice(signature);
    env
}

/// Valida o envelope (magic/ver/min len) e extrai challenge + assinatura.
pub fn parse_challenge_envelope(
    envelope: &[u8],
) -> Result<([u8; ED25519_CHALLENGE_LEN], [u8; ED25519_SIGNATURE_LEN]), Ed25519ChallengeError> {
    if envelope.len() < CHALLENGE_ENVELOPE_MIN_LEN {
        return Err(Ed25519ChallengeError::InvalidEnvelope);
    }
    if envelope[0..4] != CHALLENGE_ENVELOPE_MAGIC
        || envelope[4] != CHALLENGE_ENVELOPE_VERSION
    {
        return Err(Ed25519ChallengeError::InvalidEnvelope);
    }
    let mut challenge = [0u8; ED25519_CHALLENGE_LEN];
    let mut signature = [0u8; ED25519_SIGNATURE_LEN];
    challenge.copy_from_slice(&envelope[5..5 + ED25519_CHALLENGE_LEN]);
    signature.copy_from_slice(&envelope[5 + ED25519_CHALLENGE_LEN..5 + CHALLENGE_VERIFIED_PAYLOAD_LEN]);
    Ok((challenge, signature))
}

/// Verifica a resposta Ed25519 no app (challenge 32B + sig 64B + pubkey 32B).
pub fn verify_challenge_response(
    pubkey_bytes: &[u8; ED25519_PUBKEY_LEN],
    challenge: &[u8; ED25519_CHALLENGE_LEN],
    signature: &[u8; ED25519_SIGNATURE_LEN],
) -> Result<(), Ed25519ChallengeError> {
    let vk = VerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|_| Ed25519ChallengeError::InvalidPublicKey)?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    vk.verify(challenge, &sig)
        .map_err(|_| Ed25519ChallengeError::InvalidSignature)
}

/// Verificação completa no app via envelope: valida envelope + verifica Ed25519.
/// Retorna o challenge autenticado em caso de sucesso.
pub fn verify_challenge_envelope(
    pubkey_bytes: &[u8; ED25519_PUBKEY_LEN],
    envelope: &[u8],
) -> Result<[u8; ED25519_CHALLENGE_LEN], Ed25519ChallengeError> {
    let (challenge, signature) = parse_challenge_envelope(envelope)?;
    verify_challenge_response(pubkey_bytes, &challenge, &signature)?;
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oath::presence::{AlwaysPresentVerifier, NeverPresentVerifier};

    #[test]
    fn test_challenge_response_hmac_sha1() {
        let mut manager = ChallengeResponseManager::new();
        let key = b"01234567890123456789"; // 20-byte key
        manager.configure_slot(SlotIndex::Slot1, key, false);

        let challenge = b"test_challenge_123";
        let mut presence = AlwaysPresentVerifier;

        let resp = manager
            .process_challenge(SlotIndex::Slot1, challenge, &mut presence)
            .unwrap();

        // Verify against independent HMAC-SHA1 calculation
        let mut mac = HmacSha1::new_from_slice(key).unwrap();
        mac.update(challenge);
        let expected = mac.finalize().into_bytes();
        assert_eq!(&resp[..], &expected[..]);
    }

    #[test]
    fn test_challenge_response_touch_required() {
        let mut manager = ChallengeResponseManager::new();
        let key = b"secret_key_slot2_test";
        manager.configure_slot(SlotIndex::Slot2, key, true); // require touch

        let challenge = b"challenge_payload";
        let mut no_touch = NeverPresentVerifier;

        // Fails when touch is not satisfied
        let res = manager.process_challenge(SlotIndex::Slot2, challenge, &mut no_touch);
        assert_eq!(res, Err(ChallengeResponseError::TouchTimeout));

        // Succeeds when touch is confirmed
        let mut touch = AlwaysPresentVerifier;
        let res2 = manager.process_challenge(SlotIndex::Slot2, challenge, &mut touch);
        assert!(res2.is_ok());
    }

    #[test]
    fn should_emit_32b_trng_challenge_unique() {
        let mut rng = rand::rngs::OsRng;
        let seed = [0x42u8; ED25519_CHALLENGE_LEN];
        let mut manager = Ed25519ChallengeManager::from_seed(&seed);

        let ch1 = manager.new_challenge(&mut rng);
        assert_eq!(ch1.len(), ED25519_CHALLENGE_LEN);
        let ch2 = manager.new_challenge(&mut rng);
        assert_eq!(ch2.len(), ED25519_CHALLENGE_LEN);
        // TRNG: dois challenges seguidos divergem (prob. colisão 2^-256)
        assert_ne!(ch1, ch2);
        // Só o último vale (ativo == ch2)
        assert_eq!(manager.active_challenge(), Some(ch2));
    }

    #[test]
    fn should_sign_64b_and_verify_via_envelope_in_app() {
        let mut rng = rand::rngs::OsRng;
        let mut manager = Ed25519ChallengeManager::generate(&mut rng);
        let pubkey = manager.verifying_key_bytes();
        assert_eq!(pubkey.len(), ED25519_PUBKEY_LEN);

        let challenge = manager.new_challenge(&mut rng);
        let envelope = manager.respond_active().expect("respond once");
        assert_eq!(envelope.len(), CHALLENGE_ENVELOPE_MIN_LEN);
        assert_eq!(&envelope[0..4], &CHALLENGE_ENVELOPE_MAGIC);
        assert_eq!(envelope[4], CHALLENGE_ENVELOPE_VERSION);

        // App: valida envelope + verifica Ed25519
        let back = verify_challenge_envelope(&pubkey, &envelope).expect("app verify");
        assert_eq!(back, challenge);
    }

    #[test]
    fn should_deny_replay_single_use() {
        let mut rng = rand::rngs::OsRng;
        let mut manager = Ed25519ChallengeManager::generate(&mut rng);
        manager.new_challenge(&mut rng);
        assert!(manager.respond_active().is_ok());
        // Segundo respond sem novo challenge nega (uso único)
        assert_eq!(
            manager.respond_active(),
            Err(Ed25519ChallengeError::Replay)
        );
        assert_eq!(manager.active_challenge(), None);
    }

    #[test]
    fn should_reject_tampered_envelope_and_wrong_key() {
        let mut rng = rand::rngs::OsRng;
        let mut manager = Ed25519ChallengeManager::generate(&mut rng);
        let pubkey = manager.verifying_key_bytes();
        manager.new_challenge(&mut rng);
        let mut envelope = manager.respond_active().unwrap();

        // Tamper no challenge invalida a assinatura no app
        envelope[10] ^= 0xFF;
        assert_eq!(
            verify_challenge_envelope(&pubkey, &envelope),
            Err(Ed25519ChallengeError::InvalidSignature)
        );

        // Envelope íntegro com chave errada falha
        manager.new_challenge(&mut rng);
        let good = manager.respond_active().unwrap();
        let mut other_rng = rand::rngs::OsRng;
        let other = Ed25519ChallengeManager::generate(&mut other_rng);
        let wrong_pubkey = other.verifying_key_bytes();
        assert_eq!(
            verify_challenge_envelope(&wrong_pubkey, &good),
            Err(Ed25519ChallengeError::InvalidSignature)
        );

        // Magic/ver/tamanho inválidos mapeiam para InvalidEnvelope
        assert_eq!(
            parse_challenge_envelope(b"curto"),
            Err(Ed25519ChallengeError::InvalidEnvelope)
        );
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0xFF;
        assert_eq!(
            parse_challenge_envelope(&bad_magic),
            Err(Ed25519ChallengeError::InvalidEnvelope)
        );
        let mut bad_ver = good.clone();
        bad_ver[4] ^= 0xFF;
        assert_eq!(
            parse_challenge_envelope(&bad_ver),
            Err(Ed25519ChallengeError::InvalidEnvelope)
        );
    }
}
