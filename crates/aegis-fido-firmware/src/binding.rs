//! App binding — dono exclusivo das ops privilegiadas BLE vendor + WiFi mgmt.
//!
//! - `claim` na primeira configuracao: so `Unclaimed` + janela de pareamento
//!   aberta (hold 5s GPIO0, `PairingManager`) + UP. Grava `app_bind_pub`
//!   (SEC1 65B) + `app_bind_id` (16B) em NVS cifrada (`SecureStorage`,
//!   envelope AEGN v1, TRNG interno, zeroize apos uso).
//! - `challenge` 32B via TRNG, uso unico (anti-replay): so o ultimo emitido
//!   e valido; `verify` com sucesso o consome. Um challenge por op, pois a
//!   assinatura cobre `(challenge || op || payload_hash)`.
//! - `verify_binding`: assinatura P-256 (DER ou raw, mesma semantica de
//!   `aegis_fido_core::crypto::curves`) da chave do app (P-256 Keystore, nunca
//!   sai do celular) sobre `challenge || op || payload_hash`.
//! - `release`: via `release_signed` (assinado pela chave vinculada, op
//!   `BIND_OP_RELEASE`) OU `factory_reset` fisico (hold 5s + UP); ambos com
//!   wipe da NVS + zeroize da RAM e volta a `Unclaimed` (reclaim liberado).
//! - `NEED_BINDING (0x05)`: extensao §9.5-compativel, so BLE/WiFi —
//!   USB/CTAP (`aegis-fido-usb`, `CtapEngine`) nunca ve este erro.
//! - `no_std` compativel: sem alloc no hot path, sem I/O, relogio injetado
//!   pelo chamador onde aplicavel.
//!
//! CI-GREP: MOCK-ONLY-IN-TEST — `MockFlashBackend` so em `#[cfg(test)]`.

extern crate alloc;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::persistence::{FlashStorageBackend, SecureStorage, StorageError};
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};

/// Chave NVS da pubkey SEC1 do app vinculado (65B, envelope AEGN).
pub const BIND_PUB_NVS_KEY: &str = "app_bind_pub";
/// Chave NVS do binding id opaco (16B, envelope AEGN).
pub const BIND_ID_NVS_KEY: &str = "app_bind_id";
/// Tamanho do challenge anti-replay (TRNG 32B).
pub const BIND_CHALLENGE_LEN: usize = 32;
/// Pubkey do app em SEC1 uncompressed (`0x04 || X32 || Y32`).
pub const BIND_PUB_LEN: usize = 65;
/// Binding id opaco (sorteado pelo app, eco no claim).
pub const BIND_ID_LEN: usize = 16;
/// Hash do payload coberto pela assinatura (SHA-256, 32B).
pub const BIND_PAYLOAD_HASH_LEN: usize = 32;
/// Status vendor §9.5-compativel: precisa de binding (so BLE/WiFi, nunca USB).
pub const NEED_BINDING_STATUS: u8 = 0x05;
/// Status §9.5 existentes (golden, sem mudanca).
pub const VENDOR_STATUS_OK: u8 = 0x00;
/// Status §9.5 existentes (golden, sem mudanca).
pub const VENDOR_STATUS_NEED_UP: u8 = 0x01;
/// Status §9.5 existentes (golden, sem mudanca).
pub const VENDOR_STATUS_NEED_PIN: u8 = 0x02;
/// Status §9.5 existentes (golden, sem mudanca).
pub const VENDOR_STATUS_NO_SLOT: u8 = 0x03;
/// Status §9.5 existentes (golden, sem mudanca).
pub const VENDOR_STATUS_BAD_ENVELOPE: u8 = 0x04;
/// Op interno do `release_signed` (fora da faixa vendor 0x20-0x27 e CTAP-BLE).
pub const BIND_OP_RELEASE: u8 = 0x52;
/// Tamanho da mensagem assinada: `challenge(32) || op(1) || payload_hash(32)`.
pub const BIND_SIGNED_MSG_LEN: usize = BIND_CHALLENGE_LEN + 1 + BIND_PAYLOAD_HASH_LEN;
/// Nonce placeholder (ignorado, TRNG dentro de `store`).
const IGNORED_NONCE: [u8; 12] = [0u8; 12];

/// `true` quando `test-mode` esta ligado (gates de vinculo fazem bypass).
///
/// Release (feature OFF) = vinculo OBRIGATORIO para CONFIGURAR.
/// Teste (feature ON) = cripto app/chave DESABILITADA em teste; gates de
/// CONFIGURAR exigem so UP(+PIN), com `ltrace` (zero custo sem `debug-terminal`).
pub fn binding_bypass_enabled() -> bool {
    cfg!(feature = "test-mode")
}

/// Barreira de binding para ops CONFIG (GEN/IMPORT/DELETE/PUT/WiFi/claim-mgmt).
///
/// Release exige prova (`binding_ok` de `verify` uso unico); teste faz bypass
/// com `ltrace` (sempre `Ok`). USO (CODE/LIST/GetAssertion) nunca chama aqui
/// (ver `require_bound_usage`).
pub fn require_bound_config(binding_ok: bool) -> Result<(), BindingError> {
    if binding_ok {
        return Ok(());
    }
    if binding_bypass_enabled() {
        crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "binding-bypass");
        return Ok(());
    }
    Err(BindingError::NotClaimed)
}

/// USO (CODE/LIST/GetAssertion/display): nunca exige vinculo, so UP fisico.
///
/// O chamador (transporte) checa UP via `UpPolicy`; aqui sempre `Ok` para
/// deixar explicito que USO sem vinculo passa (senao keypass nao funciona).
pub fn require_bound_usage(_binding_ok: bool) -> Result<(), BindingError> {
    Ok(())
}

/// Erro tipado do binding (sem panics, sem stringly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// Ja existe dono (segundo claim negado).
    AlreadyClaimed,
    /// Sem dono (ou assinatura de chave estranha): app alheio ve NEED_BINDING.
    NotClaimed,
    /// UP ausente (mapeia NEED_UP).
    PresenceRequired,
    /// Janela de pareamento fechada (mapeia NEED_UP).
    PairingRequired,
    /// PIN ausente onde exigido (mapeia NEED_PIN).
    PinRequired,
    /// Pubkey SEC1 invalida (nao e ponto P-256).
    BadPubkey,
    /// Assinatura invalida (chave errada ou bytes malformados).
    BadSignature,
    /// Challenge desconhecido (de outro dono/sessao).
    ChallengeMismatch,
    /// Sem challenge ativo (ja consumido: replay negado).
    Replay,
    /// NVS inconsistente (parcial ou descriptografia falhou).
    Corrupted,
    /// Falha de storage.
    Storage,
}

impl core::fmt::Display for BindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyClaimed => write!(f, "already claimed"),
            Self::NotClaimed => write!(f, "binding required (NEED_BINDING 0x05)"),
            Self::PresenceRequired => write!(f, "presence required"),
            Self::PairingRequired => write!(f, "pairing window required"),
            Self::PinRequired => write!(f, "pin required"),
            Self::BadPubkey => write!(f, "bad app pubkey"),
            Self::BadSignature => write!(f, "bad binding signature"),
            Self::ChallengeMismatch => write!(f, "challenge mismatch"),
            Self::Replay => write!(f, "challenge already used"),
            Self::Corrupted => write!(f, "binding store corrupted"),
            Self::Storage => write!(f, "binding storage failure"),
        }
    }
}

impl BindingError {
    /// Status wire §9.5: `0x05` NEED_BINDING para tudo que e "nao e o dono";
    /// UP/PIN preservam `0x01`/`0x02`. USB nunca recebe este mapeamento.
    pub fn to_vendor_status(self) -> u8 {
        match self {
            Self::NotClaimed
            | Self::BadSignature
            | Self::ChallengeMismatch
            | Self::Replay
            | Self::BadPubkey => NEED_BINDING_STATUS,
            Self::PresenceRequired | Self::PairingRequired => VENDOR_STATUS_NEED_UP,
            Self::PinRequired => VENDOR_STATUS_NEED_PIN,
            Self::AlreadyClaimed | Self::Corrupted | Self::Storage => {
                VENDOR_STATUS_BAD_ENVELOPE
            }
        }
    }
}

impl From<StorageError> for BindingError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::KeyNotFound => Self::NotClaimed,
            StorageError::CorruptedEnvelope | StorageError::DecryptionFailed => {
                Self::Corrupted
            }
            StorageError::FlashWriteError | StorageError::BufferOverflow => Self::Storage,
        }
    }
}

/// Estado do vinculo com o app dono.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimState {
    /// Sem dono: so `claim` (primeira configuracao) e FIDO2 USB aberto.
    Unclaimed,
    /// Com dono: so a chave vinculada autoriza BLE vendor + WiFi mgmt.
    Claimed {
        /// Pubkey P-256 do app em SEC1 uncompressed (nunca sai do celular).
        app_pub: [u8; BIND_PUB_LEN],
        /// Id opaco do vinculo (eco, anti-confusao entre donos).
        binding_id: [u8; BIND_ID_LEN],
    },
}
/// Gerente do vinculo (RAM; NVS via `persist`/`load_from_storage`/`wipe`).
#[derive(Debug, Clone)]
pub struct BindingManager {
    state: ClaimState,
    /// Ultimo challenge emitido (unico valido; `None` = consumido/ausente).
    active_challenge: Option<[u8; BIND_CHALLENGE_LEN]>,
}

impl Drop for BindingManager {
    fn drop(&mut self) {
        self.zeroize_ram();
    }
}

impl BindingManager {
    /// Cria sem dono e sem challenge.
    pub fn new() -> Self {
        Self {
            state: ClaimState::Unclaimed,
            active_challenge: None,
        }
    }

    /// Estado atual (copia, sem borrow).
    pub fn state(&self) -> ClaimState {
        self.state
    }

    /// `true` quando ha dono vinculado.
    pub fn is_claimed(&self) -> bool {
        matches!(self.state, ClaimState::Claimed { .. })
    }

    /// `true` quando ha challenge ativo (unico valido).
    pub fn has_active_challenge(&self) -> bool {
        self.active_challenge.is_some()
    }

    /// Alimenta o tick monotonico (main loop chama todo poll).
    ///
    /// Hoje sem expiracao por tempo (challenge e uso unico, consumido no
    /// `verify`); o tick existe para fiacao `main` + futura expiracao sem
    /// quebrar a API. Sem I/O, sem alloc.
    pub fn tick(&mut self, _now_ms: u64) {
        // Intencionalmente sem efeito (uso unico ja garante anti-replay).
    }

    /// Zera segredos da RAM (chamado no `wipe` e no `Drop`).
    fn zeroize_ram(&mut self) {
        if let ClaimState::Claimed {
            ref mut app_pub,
            ref mut binding_id,
        } = self.state
        {
            app_pub.zeroize();
            binding_id.zeroize();
        }
        if let Some(ref mut challenge) = self.active_challenge {
            challenge.zeroize();
        }
        self.active_challenge = None;
    }

    /// Reivindica o device na primeira configuracao.
    ///
    /// Exige, nesta ordem: sem dono + janela de pareamento aberta (hold 5s)
    /// + UP + pubkey SEC1 valida (ponto P-256). Invalida challenge pendente.
    pub fn claim(
        &mut self,
        app_pub: &[u8; BIND_PUB_LEN],
        binding_id: &[u8; BIND_ID_LEN],
        pairing_window_open: bool,
        presence_confirmed: bool,
    ) -> Result<(), BindingError> {
        if self.is_claimed() {
            return Err(BindingError::AlreadyClaimed);
        }
        if !pairing_window_open {
            return Err(BindingError::PairingRequired);
        }
        if !presence_confirmed {
            return Err(BindingError::PresenceRequired);
        }
        decode_app_pubkey(app_pub)?;
        self.state = ClaimState::Claimed {
            app_pub: *app_pub,
            binding_id: *binding_id,
        };
        self.active_challenge = None;
        Ok(())
    }

    /// Emite challenge 32B via TRNG; invalida o anterior (so o ultimo vale).
    /// Exige dono (sem dono nao ha a quem autenticar).
    pub fn new_challenge<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<[u8; BIND_CHALLENGE_LEN], BindingError> {
        if !self.is_claimed() {
            return Err(BindingError::NotClaimed);
        }
        let mut challenge = [0u8; BIND_CHALLENGE_LEN];
        rng.fill_bytes(&mut challenge);
        self.active_challenge = Some(challenge);
        Ok(challenge)
    }

    /// Monta a mensagem assinada: `challenge || op || payload_hash` (65B).
    /// Pura e sem I/O (app e testes usam a mesma montagem).
    pub fn signed_message(
        challenge: &[u8; BIND_CHALLENGE_LEN],
        op: u8,
        payload_hash: &[u8; BIND_PAYLOAD_HASH_LEN],
    ) -> [u8; BIND_SIGNED_MSG_LEN] {
        let mut msg = [0u8; BIND_SIGNED_MSG_LEN];
        msg[..BIND_CHALLENGE_LEN].copy_from_slice(challenge);
        msg[BIND_CHALLENGE_LEN] = op;
        msg[BIND_CHALLENGE_LEN + 1..].copy_from_slice(payload_hash);
        msg
    }

    /// Verifica prova do dono: challenge ativo (uso unico) + assinatura P-256
    /// (DER ou raw) sobre `challenge || op || payload_hash`.
    ///
    /// Ordem: dono -> replay/uso-unico -> challenge -> assinatura.
    /// Sucesso consome o challenge (`None`); falha mantem o ativo para
    /// retry (replay do sucesso continua negado via `Replay`).
    pub fn verify(
        &mut self,
        sig: &[u8],
        challenge: &[u8; BIND_CHALLENGE_LEN],
        op: u8,
        payload_hash: &[u8; BIND_PAYLOAD_HASH_LEN],
    ) -> Result<(), BindingError> {
        let app_pub = match self.state {
            ClaimState::Claimed { app_pub, .. } => app_pub,
            ClaimState::Unclaimed => return Err(BindingError::NotClaimed),
        };
        let active = match self.active_challenge {
            Some(active) => active,
            None => return Err(BindingError::Replay),
        };
        if !ct_eq_32(&active, challenge) {
            return Err(BindingError::ChallengeMismatch);
        }
        let msg = Self::signed_message(challenge, op, payload_hash);
        verify_p256_sec1(&app_pub, &msg, sig)?;
        // Sucesso: consumo de uso unico (anti-replay).
        if let Some(ref mut active_mut) = self.active_challenge {
            active_mut.zeroize();
        }
        self.active_challenge = None;
        Ok(())
    }
    /// Gate combinado na ordem canonica: binding -> UP -> PIN.
    /// `requires_pin`: `true` nas privilegiadas (0x21/0x23/0x24/0x27 + WiFi
    /// mgmt), `false` em LIST/CODE (binding + UP).
    // Gate unico prova+politica (espelha a lista de args do handler); aridade fixa.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_with_pin(
        &mut self,
        sig: &[u8],
        challenge: &[u8; BIND_CHALLENGE_LEN],
        op: u8,
        payload_hash: &[u8; BIND_PAYLOAD_HASH_LEN],
        pin_authenticated: bool,
        presence_confirmed: bool,
        requires_pin: bool,
    ) -> Result<(), BindingError> {
        self.verify(sig, challenge, op, payload_hash)?;
        if !presence_confirmed {
            return Err(BindingError::PresenceRequired);
        }
        if requires_pin && !pin_authenticated {
            return Err(BindingError::PinRequired);
        }
        Ok(())
    }

    /// Carrega o vinculo da NVS: par presente e valido -> `Claimed`;
    /// par ausente -> `Unclaimed`; parcial/corrompido -> `Corrupted`.
    pub fn load_from_storage<B: FlashStorageBackend>(
        storage: &SecureStorage<B>,
    ) -> Result<Self, BindingError> {
        let raw_pub = storage.load(BIND_PUB_NVS_KEY);
        let raw_id = storage.load(BIND_ID_NVS_KEY);
        match (raw_pub, raw_id) {
            (Ok(pub_bytes), Ok(id_bytes)) => {
                if pub_bytes.len() != BIND_PUB_LEN || id_bytes.len() != BIND_ID_LEN {
                    return Err(BindingError::Corrupted);
                }
                let mut app_pub = [0u8; BIND_PUB_LEN];
                let mut binding_id = [0u8; BIND_ID_LEN];
                app_pub.copy_from_slice(&pub_bytes);
                binding_id.copy_from_slice(&id_bytes);
                decode_app_pubkey(&app_pub)?;
                Ok(Self {
                    state: ClaimState::Claimed {
                        app_pub,
                        binding_id,
                    },
                    active_challenge: None,
                })
            }
            (Err(StorageError::KeyNotFound), Err(StorageError::KeyNotFound)) => Ok(Self::new()),
            // Parcial (queda de energia no meio do persist): Corrupted, nunca
            // Unclaimed silencioso (bloqueia reclaim hostil; factory_reset recupera).
            (Err(StorageError::KeyNotFound), _) | (_, Err(StorageError::KeyNotFound)) => {
                Err(BindingError::Corrupted)
            }
            (Err(e), _) | (_, Err(e)) => Err(BindingError::from(e)),
        }
    }

    /// Persiste o vinculo (`Claimed`) com verify-after-write (padrao oath_store).
    /// `Unclaimed` nao grava nada (apaga resquicios e retorna `Ok`).
    pub fn persist<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
    ) -> Result<(), BindingError> {
        let (app_pub, binding_id) = match self.state {
            ClaimState::Claimed {
                ref app_pub,
                ref binding_id,
            } => (app_pub, binding_id),
            ClaimState::Unclaimed => {
                let _ = storage.delete(BIND_PUB_NVS_KEY);
                let _ = storage.delete(BIND_ID_NVS_KEY);
                return Ok(());
            }
        };
        storage.store(BIND_PUB_NVS_KEY, app_pub, &IGNORED_NONCE)?;
        storage.store(BIND_ID_NVS_KEY, binding_id, &IGNORED_NONCE)?;
        let back_pub = storage.load(BIND_PUB_NVS_KEY)?;
        let back_id = storage.load(BIND_ID_NVS_KEY)?;
        if back_pub.as_slice() != app_pub.as_slice() || back_id.as_slice() != binding_id.as_slice() {
            let _ = storage.delete(BIND_PUB_NVS_KEY);
            let _ = storage.delete(BIND_ID_NVS_KEY);
            return Err(BindingError::Storage);
        }
        Ok(())
    }

    /// Wipe total: apaga NVS, zera RAM e volta a `Unclaimed` (reclaim liberado).
    pub fn wipe<B: FlashStorageBackend>(&mut self, storage: &mut SecureStorage<B>) {
        let _ = storage.delete(BIND_PUB_NVS_KEY);
        let _ = storage.delete(BIND_ID_NVS_KEY);
        self.zeroize_ram();
        self.state = ClaimState::Unclaimed;
    }

    /// Transferencia: dono atual assina `challenge || BIND_OP_RELEASE ||
    /// sha256(binding_id)`; sucesso faz wipe (novo dono pode dar `claim`).
    pub fn release_signed<B: FlashStorageBackend>(
        &mut self,
        storage: &mut SecureStorage<B>,
        sig: &[u8],
        challenge: &[u8; BIND_CHALLENGE_LEN],
        payload_hash: &[u8; BIND_PAYLOAD_HASH_LEN],
    ) -> Result<(), BindingError> {
        self.verify(sig, challenge, BIND_OP_RELEASE, payload_hash)?;
        self.wipe(storage);
        Ok(())
    }

    /// Reset fisico de fabrica do vinculo: exige hold 5s confirmado + UP
    /// (chamador: caminho `LONG_PRESS_MS` do botao). Sem assinatura, com wipe.
    /// Nao toca em eFuse nem liga secure boot / flash encryption (proibido).
    pub fn factory_reset<B: FlashStorageBackend>(
        &mut self,
        storage: &mut SecureStorage<B>,
        hold_5s_confirmed: bool,
        presence_confirmed: bool,
    ) -> Result<(), BindingError> {
        if !hold_5s_confirmed {
            return Err(BindingError::PairingRequired);
        }
        if !presence_confirmed {
            return Err(BindingError::PresenceRequired);
        }
        self.wipe(storage);
        Ok(())
    }
}

impl Default for BindingManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Compara 32B em tempo constante (sem `subtle` no firmware; evita oraculo
/// de tempo no match do challenge).
fn ct_eq_32(a: &[u8; BIND_CHALLENGE_LEN], b: &[u8; BIND_CHALLENGE_LEN]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < BIND_CHALLENGE_LEN {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// Decodifica SEC1 65B e valida que e ponto P-256 (mesma tolerancia de
/// assinatura que `curves.rs`: aceita DER ou raw no `verify`).
fn decode_app_pubkey(app_pub: &[u8; BIND_PUB_LEN]) -> Result<(), BindingError> {
    use p256::ecdsa::VerifyingKey;
    use p256::EncodedPoint;
    let pt = EncodedPoint::from_bytes(app_pub.as_slice()).map_err(|_| BindingError::BadPubkey)?;
    VerifyingKey::from_encoded_point(&pt).map_err(|_| BindingError::BadPubkey)?;
    Ok(())
}

/// Verifica assinatura P-256 (DER ou raw) sobre `msg` com pubkey SEC1.
fn verify_p256_sec1(
    app_pub: &[u8; BIND_PUB_LEN],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), BindingError> {
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::EncodedPoint;
    use signature::Verifier;
    let pt = EncodedPoint::from_bytes(app_pub.as_slice()).map_err(|_| BindingError::BadPubkey)?;
    let vk = VerifyingKey::from_encoded_point(&pt).map_err(|_| BindingError::BadPubkey)?;
    let signature = Signature::from_der(sig)
        .or_else(|_| Signature::from_slice(sig))
        .map_err(|_| BindingError::BadSignature)?;
    vk.verify(msg, &signature)
        .map_err(|_| BindingError::BadSignature)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use crate::persistence::MockFlashBackend;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    fn fixed_app_key() -> (p256::ecdsa::SigningKey, [u8; BIND_PUB_LEN]) {
        use p256::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(&[0x11u8; 32]).expect("scalar valido");
        let pt = sk.verifying_key().to_encoded_point(false);
        let mut sec1 = [0u8; BIND_PUB_LEN];
        sec1.copy_from_slice(pt.as_bytes());
        assert_eq!(sec1[0], 0x04);
        (sk, sec1)
    }

    fn other_app_key() -> (p256::ecdsa::SigningKey, [u8; BIND_PUB_LEN]) {
        use p256::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(&[0x22u8; 32]).expect("scalar valido");
        let pt = sk.verifying_key().to_encoded_point(false);
        let mut sec1 = [0u8; BIND_PUB_LEN];
        sec1.copy_from_slice(pt.as_bytes());
        (sk, sec1)
    }

    fn payload_hash(data: &[u8]) -> [u8; BIND_PAYLOAD_HASH_LEN] {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(data);
        let mut out = [0u8; BIND_PAYLOAD_HASH_LEN];
        out.copy_from_slice(&digest);
        out
    }

    fn sign_der(sk: &p256::ecdsa::SigningKey, msg: &[u8]) -> Vec<u8> {
        use signature::Signer;
        let sig: p256::ecdsa::Signature = sk.sign(msg);
        sig.to_der().as_bytes().to_vec()
    }

    fn claimed_manager() -> (BindingManager, p256::ecdsa::SigningKey, [u8; BIND_ID_LEN]) {
        let (_sk_other, _) = other_app_key();
        let (sk, sec1) = fixed_app_key();
        let id = [0xABu8; BIND_ID_LEN];
        let mut m = BindingManager::new();
        m.claim(&sec1, &id, true, true).expect("claim ok");
        (m, sk, id)
    }

    #[test]
    fn claim_requires_unclaimed_pairing_up_and_valid_pubkey() {
        let (_, sec1) = fixed_app_key();
        let id = [0x01u8; BIND_ID_LEN];
        // Sem janela de pareamento: nega sem trocar estado.
        let mut m = BindingManager::new();
        assert_eq!(
            m.claim(&sec1, &id, false, true),
            Err(BindingError::PairingRequired)
        );
        assert!(!m.is_claimed());
        // Sem UP: nega.
        assert_eq!(
            m.claim(&sec1, &id, true, false),
            Err(BindingError::PresenceRequired)
        );
        assert!(!m.is_claimed());
        // Ok: vira Claimed com eco.
        m.claim(&sec1, &id, true, true).expect("claim ok");
        assert!(m.is_claimed());
        assert_eq!(
            m.state(),
            ClaimState::Claimed {
                app_pub: sec1,
                binding_id: id
            }
        );
        // Segundo claim (qualquer chave): nega.
        let (_, sec1_b) = other_app_key();
        assert_eq!(
            m.claim(&sec1_b, &[0x02u8; BIND_ID_LEN], true, true),
            Err(BindingError::AlreadyClaimed)
        );
        // Dono preservado.
        assert_eq!(
            m.state(),
            ClaimState::Claimed {
                app_pub: sec1,
                binding_id: id
            }
        );
    }

    #[test]
    fn claim_rejects_bad_pubkey() {
        let id = [0x01u8; BIND_ID_LEN];
        let mut m = BindingManager::new();
        // Prefixo errado.
        let mut bad = [0u8; BIND_PUB_LEN];
        bad[0] = 0x02;
        assert_eq!(
            m.claim(&bad, &id, true, true),
            Err(BindingError::BadPubkey)
        );
        // 65B mas fora da curva.
        assert_eq!(
            m.claim(&[0x04u8; BIND_PUB_LEN], &id, true, true),
            Err(BindingError::BadPubkey)
        );
        assert!(!m.is_claimed());
    }

    #[test]
    fn persist_load_roundtrip_and_unclaimed_empty() {
        let mut st = test_storage();
        // Vazio: Unclaimed.
        let m0 = BindingManager::load_from_storage(&st).expect("vazio = unclaimed");
        assert!(!m0.is_claimed());
        // Claim + persist + reload preserva dono.
        let (sec1_holder, id_holder);
        {
            let (_, sec1) = fixed_app_key();
            sec1_holder = sec1;
            id_holder = [0x77u8; BIND_ID_LEN];
            let mut m = BindingManager::new();
            m.claim(&sec1_holder, &id_holder, true, true).expect("claim");
            m.persist(&mut st).expect("persist");
        }
        let m1 = BindingManager::load_from_storage(&st).expect("reload");
        assert_eq!(
            m1.state(),
            ClaimState::Claimed {
                app_pub: sec1_holder,
                binding_id: id_holder
            }
        );
    }

    #[test]
    fn load_corrupted_when_partial_or_tampered() {
        let mut st = test_storage();
        let (_, sec1) = fixed_app_key();
        // Parcial (so pub): Corrupted, nao Unclaimed silencioso.
        st.store(BIND_PUB_NVS_KEY, &sec1, &IGNORED_NONCE)
            .expect("raw parcial");
        assert_eq!(
            BindingManager::load_from_storage(&st).unwrap_err(),
            BindingError::Corrupted
        );
        // Tamanho errado: Corrupted (nao truncated-ok).
        st.store(BIND_PUB_NVS_KEY, &[0x04u8; 10], &IGNORED_NONCE)
            .expect("pub curto");
        st.store(BIND_ID_NVS_KEY, &[0x01u8; BIND_ID_LEN], &IGNORED_NONCE)
            .expect("id ok");
        assert_eq!(
            BindingManager::load_from_storage(&st).unwrap_err(),
            BindingError::Corrupted
        );
        // Mapeamento de storage: DecryptionFailed vira Corrupted.
        assert_eq!(
            BindingError::from(crate::persistence::StorageError::DecryptionFailed),
            BindingError::Corrupted
        );
        assert_eq!(
            BindingError::from(crate::persistence::StorageError::KeyNotFound),
            BindingError::NotClaimed
        );
    }
    #[test]
    fn challenge_verify_ok_consumes_and_replay_denied() {
        let (mut m, sk, _id) = claimed_manager();
        // Sem dono nao emite challenge.
        let mut bare = BindingManager::new();
        assert_eq!(
            bare.new_challenge(&mut rand_core::OsRng),
            Err(BindingError::NotClaimed)
        );
        // Emite, verifica, consome.
        let challenge = m.new_challenge(&mut rand_core::OsRng).expect("challenge");
        assert!(m.has_active_challenge());
        let op = crate::ble_gatt::OP_KEY_LIST;
        let ph = payload_hash(b"list-keys");
        let msg = BindingManager::signed_message(&challenge, op, &ph);
        assert_eq!(msg.len(), BIND_SIGNED_MSG_LEN);
        let sig = sign_der(&sk, &msg);
        m.verify(&sig, &challenge, op, &ph).expect("verify ok");
        assert!(!m.has_active_challenge());
        // Replay do sucesso: negado (sem challenge ativo).
        assert_eq!(
            m.verify(&sig, &challenge, op, &ph),
            Err(BindingError::Replay)
        );
        // Challenge antigo apos novo emitido: mismatch.
        let fresh = m.new_challenge(&mut rand_core::OsRng).expect("novo");
        assert_eq!(
            m.verify(&sig, &challenge, op, &ph),
            Err(BindingError::ChallengeMismatch)
        );
        let msg2 = BindingManager::signed_message(&fresh, op, &ph);
        let sig2 = sign_der(&sk, &msg2);
        m.verify(&sig2, &fresh, op, &ph).expect("fresh ok");
    }

    #[test]
    fn wrong_app_key_and_tampered_fields_denied() {
        let (mut m, _sk, _id) = claimed_manager();
        let (sk_evil, _) = other_app_key();
        let challenge = m.new_challenge(&mut rand_core::OsRng).expect("challenge");
        let op = crate::ble_gatt::OP_KEY_DELETE;
        let ph = payload_hash(b"slot-7");
        let msg = BindingManager::signed_message(&challenge, op, &ph);
        // Chave errada: BadSignature, challenge segue ativo p/ retry legitimo.
        let evil_sig = sign_der(&sk_evil, &msg);
        assert_eq!(
            m.verify(&evil_sig, &challenge, op, &ph),
            Err(BindingError::BadSignature)
        );
        assert!(m.has_active_challenge());
        // Op trocado (assinatura nao cobre): nega.
        let (sk, _) = fixed_app_key();
        let good_sig = sign_der(&sk, &msg);
        assert_eq!(
            m.verify(&good_sig, &challenge, op ^ 0x01, &ph),
            Err(BindingError::BadSignature)
        );
        // Payload trocado: nega.
        let ph2 = payload_hash(b"slot-8");
        assert_eq!(
            m.verify(&good_sig, &challenge, op, &ph2),
            Err(BindingError::BadSignature)
        );
        // Lixo como assinatura: nega.
        assert_eq!(
            m.verify(b"lixo", &challenge, op, &ph),
            Err(BindingError::BadSignature)
        );
        // Raw (nao-DER) da chave certa: aceita (tolerancia curves.rs).
        let raw_sig: p256::ecdsa::Signature = signature::Signer::sign(&sk, &msg);
        let raw: Vec<u8> = raw_sig.to_bytes().to_vec();
        m.verify(&raw, &challenge, op, &ph).expect("raw ok");
    }

    #[test]
    fn release_signed_and_factory_reset_wipe_and_reclaim() {
        let (sk, sec1) = fixed_app_key();
        let id = [0x5Au8; BIND_ID_LEN];
        let mut st = test_storage();
        let mut m = BindingManager::new();
        m.claim(&sec1, &id, true, true).expect("claim");
        m.persist(&mut st).expect("persist");
        // Release exige prova assinada: lixo nega e mantem dono.
        let challenge = m.new_challenge(&mut rand_core::OsRng).expect("ch");
        let id_hash = payload_hash(&id);
        assert_eq!(
            m.release_signed(&mut st, b"lixo", &challenge, &id_hash),
            Err(BindingError::BadSignature)
        );
        assert!(m.is_claimed());
        // Release valido: wipe + Unclaimed + NVS limpa.
        let msg = BindingManager::signed_message(&challenge, BIND_OP_RELEASE, &id_hash);
        let sig = sign_der(&sk, &msg);
        m.release_signed(&mut st, &sig, &challenge, &id_hash)
            .expect("release ok");
        assert!(!m.is_claimed());
        assert!(!st.exists(BIND_PUB_NVS_KEY));
        assert!(!st.exists(BIND_ID_NVS_KEY));
        // Reclaim com outro app: liberado.
        let (_, sec1_b) = other_app_key();
        m.claim(&sec1_b, &[0x09u8; BIND_ID_LEN], true, true)
            .expect("reclaim ok");
        assert!(m.is_claimed());
        // Reset fisico exige hold 5s + UP.
        assert_eq!(
            m.factory_reset(&mut st, false, true),
            Err(BindingError::PairingRequired)
        );
        assert_eq!(
            m.factory_reset(&mut st, true, false),
            Err(BindingError::PresenceRequired)
        );
        assert!(m.is_claimed());
        m.persist(&mut st).expect("persist b");
        m.factory_reset(&mut st, true, true).expect("reset ok");
        assert!(!m.is_claimed());
        assert!(!st.exists(BIND_PUB_NVS_KEY));
    }

    #[test]
    fn verify_with_pin_follows_binding_up_pin_order() {
        let (mut m, sk, _id) = claimed_manager();
        let challenge = m.new_challenge(&mut rand_core::OsRng).expect("ch");
        let op = crate::ble_gatt::OP_OATH_PUT;
        let ph = payload_hash(b"oath-put");
        let msg = BindingManager::signed_message(&challenge, op, &ph);
        let sig = sign_der(&sk, &msg);
        // Sem UP: nega (challenge ja consumido pelo verify interno).
        assert_eq!(
            m.verify_with_pin(&sig, &challenge, op, &ph, true, false, true),
            Err(BindingError::PresenceRequired)
        );
        // Novo challenge: sem PIN em op privilegiada nega.
        let ch2 = m.new_challenge(&mut rand_core::OsRng).expect("ch2");
        let msg2 = BindingManager::signed_message(&ch2, op, &ph);
        let sig2 = sign_der(&sk, &msg2);
        assert_eq!(
            m.verify_with_pin(&sig2, &ch2, op, &ph, false, true, true),
            Err(BindingError::PinRequired)
        );
        // Completo: ok. LIST (sem PIN) com UP: ok.
        let ch3 = m.new_challenge(&mut rand_core::OsRng).expect("ch3");
        let msg3 = BindingManager::signed_message(&ch3, op, &ph);
        let sig3 = sign_der(&sk, &msg3);
        m.verify_with_pin(&sig3, &ch3, op, &ph, true, true, true)
            .expect("privilegiada ok");
        let ch4 = m.new_challenge(&mut rand_core::OsRng).expect("ch4");
        let list_op = crate::ble_gatt::OP_OATH_LIST;
        let msg4 = BindingManager::signed_message(&ch4, list_op, &ph);
        let sig4 = sign_der(&sk, &msg4);
        m.verify_with_pin(&sig4, &ch4, list_op, &ph, false, true, false)
            .expect("lista ok sem pin");
        // Sem dono: NEED_BINDING antes de qualquer UP/PIN.
        let mut bare = BindingManager::new();
        let chx = [0xAAu8; BIND_CHALLENGE_LEN];
        let phx = [0xBBu8; BIND_PAYLOAD_HASH_LEN];
        let r = bare.verify_with_pin(b"sig", &chx, op, &phx, false, false, true);
        assert_eq!(r, Err(BindingError::NotClaimed));
        assert_eq!(r.unwrap_err().to_vendor_status(), NEED_BINDING_STATUS);
    }
    #[test]
    fn ble_vendor_gate_matrix_binding_up_pin() {
        use crate::ble_gatt::{
            authorize_vendor_op, is_vendor_keys_oath_op, vendor_op_requires_pin,
            BleGattError, OP_KEY_DELETE, OP_KEY_GEN_ONDEVICE, OP_KEY_IMPORT_ENVELOPE,
            OP_KEY_LIST, OP_MSG, OP_OATH_CODE, OP_OATH_DELETE, OP_OATH_LIST, OP_OATH_PUT,
            OP_PING,
        };
        // So 0x21/0x23/0x24/0x27 exigem PIN; resto vendor: so UP (+binding).
        assert!(vendor_op_requires_pin(OP_KEY_IMPORT_ENVELOPE));
        assert!(vendor_op_requires_pin(OP_KEY_DELETE));
        assert!(vendor_op_requires_pin(OP_OATH_PUT));
        assert!(vendor_op_requires_pin(OP_OATH_DELETE));
        assert!(!vendor_op_requires_pin(OP_KEY_GEN_ONDEVICE));
        assert!(!vendor_op_requires_pin(OP_KEY_LIST));
        assert!(!vendor_op_requires_pin(OP_OATH_LIST));
        assert!(!vendor_op_requires_pin(OP_OATH_CODE));
        // Split uso/config: USO (LIST/CODE) nunca exige vinculo, so UP.
        // CONFIG (GEN/IMPORT/DELETE/PUT) exige vinculo em release;
        // em test-mode faz bypass com ltrace (so UP+PIN).
        use crate::ble_gatt::{is_config_op, is_usage_op};
        for op in [OP_KEY_LIST, OP_OATH_LIST, OP_OATH_CODE] {
            assert!(is_usage_op(op));
            assert!(!is_config_op(op));
            // Sem vinculo + UP: passa (PIN irrelevante em uso).
            authorize_vendor_op(op, false, false, true).expect("uso sem vinculo passa");
            authorize_vendor_op(op, false, true, true).expect("uso sem vinculo passa");
            // Sem UP: NEED_UP mesmo sem vinculo.
            assert_eq!(
                authorize_vendor_op(op, false, true, false),
                Err(BleGattError::PresenceRequired)
            );
        }
        // CONFIG sem binding: release nega, teste faz bypass.
        let bypass = crate::binding::binding_bypass_enabled();
        for op in [
            OP_KEY_GEN_ONDEVICE,
            OP_KEY_IMPORT_ENVELOPE,
            OP_KEY_DELETE,
            OP_OATH_PUT,
            OP_OATH_DELETE,
        ] {
            assert!(is_config_op(op));
            assert!(!is_usage_op(op));
            assert!(is_vendor_keys_oath_op(op));
            if bypass {
                // Teste: sem vinculo + UP(+PIN) passa com ltrace.
                let need_pin = vendor_op_requires_pin(op);
                authorize_vendor_op(op, false, need_pin, true).expect("bypass teste passa");
            } else {
                // Release: sem vinculo nega mesmo com UP+PIN.
                assert_eq!(
                    authorize_vendor_op(op, false, true, true),
                    Err(BleGattError::NeedBinding)
                );
            }
        }
        // Com binding, sem UP: NEED_UP (qualquer op).
        assert_eq!(
            authorize_vendor_op(OP_OATH_CODE, true, true, false),
            Err(BleGattError::PresenceRequired)
        );
        // Com binding+UP, sem PIN: privilegiada nega, lista/codigo passa.
        assert_eq!(
            authorize_vendor_op(OP_KEY_DELETE, true, false, true),
            Err(BleGattError::PinRequired)
        );
        authorize_vendor_op(OP_OATH_CODE, true, false, true).expect("code sem pin");
        authorize_vendor_op(OP_OATH_LIST, true, false, true).expect("list sem pin");
        // Completo passa nas privilegiadas.
        authorize_vendor_op(OP_KEY_IMPORT_ENVELOPE, true, true, true).expect("import ok");
        authorize_vendor_op(OP_OATH_DELETE, true, true, true).expect("oath del ok");
        // Fora da faixa vendor: opcode invalido (GATT 0x81/0x83 intactos fora).
        assert_eq!(
            authorize_vendor_op(OP_PING, true, true, true),
            Err(BleGattError::InvalidOpcode)
        );
        assert_eq!(
            authorize_vendor_op(OP_MSG, true, true, true),
            Err(BleGattError::InvalidOpcode)
        );
        // Status wire golden §9.5 + 0x05.
        assert_eq!(BleGattError::NeedBinding.to_vendor_status(), 0x05);
        assert_eq!(BleGattError::PresenceRequired.to_vendor_status(), 0x01);
        assert_eq!(BleGattError::PinRequired.to_vendor_status(), 0x02);
    }

    #[test]
    fn wifi_and_oath_bound_gates_require_binding_first() {
        use crate::oath_store::{oath_store_delete_bound, oath_store_get_bound, oath_store_put_bound};
        use crate::wifi_ap::{change_ap_password_bound, handle_get_oath_code_bound, WifiApError};
        use crate::wifi_station::{
            clear_station_credentials_bound, save_station_credentials_bound, WifiStationError,
            WIFI_STA_PASS_NVS_KEY, WIFI_STA_SSID_NVS_KEY,
        };
        use aegis_fido_core::oath::OathAlgorithm;
        let mut st = test_storage();
        let bypass = crate::binding::binding_bypass_enabled();
        // WiFi AP (CONFIG): release exige vinculo; teste faz bypass (so UP+PIN).
        if bypass {
            change_ap_password_bound(&mut st, "nova-senha-123", false, true, true)
                .expect("bypass teste passa");
        } else {
            assert_eq!(
                change_ap_password_bound(&mut st, "nova-senha-123", false, true, true),
                Err(WifiApError::NeedBinding)
            );
            assert!(!st.exists(crate::wifi_ap::WIFI_PASS_NVS_KEY));
        }
        // Com binding, sem PIN: Unauthorized (UP+PIN como antes).
        assert_eq!(
            change_ap_password_bound(&mut st, "nova-senha-123", true, false, true),
            Err(WifiApError::Unauthorized)
        );
        change_ap_password_bound(&mut st, "nova-senha-123", true, true, true).expect("ap ok");
        // Station (CONFIG): mesmo split release/teste.
        if bypass {
            save_station_credentials_bound(&mut st, "Casa-5G", "senha-segura-123", false, true, true)
                .expect("bypass station passa");
        } else {
            assert_eq!(
                save_station_credentials_bound(&mut st, "Casa-5G", "senha-segura-123", false, true, true),
                Err(WifiStationError::NeedBinding)
            );
            assert!(!st.exists(WIFI_STA_SSID_NVS_KEY));
            assert!(!st.exists(WIFI_STA_PASS_NVS_KEY));
            save_station_credentials_bound(&mut st, "Casa-5G", "senha-segura-123", true, true, true)
                .expect("station ok");
        }
        if bypass {
            clear_station_credentials_bound(&mut st, false, true, true).expect("bypass clear passa");
        } else {
            assert_eq!(
                clear_station_credentials_bound(&mut st, false, true, true),
                Err(WifiStationError::NeedBinding)
            );
            clear_station_credentials_bound(&mut st, true, true, true).expect("clear ok");
        }
        // OATH store PUT/DELETE (CONFIG): release exige vinculo; teste bypass.
        if bypass {
            oath_store_put_bound(&mut st, "GitHub:alice", b"blob", false).expect("bypass put passa");
        } else {
            assert_eq!(
                oath_store_put_bound(&mut st, "GitHub:alice", b"blob", false),
                Err(crate::oath_store::OathStoreError::NeedBinding)
            );
            oath_store_put_bound(&mut st, "GitHub:alice", b"blob", true).expect("put ok");
        }
        // OATH store GET (USO): nunca exige vinculo, so leitura (UP no transporte).
        assert_eq!(
            oath_store_get_bound(&st, "GitHub:alice", false).expect("uso sem vinculo passa"),
            b"blob"
        );
        assert_eq!(
            oath_store_get_bound(&st, "GitHub:alice", true).expect("get ok"),
            b"blob"
        );
        if bypass {
            oath_store_delete_bound(&mut st, "GitHub:alice", false).expect("bypass del passa");
        } else {
            assert_eq!(
                oath_store_delete_bound(&mut st, "GitHub:alice", false),
                Err(crate::oath_store::OathStoreError::NeedBinding)
            );
            oath_store_delete_bound(&mut st, "GitHub:alice", true).expect("del ok");
            // Recria para o check de CODE abaixo (uso).
            oath_store_put_bound(&mut st, "GitHub:alice", b"blob", true).expect("put recria");
        }
        // OATH code via WiFi (USO): nunca exige vinculo, so UP.
        let secret = b"12345678901234567890";
        let secrets: &[(&str, &[u8], OathAlgorithm, u8)] =
            &[("GitHub:alice", secret, OathAlgorithm::Sha1, 6)];
        let r = handle_get_oath_code_bound("GitHub:alice", secrets, 59, false, true).expect("uso sem vinculo passa");
        assert_eq!(r.code, "287082");
        let r2 = handle_get_oath_code_bound("GitHub:alice", secrets, 59, true, true).expect("code");
        assert_eq!(r2.code, "287082");
    }

    #[cfg(feature = "test-mode")]
    #[test]
    fn config_bypass_in_test_mode() {
        // Teste: CONFIG sem vinculo passa com UP(+PIN) + ltrace (cripto DESABILITADA).
        assert!(binding_bypass_enabled());
        require_bound_config(false).expect("bypass config passa");
        require_bound_usage(false).expect("uso passa");
        use crate::ble_gatt::{authorize_vendor_op, OP_KEY_DELETE, OP_OATH_PUT};
        authorize_vendor_op(OP_KEY_DELETE, false, true, true).expect("bypass delete passa");
        authorize_vendor_op(OP_OATH_PUT, false, true, true).expect("bypass put passa");
    }

    #[cfg(not(feature = "test-mode"))]
    #[test]
    fn release_denies_config_without_binding() {
        // Release: CONFIG sem vinculo nega NEED_BINDING 0x05.
        assert!(!binding_bypass_enabled());
        assert_eq!(require_bound_config(false), Err(BindingError::NotClaimed));
        assert_eq!(require_bound_config(false).unwrap_err().to_vendor_status(), NEED_BINDING_STATUS);
        require_bound_usage(false).expect("uso nunca exige vinculo");
        use crate::ble_gatt::{authorize_vendor_op, BleGattError, OP_KEY_DELETE};
        assert_eq!(
            authorize_vendor_op(OP_KEY_DELETE, false, true, true),
            Err(BleGattError::NeedBinding)
        );
    }

    #[test]
    fn usage_never_requires_binding_in_any_mode() {
        // USO (CODE/LIST) sem vinculo passa em release E teste; so UP.
        use crate::ble_gatt::{authorize_vendor_op, BleGattError, OP_OATH_CODE, OP_OATH_LIST, OP_KEY_LIST};
        for op in [OP_OATH_CODE, OP_OATH_LIST, OP_KEY_LIST] {
            require_bound_usage(false).expect("uso passa");
            authorize_vendor_op(op, false, false, true).expect("uso sem vinculo passa");
            assert_eq!(
                authorize_vendor_op(op, false, false, false),
                Err(BleGattError::PresenceRequired)
            );
        }
        // GetAssertion BLE (0x83 MSG) fora dos vendor ops: transporte so exige UP,
        // nunca vinculo (USB/CTAP intacto e sempre livre; BLE MSG igual).
    }

    #[test]
    fn usb_ctap_bytes_untouched_golden() {
        // USB/CTAP 100% intacto e ABERTO: golden de constantes do transporte
        // USB + GATT + faixa vendor. Binding nunca toca neste caminho.
        use aegis_fido_usb::ctaphid::{
            BROADCAST_CID, CMD_CANCEL, CMD_CBOR, CMD_INIT, CMD_MSG, CMD_PING, PACKET_SIZE,
        };
        assert_eq!(PACKET_SIZE, 64);
        assert_eq!(CMD_PING, 0x81);
        assert_eq!(CMD_MSG, 0x83);
        assert_eq!(CMD_CBOR, 0x90);
        assert_eq!(CMD_INIT, 0x86);
        assert_eq!(CMD_CANCEL, 0x91);
        assert_eq!(BROADCAST_CID, 0xFFFF_FFFF);
        assert_eq!(crate::ble_gatt::GATT_REVISION, 0x01);
        assert_eq!(crate::ble_gatt::BLE_SERVICE_UUID, 0xFFFD);
        assert_eq!(crate::ble_gatt::VENDOR_OP_MIN, 0x20);
        assert_eq!(crate::ble_gatt::VENDOR_OP_MAX, 0x27);
        // §9.5 golden: 0x00-0x04 preservados, 0x05 e a unica adicao (BLE/WiFi).
        assert_eq!(VENDOR_STATUS_OK, 0x00);
        assert_eq!(VENDOR_STATUS_NEED_UP, 0x01);
        assert_eq!(VENDOR_STATUS_NEED_PIN, 0x02);
        assert_eq!(VENDOR_STATUS_NO_SLOT, 0x03);
        assert_eq!(VENDOR_STATUS_BAD_ENVELOPE, 0x04);
        assert_eq!(NEED_BINDING_STATUS, 0x05);
        assert_eq!(BindingError::NotClaimed.to_vendor_status(), 0x05);
        assert_eq!(BindingError::Replay.to_vendor_status(), 0x05);
        assert_eq!(BindingError::ChallengeMismatch.to_vendor_status(), 0x05);
        assert_eq!(BindingError::BadSignature.to_vendor_status(), 0x05);
        assert_eq!(BindingError::PresenceRequired.to_vendor_status(), 0x01);
        assert_eq!(BindingError::PairingRequired.to_vendor_status(), 0x01);
        assert_eq!(BindingError::PinRequired.to_vendor_status(), 0x02);
    }
}
