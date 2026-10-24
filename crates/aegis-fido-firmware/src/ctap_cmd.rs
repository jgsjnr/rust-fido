//! T-FD-04 MakeCredential/GetAssertion sobre cred_store+pin_uv+ctap_state.
//!
//! Purpose: compose the durable vault (T-FD-02), the durable PIN/UV truth
//! (T-FD-03) and the RAM admission gate (T-FD-01) into the two CTAP
//! credential operations plus CTAP Reset. Does NOT edit those modules.
//!
//! Order (fail-closed): wire limits -> UV predicate -> bound UP -> single-use
//! PIN session -> atomic storage. UP grant is bound to one OperationHash and
//! is single-use (confused deputy denied with OperationDenied). The PIN/UV
//! session is single-use as well (replay denied with PinTokenExpired).
//!
//! - Credential bytes are born on-device via HrngSource (R14); the host
//!   simulator in tests only supplies rpId/clientData hashes, never key
//!   material (GEN-DEVICE; export would be GEN-APP-STORE via envelope).
//! - Storage label is hex(credId); quota/rollback semantics are inherited
//!   from cred_store (QuotaExceeded -> KeyStoreFull, replay -> Integrity).
//! - Call contexts (`CtapCall`/`CtapResetCall`) keep signatures small
//!   (SOLID, clippy-clean) and borrow storage/gates/entropy together.
//! - no_std compatible (alloc only). HW via traits (FlashStorageBackend,
//!   HrngSource). Debug impls expose lengths only, never secrets.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::cred_store::{
    cred_bump_counter, cred_delete, cred_get, cred_put, CredRecord, CredStoreError,
    CRED_ID_MAX_BYTES,
};
use crate::crypto_hrng::HrngSource;
use crate::ctap_state::{map_hrng_error, CtapCommand, CtapError, PinUvGate};
use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::pin_uv::{self, PinUvSession};
use crate::up_policy::{OperationHash, UpGrant, UpPolicy};

/// Bytes of credentialId generated on-device per MakeCredential.
pub const CTAP_CRED_ID_BYTES: usize = 16;
/// Bytes of opaque private blob generated on-device (sealed by T-ST-01).
pub const CTAP_PRIV_BYTES: usize = 32;
/// rpIdHash / clientDataHash length (SHA-256).
pub const CTAP_HASH_BYTES: usize = 32;
/// Max user.id length accepted (CTAP user entity id cap).
pub const CTAP_USER_ID_MAX: usize = 64;
/// Flags bitmask: discoverable slot.
pub const CTAP_FLAG_RESIDENT: u8 = 0x01;
/// Flags bitmask: UV was performed for this credential.
pub const CTAP_FLAG_UV: u8 = 0x04;

/// Shared call context for MakeCredential/GetAssertion.
///
/// Bundles durable storage, the RAM gate, the single-use PIN session, the
/// bound UP grant and the entropy source so no operation needs more than
/// three arguments (SOLID, clippy `too_many_arguments` clean).
pub struct CtapCall<'a, B: FlashStorageBackend, R: HrngSource> {
    /// Durable encrypted storage (credential slots + PIN/UV counters).
    pub storage: &'a mut SecureStorage<B>,
    /// RAM admission gate (command table, limits, token flags).
    pub gate: &'a PinUvGate,
    /// Single-use `pinUvAuth` session (consumed when `pin_auth_ok`).
    pub session: &'a mut PinUvSession,
    /// Bound-UP policy (confused deputy denied).
    pub policy: &'a UpPolicy,
    /// Single-use UP grant for `op`.
    pub grant: &'a mut UpGrant,
    /// Operation the UP grant is bound to (challenge hash).
    pub op: OperationHash,
    /// Monotonic clock sample in ms (HW injected).
    pub now_ms: u64,
    /// On-device entropy (HW TRNG on target, fixture only in tests).
    pub rng: &'a mut R,
}

/// Reset context: same admission without entropy (no keygen on Reset).
pub struct CtapResetCall<'a, B: FlashStorageBackend> {
    /// Durable encrypted storage (wiped by Reset).
    pub storage: &'a mut SecureStorage<B>,
    /// RAM gate (cleared by Reset, hence `&mut`).
    pub gate: &'a mut PinUvGate,
    /// PIN session (dropped by Reset).
    pub session: &'a mut PinUvSession,
    /// Bound-UP policy.
    pub policy: &'a UpPolicy,
    /// Single-use UP grant for the Reset operation.
    pub grant: &'a mut UpGrant,
    /// Operation the UP grant is bound to.
    pub op: OperationHash,
    /// Monotonic clock sample in ms.
    pub now_ms: u64,
}

/// MakeCredential input (CBOR already decoded by the dispatcher).
pub struct MakeCredentialRequest {
    /// SHA-256(rp.id).
    pub rp_id_hash: [u8; CTAP_HASH_BYTES],
    /// SHA-256(clientDataJSON).
    pub client_data_hash: [u8; CTAP_HASH_BYTES],
    /// user.id (1..=64 bytes).
    pub user_id: Vec<u8>,
    /// Whether to create a discoverable (resident) slot.
    pub require_resident: bool,
    /// Whether UV is required for this creation.
    pub require_uv: bool,
    /// True when the caller performed native UV out-of-band.
    pub uv_performed: bool,
    /// True when a live pinUvAuth session backs this call.
    pub pin_auth_ok: bool,
}

/// MakeCredential output (lengths only in Debug).
pub struct MakeCredentialResponse {
    /// Generated credentialId (16 bytes).
    pub cred_id: Vec<u8>,
    /// Initial signature counter (always 0).
    pub sign_count: u32,
}

impl core::fmt::Debug for MakeCredentialResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MakeCredentialResponse")
            .field("cred_id_len", &self.cred_id.len())
            .field("sign_count", &self.sign_count)
            .finish()
    }
}

/// GetAssertion input (CBOR already decoded by the dispatcher).
pub struct GetAssertionRequest {
    /// SHA-256(rp.id) the assertion is bound to.
    pub rp_id_hash: [u8; CTAP_HASH_BYTES],
    /// SHA-256(clientDataJSON) the assertion is bound to.
    pub client_data_hash: [u8; CTAP_HASH_BYTES],
    /// credentialId allow-listed by the host (1..=128 bytes).
    pub cred_id: Vec<u8>,
    /// Whether UV is required for this assertion.
    pub require_uv: bool,
    /// True when the caller performed native UV out-of-band.
    pub uv_performed: bool,
    /// True when a live pinUvAuth session backs this call.
    pub pin_auth_ok: bool,
}

/// GetAssertion output (no private bytes cross this boundary).
pub struct GetAssertionResponse {
    /// Asserted credentialId (echoed).
    pub cred_id: Vec<u8>,
    /// Counter after the atomic +1 (rollback-safe).
    pub sign_count: u32,
    /// Stored credential flags (opaque bitmask).
    pub flags: u8,
}

impl core::fmt::Debug for GetAssertionResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GetAssertionResponse")
            .field("cred_id_len", &self.cred_id.len())
            .field("sign_count", &self.sign_count)
            .field("flags", &self.flags)
            .finish()
    }
}

fn map_cred_err(e: CredStoreError) -> CtapError {
    match e {
        CredStoreError::BadLabel => CtapError::InvalidParameter,
        CredStoreError::TooLarge => CtapError::RequestTooLarge,
        CredStoreError::QuotaExceeded => CtapError::KeyStoreFull,
        CredStoreError::NotFound => CtapError::NoCredentials,
        CredStoreError::Storage => CtapError::IntegrityFailure,
        CredStoreError::InvalidRecord => CtapError::InvalidCredential,
        CredStoreError::CounterRegression => CtapError::IntegrityFailure,
    }
}

fn map_pin_err(e: pin_uv::PinUvError) -> CtapError {
    match e {
        pin_uv::PinUvError::PinNotSet => CtapError::PinNotSet,
        pin_uv::PinUvError::PinBlocked => CtapError::PinBlocked,
        pin_uv::PinUvError::UvBlocked => CtapError::UvBlocked,
        pin_uv::PinUvError::PinInvalid => CtapError::PinInvalid,
        pin_uv::PinUvError::PinPolicyViolation => CtapError::PinPolicyViolation,
        pin_uv::PinUvError::TokenExpired => CtapError::PinTokenExpired,
        pin_uv::PinUvError::Storage => CtapError::IntegrityFailure,
    }
}

/// Deterministic label for a credentialId (lowercase hex, fits 1..=64).
fn label_for_cred_id(cred_id: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(cred_id.len() * 2);
    for b in cred_id {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

/// Shared admission: wire limits -> durable UV truth -> UV predicate ->
/// bound UP -> single-use PIN session. Returns Ok(()) when the caller may
/// touch storage; consumes the PIN session only when `pin_auth_ok` is set.
fn admit<B: FlashStorageBackend, R: HrngSource>(
    ctx: &mut CtapCall<'_, B, R>,
    cmd: CtapCommand,
    encoded_len: usize,
    require_uv: bool,
    uv_performed: bool,
    pin_auth_ok: bool,
) -> Result<(), CtapError> {
    ctx.gate.check_request(cmd.code(), encoded_len)?;
    let uv_blocked = match pin_uv::uv_retries_left(ctx.storage) {
        Ok(0) => true,
        Ok(_) => false,
        Err(_) => return Err(CtapError::IntegrityFailure),
    };
    if uv_blocked {
        return Err(CtapError::UvBlocked);
    }
    ctx.gate
        .check_uv_policy(require_uv, uv_performed, pin_auth_ok)?;
    ctx.gate
        .check_up(ctx.policy, ctx.grant, ctx.op, ctx.now_ms)?;
    if pin_auth_ok {
        ctx.session
            .consume_uv_auth()
            .map_err(|_| CtapError::PinTokenExpired)?;
    }
    Ok(())
}
/// Create a resident credential bound to (rpIdHash, clientDataHash).
///
/// Generates credId (16 B) + opaque private blob (32 B) via the context RNG,
/// stores the record with sign_count 0 and consumes the UP grant + PIN
/// session held by the context.
pub fn make_credential<B: FlashStorageBackend, R: HrngSource>(
    ctx: &mut CtapCall<'_, B, R>,
    req: &MakeCredentialRequest,
    encoded_len: usize,
) -> Result<MakeCredentialResponse, CtapError> {
    if req.user_id.is_empty() {
        return Err(CtapError::MissingParameter);
    }
    if req.user_id.len() > CTAP_USER_ID_MAX {
        return Err(CtapError::InvalidParameter);
    }
    admit(
        ctx,
        CtapCommand::MakeCredential,
        encoded_len,
        req.require_uv,
        req.uv_performed,
        req.pin_auth_ok,
    )?;
    let mut cred_id = [0u8; CTAP_CRED_ID_BYTES];
    ctx.rng.fill(&mut cred_id).map_err(map_hrng_error)?;
    let mut priv_blob = [0u8; CTAP_PRIV_BYTES];
    if let Err(e) = ctx.rng.fill(&mut priv_blob) {
        cred_id.zeroize();
        return Err(map_hrng_error(e));
    }
    let mut flags = 0u8;
    if req.require_resident {
        flags |= CTAP_FLAG_RESIDENT;
    }
    if req.uv_performed || req.pin_auth_ok {
        flags |= CTAP_FLAG_UV;
    }
    let rec = CredRecord {
        flags,
        sign_count: 0,
        rp_id_hash: req.rp_id_hash,
        cred_id: cred_id.to_vec(),
        priv_blob: priv_blob.to_vec(),
    };
    cred_id.zeroize();
    priv_blob.zeroize();
    if rec.cred_id.len() > CRED_ID_MAX_BYTES {
        return Err(CtapError::InvalidParameter);
    }
    let label = label_for_cred_id(&rec.cred_id);
    let out_id = rec.cred_id.clone();
    cred_put(ctx.storage, &label, &rec).map_err(map_cred_err)?;
    Ok(MakeCredentialResponse {
        cred_id: out_id,
        sign_count: 0,
    })
}

/// Assert ownership of `req.cred_id` for the bound rp, bumping signCount.
///
/// Denies cross-RP use (InvalidCredential), missing slots (NoCredentials)
/// and replays the UP/PIN gates (OperationDenied / PinTokenExpired).
pub fn get_assertion<B: FlashStorageBackend, R: HrngSource>(
    ctx: &mut CtapCall<'_, B, R>,
    req: &GetAssertionRequest,
    encoded_len: usize,
) -> Result<GetAssertionResponse, CtapError> {
    if req.cred_id.is_empty() {
        return Err(CtapError::MissingParameter);
    }
    if req.cred_id.len() > CRED_ID_MAX_BYTES {
        return Err(CtapError::InvalidParameter);
    }
    admit(
        ctx,
        CtapCommand::GetAssertion,
        encoded_len,
        req.require_uv,
        req.uv_performed,
        req.pin_auth_ok,
    )?;
    let label = label_for_cred_id(&req.cred_id);
    let rec = cred_get(ctx.storage, &label).map_err(map_cred_err)?;
    if rec.rp_id_hash != req.rp_id_hash {
        return Err(CtapError::InvalidCredential);
    }
    if rec.cred_id.as_slice() != req.cred_id.as_slice() {
        return Err(CtapError::InvalidCredential);
    }
    let flags = rec.flags;
    let next = cred_bump_counter(ctx.storage, &label).map_err(map_cred_err)?;
    Ok(GetAssertionResponse {
        cred_id: req.cred_id.clone(),
        sign_count: next,
        flags,
    })
}

/// CTAP Reset composed here (owner T-FD-04): requires bound UP, then wipes
/// the durable PIN/UV truth, the RAM gate and every listed credential slot.
/// Absent slots are idempotent (no error); corrupt slots fail closed.
pub fn ctap_reset<B: FlashStorageBackend>(
    ctx: &mut CtapResetCall<'_, B>,
    labels: &[String],
) -> Result<(), CtapError> {
    ctx.gate.check_request(CtapCommand::Reset.code(), 1)?;
    ctx.gate
        .check_up(ctx.policy, ctx.grant, ctx.op, ctx.now_ms)?;
    pin_uv::factory_reset(ctx.storage, ctx.session).map_err(map_pin_err)?;
    ctx.gate.factory_reset();
    for label in labels {
        match cred_delete(ctx.storage, label) {
            Ok(()) => {}
            Err(CredStoreError::NotFound) => {}
            Err(e) => return Err(map_cred_err(e)),
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_hrng::{HrngError, HRNG_MAX_FILL};
    use crate::ctap_state::CTAP_MAX_MSG_LEN;
    use crate::persistence::MockFlashBackend;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    /// Deterministic xorshift, SOMENTE fixture; HW real e o TRNG.
    struct TestRng(u64);
    impl HrngSource for TestRng {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), HrngError> {
            if dest.is_empty() {
                return Err(HrngError::TooShort);
            }
            if dest.len() > HRNG_MAX_FILL {
                return Err(HrngError::TooLarge);
            }
            for chunk in dest.chunks_mut(8) {
                let mut x = self.0;
                if x == 0 {
                    x = 0x9E3779B97F4A7C15;
                }
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                let v = x.to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            Ok(())
        }
    }

    fn op(byte: u8) -> OperationHash {
        OperationHash([byte; 32])
    }

    fn live_session(
        storage: &mut SecureStorage<MockFlashBackend>,
        rng: &mut TestRng,
    ) -> PinUvSession {
        let mut ses = PinUvSession::new();
        pin_uv::pin_set(storage, rng, &mut ses, b"1234").unwrap();
        pin_uv::pin_verify(storage, &mut ses, b"1234").unwrap();
        assert!(ses.is_live());
        ses
    }

    fn gate_ready() -> PinUvGate {
        let mut gate = PinUvGate::new(true);
        gate.set_key_agreement(true);
        gate
    }

    fn mc_req(pin_auth_ok: bool) -> MakeCredentialRequest {
        MakeCredentialRequest {
            rp_id_hash: [0x11u8; 32],
            client_data_hash: [0x22u8; 32],
            user_id: alloc::vec![0x75u8; 8],
            require_resident: true,
            require_uv: true,
            uv_performed: false,
            pin_auth_ok,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn call<'a>(
        storage: &'a mut SecureStorage<MockFlashBackend>,
        gate: &'a PinUvGate,
        session: &'a mut PinUvSession,
        policy: &'a UpPolicy,
        grant: &'a mut UpGrant,
        op: OperationHash,
        now_ms: u64,
        rng: &'a mut TestRng,
    ) -> CtapCall<'a, MockFlashBackend, TestRng> {
        CtapCall {
            storage,
            gate,
            session,
            policy,
            grant,
            op,
            now_ms,
            rng,
        }
    }

    fn reset_call<'a>(
        storage: &'a mut SecureStorage<MockFlashBackend>,
        gate: &'a mut PinUvGate,
        session: &'a mut PinUvSession,
        policy: &'a UpPolicy,
        grant: &'a mut UpGrant,
        op: OperationHash,
        now_ms: u64,
    ) -> CtapResetCall<'a, MockFlashBackend> {
        CtapResetCall {
            storage,
            gate,
            session,
            policy,
            grant,
            op,
            now_ms,
        }
    }

    #[test]
    fn interop_make_then_two_assertions_bump_counter() {
        let mut st = test_storage();
        let mut rng = TestRng(0xC04D);
        let mut ses = live_session(&mut st, &mut rng);
        let gate = gate_ready();
        let policy = UpPolicy::with_default_window();
        // Host simulado: grant vinculado ao desafio da criacao.
        let mut g = policy.issue(op(9), 1_000);
        let mut ctx = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g,
            op(9),
            1_100,
            &mut rng,
        );
        let mc = make_credential(&mut ctx, &mc_req(true), 128).unwrap();
        assert_eq!(mc.cred_id.len(), CTAP_CRED_ID_BYTES);
        assert_eq!(mc.sign_count, 0);
        assert!(!ses.is_live(), "sessao PIN de uso unico foi consumida");
        // PIN de uso unico: segunda operacao exige novo verify.
        pin_uv::pin_verify(&mut st, &mut ses, b"1234").unwrap();
        let mut g2 = policy.issue(op(10), 2_000);
        let ga_req = GetAssertionRequest {
            rp_id_hash: [0x11u8; 32],
            client_data_hash: [0x22u8; 32],
            cred_id: mc.cred_id.clone(),
            require_uv: true,
            uv_performed: false,
            pin_auth_ok: true,
        };
        let mut ctx2 = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g2,
            op(10),
            2_100,
            &mut rng,
        );
        let a1 = get_assertion(&mut ctx2, &ga_req, 96).unwrap();
        assert_eq!(a1.sign_count, 1);
        pin_uv::pin_verify(&mut st, &mut ses, b"1234").unwrap();
        let mut g3 = policy.issue(op(10), 3_000);
        let mut ctx3 = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g3,
            op(10),
            3_100,
            &mut rng,
        );
        let a2 = get_assertion(&mut ctx3, &ga_req, 96).unwrap();
        assert_eq!(a2.sign_count, 2, "contador monotonico sobrevive");
    }

    #[test]
    fn up_binding_replay_and_wrong_op_denied() {
        let mut st = test_storage();
        let mut rng = TestRng(77);
        let mut ses = live_session(&mut st, &mut rng);
        let gate = gate_ready();
        let policy = UpPolicy::with_default_window();
        let mut g = policy.issue(op(1), 1_000);
        let mut ctx = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g,
            op(1),
            1_100,
            &mut rng,
        );
        make_credential(&mut ctx, &mc_req(true), 64).unwrap();
        // Replay do mesmo grant nega mesmo dentro da janela.
        let mut ses2 = live_session(&mut st, &mut rng);
        // grant g ja consumido: reutilizar nega OperationDenied.
        let mut ctx_replay = call(
            &mut st,
            &gate,
            &mut ses2,
            &policy,
            &mut g,
            op(1),
            1_150,
            &mut rng,
        );
        assert_eq!(
            make_credential(&mut ctx_replay, &mc_req(true), 64).unwrap_err(),
            CtapError::OperationDenied
        );
        // Grant para outra operacao tambem nega (confused deputy).
        let mut ses3 = PinUvSession::new();
        pin_uv::pin_verify(&mut st, &mut ses3, b"1234").unwrap();
        let mut g_other = policy.issue(op(2), 2_000);
        let mut ctx_other = call(
            &mut st,
            &gate,
            &mut ses3,
            &policy,
            &mut g_other,
            op(3),
            2_050,
            &mut rng,
        );
        assert_eq!(
            get_assertion(
                &mut ctx_other,
                &GetAssertionRequest {
                    rp_id_hash: [0x11u8; 32],
                    client_data_hash: [0x22u8; 32],
                    cred_id: alloc::vec![0xAAu8; 16],
                    require_uv: false,
                    uv_performed: false,
                    pin_auth_ok: false,
                },
                64
            )
            .unwrap_err(),
            CtapError::OperationDenied
        );
    }
    #[test]
    fn uv_limits_and_cross_rp_denied() {
        let mut st = test_storage();
        let mut rng = TestRng(0xBEEF);
        let mut ses = live_session(&mut st, &mut rng);
        let gate = gate_ready();
        let policy = UpPolicy::with_default_window();
        // UV exigida sem PIN nem UV nega PinRequired (sem consumir grant).
        let mut g = policy.issue(op(5), 1_000);
        let mut no_auth = mc_req(false);
        no_auth.require_uv = true;
        let mut ctx = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g,
            op(5),
            1_100,
            &mut rng,
        );
        assert_eq!(
            make_credential(&mut ctx, &no_auth, 64).unwrap_err(),
            CtapError::PinRequired
        );
        assert!(ses.is_live(), "negativa nao consome a sessao");
        // UV bloqueada nega tudo (duravel T-FD-03).
        pin_uv::uv_record_failure(&mut st).unwrap();
        pin_uv::uv_record_failure(&mut st).unwrap();
        assert_eq!(
            pin_uv::uv_record_failure(&mut st),
            Err(pin_uv::PinUvError::UvBlocked)
        );
        let mut g2 = policy.issue(op(6), 2_000);
        let mut ctx2 = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g2,
            op(6),
            2_100,
            &mut rng,
        );
        assert_eq!(
            make_credential(&mut ctx2, &mc_req(true), 64).unwrap_err(),
            CtapError::UvBlocked
        );
        // Destrava para seguir: factory_reset + recadastro.
        let mut ses_f = PinUvSession::new();
        pin_uv::factory_reset(&mut st, &mut ses_f).unwrap();
        let mut ses = live_session(&mut st, &mut rng);
        let mut g3 = policy.issue(op(7), 3_000);
        let mut ctx3 = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g3,
            op(7),
            3_100,
            &mut rng,
        );
        let mc = make_credential(&mut ctx3, &mc_req(true), 64).unwrap();
        // RP trocado nega InvalidCredential (vinculo rpIdHash).
        pin_uv::pin_verify(&mut st, &mut ses, b"1234").unwrap();
        let mut g4 = policy.issue(op(8), 4_000);
        let mut ctx4 = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g4,
            op(8),
            4_100,
            &mut rng,
        );
        assert_eq!(
            get_assertion(
                &mut ctx4,
                &GetAssertionRequest {
                    rp_id_hash: [0x99u8; 32],
                    client_data_hash: [0x22u8; 32],
                    cred_id: mc.cred_id.clone(),
                    require_uv: false,
                    uv_performed: false,
                    pin_auth_ok: true,
                },
                64
            )
            .unwrap_err(),
            CtapError::InvalidCredential
        );
        // Credencial ausente nega NoCredentials.
        pin_uv::pin_verify(&mut st, &mut ses, b"1234").unwrap();
        let mut g5 = policy.issue(op(8), 5_000);
        let mut ctx5 = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g5,
            op(8),
            5_100,
            &mut rng,
        );
        assert_eq!(
            get_assertion(
                &mut ctx5,
                &GetAssertionRequest {
                    rp_id_hash: [0x11u8; 32],
                    client_data_hash: [0x22u8; 32],
                    cred_id: alloc::vec![0xDEu8; 16],
                    require_uv: false,
                    uv_performed: false,
                    pin_auth_ok: true,
                },
                64
            )
            .unwrap_err(),
            CtapError::NoCredentials
        );
    }

    #[test]
    fn rejects_invalid_truncated_and_limits() {
        let mut st = test_storage();
        let mut rng = TestRng(9);
        let mut ses = live_session(&mut st, &mut rng);
        let gate = gate_ready();
        let policy = UpPolicy::with_default_window();
        // Quadro acima do teto nega LimitExceeded.
        let mut g = policy.issue(op(1), 1_000);
        let mut ctx = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g,
            op(1),
            1_100,
            &mut rng,
        );
        assert_eq!(
            make_credential(&mut ctx, &mc_req(true), CTAP_MAX_MSG_LEN + 1).unwrap_err(),
            CtapError::LimitExceeded
        );
        // user.id vazio nega MissingParameter; gigante nega InvalidParameter.
        let mut g2 = policy.issue(op(1), 2_000);
        let mut bad = mc_req(true);
        bad.user_id.clear();
        let mut ctx2 = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g2,
            op(1),
            2_100,
            &mut rng,
        );
        assert_eq!(
            make_credential(&mut ctx2, &bad, 64).unwrap_err(),
            CtapError::MissingParameter
        );
        let mut g3 = policy.issue(op(1), 3_000);
        let mut big = mc_req(true);
        big.user_id = alloc::vec![0x41u8; CTAP_USER_ID_MAX + 1];
        let mut ctx3 = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g3,
            op(1),
            3_100,
            &mut rng,
        );
        assert_eq!(
            make_credential(&mut ctx3, &big, 64).unwrap_err(),
            CtapError::InvalidParameter
        );
        // allow-list vazia nega MissingParameter.
        let mut g4 = policy.issue(op(2), 4_000);
        let mut ctx4 = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g4,
            op(2),
            4_100,
            &mut rng,
        );
        assert_eq!(
            get_assertion(
                &mut ctx4,
                &GetAssertionRequest {
                    rp_id_hash: [0x11u8; 32],
                    client_data_hash: [0x22u8; 32],
                    cred_id: Vec::new(),
                    require_uv: false,
                    uv_performed: false,
                    pin_auth_ok: false,
                },
                64
            )
            .unwrap_err(),
            CtapError::MissingParameter
        );
        // Comando desconhecido no gate nega InvalidCommand (tabela T-FD-01).
        assert_eq!(
            gate.check_request(0xFF, 16).unwrap_err(),
            CtapError::InvalidCommand
        );
    }

    #[test]
    fn quota_full_maps_to_key_store_full() {
        let mut st = test_storage();
        let mut rng = TestRng(0x1234);
        let mut ses = live_session(&mut st, &mut rng);
        let gate = gate_ready();
        let policy = UpPolicy::with_default_window();
        let mut now = 1_000u64;
        for _ in 0..32 {
            pin_uv::pin_verify(&mut st, &mut ses, b"1234").unwrap();
            let mut g = policy.issue(op(0x0A), now);
            now += 100;
            let mut ctx = call(
                &mut st,
                &gate,
                &mut ses,
                &policy,
                &mut g,
                op(0x0A),
                now,
                &mut rng,
            );
            make_credential(&mut ctx, &mc_req(true), 64).unwrap();
        }
        pin_uv::pin_verify(&mut st, &mut ses, b"1234").unwrap();
        let mut g = policy.issue(op(0x0A), now + 50);
        let mut ctx = call(
            &mut st,
            &gate,
            &mut ses,
            &policy,
            &mut g,
            op(0x0A),
            now + 60,
            &mut rng,
        );
        assert_eq!(
            make_credential(&mut ctx, &mc_req(true), 64).unwrap_err(),
            CtapError::KeyStoreFull
        );
    }

    #[test]
    fn reset_requires_up_and_wipes_slots_and_pin() {
        let mut st = test_storage();
        let mut rng = TestRng(0x5EED);
        let mut ses = live_session(&mut st, &mut rng);
        let policy = UpPolicy::with_default_window();
        // Gate com acordo (RAM) para compor o Reset.
        let mut gate = gate_ready();
        let mut g = policy.issue(op(0x52), 1_000);
        let mc = {
            let mut ctx = call(
                &mut st,
                &gate,
                &mut ses,
                &policy,
                &mut g,
                op(0x52),
                1_100,
                &mut rng,
            );
            make_credential(&mut ctx, &mc_req(true), 64).unwrap()
        };
        let label = label_for_cred_id(&mc.cred_id);
        // Reset com operacao errada nega sem apagar.
        let mut g_bad = policy.issue(op(0x52), 2_000);
        let mut rbad = reset_call(
            &mut st,
            &mut gate,
            &mut ses,
            &policy,
            &mut g_bad,
            op(0x99),
            2_100,
        );
        assert_eq!(
            ctap_reset(&mut rbad, core::slice::from_ref(&label)).unwrap_err(),
            CtapError::OperationDenied
        );
        assert!(cred_get(&st, &label).is_ok());
        // Reset correto limpa PIN (PinNotSet) e o slot some (NoCredentials).
        let mut g_ok = policy.issue(op(0x52), 3_000);
        let mut rok = reset_call(
            &mut st,
            &mut gate,
            &mut ses,
            &policy,
            &mut g_ok,
            op(0x52),
            3_100,
        );
        ctap_reset(&mut rok, core::slice::from_ref(&label)).unwrap();
        let mut ses2 = PinUvSession::new();
        assert_eq!(
            pin_uv::pin_verify(&mut st, &mut ses2, b"1234"),
            Err(pin_uv::PinUvError::PinNotSet)
        );
        let gate2 = gate_ready();
        let mut ses3 = PinUvSession::new();
        let mut g3 = policy.issue(op(0x52), 4_000);
        let mut ctx3 = call(
            &mut st,
            &gate2,
            &mut ses3,
            &policy,
            &mut g3,
            op(0x52),
            4_100,
            &mut rng,
        );
        assert_eq!(
            get_assertion(
                &mut ctx3,
                &GetAssertionRequest {
                    rp_id_hash: [0x11u8; 32],
                    client_data_hash: [0x22u8; 32],
                    cred_id: mc.cred_id.clone(),
                    require_uv: false,
                    uv_performed: false,
                    pin_auth_ok: false,
                },
                64
            )
            .unwrap_err(),
            CtapError::NoCredentials
        );
    }

    #[test]
    fn debug_never_leaks_secret() {
        let mc = MakeCredentialResponse {
            cred_id: alloc::vec![0xCDu8; 16],
            sign_count: 0,
        };
        let ga = GetAssertionResponse {
            cred_id: alloc::vec![0xCDu8; 16],
            sign_count: 1,
            flags: 0x05,
        };
        let a = format!("{:?}", mc);
        let b = format!("{:?}", ga);
        assert!(a.contains("MakeCredentialResponse"));
        assert!(b.contains("GetAssertionResponse"));
        assert!(a.contains("cred_id_len"));
        assert!(!a.contains("cdcd"));
        assert!(!a.contains("CDCD"));
        assert!(!b.contains("cdcd"));
        let e = format!("{:?}", CtapError::PinAuthInvalid);
        assert!(e.contains("0x33"));
        assert!(!e.contains("cd"));
    }
}
