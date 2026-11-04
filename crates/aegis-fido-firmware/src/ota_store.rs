//! OTA staging + dispatch (casca fina de compat; ver `stores::ota_store`).
//! Conteudo movido para `stores::ota_store` sem mudanca de comportamento.
//! Testes `mod ota_wiring_tests` ficam aqui (via `super::*` sobre o re-export).
pub use crate::stores::ota_store::*;
#[cfg(test)]
extern crate alloc;
#[cfg(test)]
use crate::ota::{OtaError, OtaKeyProvider, OtaSink, MAX_OTA_IMAGE_BYTES};
#[cfg(test)]
use crate::persistence::FlashStorageBackend;
#[cfg(test)]
use alloc::{vec, vec::Vec};

/// Wave OTA wiring tests (Step 4, traces R-04/R-06).
///
/// BEHAVIOR: USB CTAPHID vendor dispatch for `0x30-0x34`
/// (begin/chunk/verify/commit/abort) with session state, UP gate on commit,
/// NVS preserved, rollback semantics. RED-first: these tests fail until
/// `FlashOtaSink` + `dispatch_ota_request` + real `verify_ota_signature`
/// land below.
#[cfg(test)]
mod ota_wiring_tests {
    use super::*;
    use crate::ota::{
        OtaManifest, OtaPhase, OtaState, OP_OTA_ABORT, OP_OTA_BEGIN, OP_OTA_CHUNK, OP_OTA_COMMIT,
        OP_OTA_FINISH, OTA_MANIFEST_LEN,
    };
    use crate::persistence::{MockFlashBackend, SecureStorage};
    use ed25519_dalek::SigningKey;
    use sha2::Digest as _;
    use sha2::Sha256;
    use signature::Signer as _;

    const OTA_CURRENT: u32 = 7;
    const OTA_NEXT: u32 = 8;
    const CRED_KEYS: &[&str] = &["credential_01", "oath_secret_02", "pin_hash"];

    fn ota_image() -> Vec<u8> {
        vec![0xA5u8; 1024]
    }

    fn manifest_raw(version: u32, image: &[u8], sig: &[u8; 64]) -> Vec<u8> {
        let digest = Sha256::digest(image);
        let mut raw = Vec::with_capacity(OTA_MANIFEST_LEN);
        raw.extend_from_slice(&version.to_be_bytes());
        raw.extend_from_slice(&(image.len() as u32).to_be_bytes());
        raw.extend_from_slice(&digest);
        raw.extend_from_slice(sig);
        raw
    }

    fn signed_manifest(version: u32, image: &[u8], sk: &SigningKey) -> Vec<u8> {
        let unsigned = manifest_raw(version, image, &[0x5Eu8; 64]);
        let m = OtaManifest::parse(&unsigned).expect("parse unsigned");
        let sig = sk.sign(&m.signed_bytes());
        manifest_raw(version, image, &sig.to_bytes())
    }

    fn chunk_payload(offset: u32, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + data.len());
        v.extend_from_slice(&offset.to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    fn req_ctx(provisioned: bool, up: bool, pubkey: [u8; 32]) -> OtaRequestCtx {
        req_ctx_hook(provisioned, up, false, pubkey)
    }

    fn req_ctx_hook(provisioned: bool, up: bool, up_hook: bool, pubkey: [u8; 32]) -> OtaRequestCtx {
        OtaRequestCtx {
            provisioned,
            up,
            up_hook,
            ota_pubkey: pubkey,
            current_version: OTA_CURRENT,
        }
    }

    fn credentialed_storage() -> SecureStorage<MockFlashBackend> {
        let mut storage = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        let nonce = [0x00u8; 12];
        storage
            .store("credential_01", b"passkey-bytes", &nonce)
            .unwrap();
        storage
            .store("oath_secret_02", b"oath-seed", &nonce)
            .unwrap();
        storage.store("pin_hash", b"pin-salt-hash", &nonce).unwrap();
        storage
    }

    /// Stages a fully verified session; leaves `sink` scope open for the caller.
    fn stage_to_verified(
        ota: &mut OtaState,
        sink: &mut FlashOtaSink<MockFlashBackend>,
        manifest: &[u8],
        image: &[u8],
        ctx: &OtaRequestCtx,
    ) {
        assert_eq!(
            dispatch_ota_request(ota, sink, OP_OTA_BEGIN, manifest, ctx),
            Some((OTA_STATUS_OK, Vec::new()))
        );
        let mut off = 0u32;
        for chunk in image.chunks(256) {
            let p = chunk_payload(off, chunk);
            let (st, body) =
                dispatch_ota_request(ota, sink, OP_OTA_CHUNK, &p, ctx).expect("chunk dispatch");
            assert_eq!(st, OTA_STATUS_OK);
            off += chunk.len() as u32;
            assert_eq!(body, off.to_be_bytes().to_vec());
        }
        assert_eq!(
            dispatch_ota_request(ota, sink, OP_OTA_FINISH, &[], ctx),
            Some((OTA_STATUS_OK, Vec::new()))
        );
        assert_eq!(ota.phase(), OtaPhase::Verified);
    }

    #[test]
    fn ota_unknown_opcode_ignored() {
        let mut storage = credentialed_storage();
        let mut ota = OtaState::new(OTA_CURRENT);
        let sk = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        let mut sink = FlashOtaSink::new(storage.backend_mut());
        for op in [0x20u8, 0x2D, 0x2F, 0x35, 0xFF] {
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, op, &[], &ctx),
                None
            );
        }
        assert_eq!(ota.phase(), OtaPhase::Idle);
    }

    #[test]
    fn ota_chunk_before_begin_rejected() {
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, [0x11u8; 32]);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            let p = chunk_payload(0, b"orphan-bytes");
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_multichunk_staging_acima_de_8k() {
        // F5: imagem de 20 KiB atravessa 3 chunks NVS e verifica ponta a ponta.
        let mut storage = credentialed_storage();
        let image: Vec<u8> = (0..20 * 1024).map(|i| (i % 251) as u8).collect();
        let sk = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        let staged_len = {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            stage_to_verified(&mut ota, &mut sink, &manifest, &image, &ctx);
            assert_eq!(ota.received(), image.len());
            sink.len
        };
        // Chunks reais no backend (nenhum blob único gigante).
        assert!(storage.backend().exists("ota_c000000"));
        assert!(storage.backend().exists("ota_c000001"));
        assert!(storage.backend().exists("ota_c000002"));
        assert!(!storage.backend().exists("ota_staging"));
        // Reabre o sink (resume pelo len) e confirma NVS intacto.
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let staged_len2 = {
            let sink2 = FlashOtaSink::new(storage.backend_mut());
            sink2.len
        };
        assert_eq!(staged_len2, staged_len);
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_begin_rejects_unprovisioned() {
        let mut storage = credentialed_storage();
        let image = ota_image();
        let raw = manifest_raw(OTA_NEXT, &image, &[0x5Eu8; 64]);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(false, true, [0x11u8; 32]);
        let mut sink = FlashOtaSink::new(storage.backend_mut());
        assert_eq!(
            dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &raw, &ctx),
            Some((OTA_STATUS_FAIL, Vec::new()))
        );
        assert_eq!(ota.phase(), OtaPhase::Idle);
    }

    #[test]
    fn ota_commit_without_up_rejected_session_preserved() {
        let mut storage = credentialed_storage();
        let image = ota_image();
        let sk = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        let mut sink = FlashOtaSink::new(storage.backend_mut());
        stage_to_verified(&mut ota, &mut sink, &manifest, &image, &ctx);
        // COMMIT without the physical UP latch: NEED_UP, session intact.
        let no_up = req_ctx(true, false, sk.verifying_key().to_bytes());
        assert_eq!(
            dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &no_up),
            Some((OTA_STATUS_NEED_UP, Vec::new()))
        );
        assert_eq!(ota.phase(), OtaPhase::Verified);
        assert_eq!(ota.received(), image.len());
        // Same COMMIT with UP now succeeds.
        assert_eq!(
            dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &ctx),
            Some((OTA_STATUS_OK, OTA_NEXT.to_be_bytes().to_vec()))
        );
        assert_eq!(ota.committed_version(), OTA_NEXT);
    }

    #[test]
    fn ota_happy_path_commit_then_rollback_preserves_nvs() {
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let sk = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            stage_to_verified(&mut ota, &mut sink, &manifest, &image, &ctx);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &ctx),
                Some((OTA_STATUS_OK, OTA_NEXT.to_be_bytes().to_vec()))
            );
            assert_eq!(ota.phase(), OtaPhase::Committed);
            assert_eq!(sink.committed_marker(), Some(OTA_NEXT));
            // Post-commit rollback (pre-reboot): back to Idle, version kept.
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_ABORT, &[], &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert_eq!(ota.committed_version(), OTA_NEXT);
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_bad_chunk_offset_rolls_back_and_preserves_nvs() {
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let sk = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &manifest, &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            let good = chunk_payload(0, &image[..256]);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &good, &ctx).map(|r| r.0),
                Some(OTA_STATUS_OK)
            );
            // Out-of-order chunk aborts the whole session (fail-closed).
            let bad = chunk_payload(512, &image[256..512]);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &bad, &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_finish_rejects_bad_signature_and_rolls_back() {
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let raw = manifest_raw(OTA_NEXT, &image, &[0x5Eu8; 64]);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, [0x11u8; 32]);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &raw, &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            let mut off = 0u32;
            for chunk in image.chunks(256) {
                let p = chunk_payload(off, chunk);
                let st =
                    dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &ctx).map(|r| r.0);
                assert_eq!(st, Some(OTA_STATUS_OK));
                off += chunk.len() as u32;
            }
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_FINISH, &[], &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_sink_only_touches_ota_keys() {
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let sk = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, sk.verifying_key().to_bytes());
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &manifest, &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            let p = chunk_payload(0, &image[..64]);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &ctx).map(|r| r.0),
                Some(OTA_STATUS_OK)
            );
            // Staging + manifest live under ota_* keys only; no commit marker yet.
            assert!(sink.exists_staging());
            assert!(!sink.has_commit_marker());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_begin_rejects_manifest_over_storage_budget() {
        // Fail-fast: manifesto dentro do teto de protocolo (2 MiB) mas acima
        // do flash real `storage` (896 KiB) nunca abre sessão.
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let mut raw = manifest_raw(OTA_NEXT, &image, &[0x5Eu8; 64]);
        let over = (OTA_STORAGE_BUDGET_BYTES as u32) + 1;
        assert!(over < MAX_OTA_IMAGE_BYTES as u32);
        raw[4..8].copy_from_slice(&over.to_be_bytes());
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, [0x11u8; 32]);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &raw, &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_unprovisioned_denies_every_op_serial_parity() {
        // Paridade serial/USB: os dois transportes montam o mesmo ctx em
        // `main.rs` e dividem este dispatch, logo o dispositivo sem vínculo
        // de fábrica (não provisionado, R-02/R-06) nega em todo op
        // mutante — serial nega sem vínculo, fail-closed. ABORT segue OK
        // (limpeza idempotente nunca nega).
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let raw = manifest_raw(OTA_NEXT, &image, &[0x5Eu8; 64]);
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(false, true, [0x11u8; 32]);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_BEGIN, &raw, &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            let p = chunk_payload(0, &image[..64]);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_CHUNK, &p, &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_FINISH, &[], &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &ctx),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_ABORT, &[], &ctx),
                Some((OTA_STATUS_OK, Vec::new()))
            );
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_finish_and_commit_deny_denied_key() {
        // NUNCA COMMIT/verify sem chave válida: staging sob chave real,
        // FINISH/COMMIT sob zeros negam + rollback, sem marcador, NVS intacta.
        let mut storage = credentialed_storage();
        let snap = snapshot_keys(storage.backend(), CRED_KEYS);
        let image = ota_image();
        let sk = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let mut ota = OtaState::new(OTA_CURRENT);
        let real = req_ctx(true, true, sk.verifying_key().to_bytes());
        let denied = req_ctx(true, true, OtaKeyProvider::RELEASE_PUBKEY);
        {
            let mut sink = FlashOtaSink::new(storage.backend_mut());
            let stage = |ota: &mut OtaState,
                         sink: &mut FlashOtaSink<'_, MockFlashBackend>,
                         ctx: &OtaRequestCtx| {
                assert_eq!(
                    dispatch_ota_request(ota, sink, OP_OTA_BEGIN, &manifest, ctx),
                    Some((OTA_STATUS_OK, Vec::new()))
                );
                let mut off = 0u32;
                for chunk in image.chunks(256) {
                    let p = chunk_payload(off, chunk);
                    assert_eq!(
                        dispatch_ota_request(ota, sink, OP_OTA_CHUNK, &p, ctx).map(|r| r.0),
                        Some(OTA_STATUS_OK)
                    );
                    off += chunk.len() as u32;
                }
            };
            stage(&mut ota, &mut sink, &real);
            // FINISH sob zeros: FAIL + rollback, mesmo com imagem íntegra.
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_FINISH, &[], &denied),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.exists_staging());
            // Re-estagia, verifica sob chave real...
            stage(&mut ota, &mut sink, &real);
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_FINISH, &[], &real),
                Some((OTA_STATUS_OK, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Verified);
            // ...mas COMMIT sob zeros: FAIL + rollback, sem marcador.
            assert_eq!(
                dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &denied),
                Some((OTA_STATUS_FAIL, Vec::new()))
            );
            assert_eq!(ota.phase(), OtaPhase::Idle);
            assert!(!sink.has_commit_marker());
            assert_eq!(sink.committed_marker(), None);
        }
        assert!(keys_unchanged(storage.backend(), CRED_KEYS, &snap));
    }

    #[test]
    fn ota_sink_enforces_storage_budget_standalone() {
        // O sink sozinho nega além de 896 KiB (defesa em profundidade além
        // do fail-fast do BEGIN): preenche exatamente até o teto com chunks
        // NVS de 8 KiB e prova que o próximo byte nega `Overflow`.
        let mut backend = MockFlashBackend::new();
        let full = vec![0xA5u8; OTA_CHUNK_LEN];
        let mut sink = FlashOtaSink::new(&mut backend);
        let mut written = 0usize;
        while written < OTA_STORAGE_BUDGET_BYTES {
            sink.write_chunk(written, &full).expect("in-budget chunk");
            written += OTA_CHUNK_LEN;
        }
        assert_eq!(written, OTA_STORAGE_BUDGET_BYTES);
        assert_eq!(sink.write_chunk(written, &[0x01]), Err(OtaError::Overflow));
        assert!(backend.exists(&chunk_key(0)));
    }

    #[test]
    fn ota_verify_signature_roundtrip() {
        let sk = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
        let vk = sk.verifying_key().to_bytes();
        let msg = b"ota-release-40-bytes-padded.........";
        let sig = sk.sign(msg).to_bytes();
        assert!(verify_ota_signature(&vk, msg, &sig));
        let mut bad_sig = sig;
        bad_sig[0] ^= 0xFF;
        assert!(!verify_ota_signature(&vk, msg, &bad_sig));
        assert!(!verify_ota_signature(&[0x22u8; 32], msg, &sig));
        assert!(!verify_ota_signature(&[0u8; 32], msg, &sig));
        assert!(!verify_ota_signature(&vk, b"tampered message", &sig));
    }

    #[test]
    fn ota_commit_hook_semantics() {
        // Default `false`; só test-mode honra o hook (release ignora e
        // exige o BOOT físico via `up`).
        let plain = req_ctx(true, false, [0x11u8; 32]);
        assert!(!plain.up_hook);
        assert!(!plain.commit_up_ok());
        assert!(req_ctx(true, true, [0x11u8; 32]).commit_up_ok());
        let hooked = req_ctx_hook(true, false, true, [0x11u8; 32]);
        assert_eq!(hooked.commit_up_ok(), cfg!(feature = "test-mode"));
        assert!(req_ctx_hook(true, true, true, [0x11u8; 32]).commit_up_ok());
    }

    #[test]
    fn ota_commit_hook_gate_no_dispatch() {
        // COMMIT sem UP físico: com o hook armado passa em test-mode e
        // nega (`NEED_UP`, sessão preservada) em release; sem hook nega
        // nos dois builds.
        use crate::ota::OP_OTA_COMMIT;
        let mut storage = credentialed_storage();
        let image = ota_image();
        let sk = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
        let manifest = signed_manifest(OTA_NEXT, &image, &sk);
        let pubkey = sk.verifying_key().to_bytes();
        let mut ota = OtaState::new(OTA_CURRENT);
        let ctx = req_ctx(true, true, pubkey);
        let mut sink = FlashOtaSink::new(storage.backend_mut());
        stage_to_verified(&mut ota, &mut sink, &manifest, &image, &ctx);
        // Sem hook: NEED_UP nos dois builds, sessão preservada.
        let no_hook = req_ctx_hook(true, false, false, pubkey);
        assert_eq!(
            dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &no_hook),
            Some((OTA_STATUS_NEED_UP, Vec::new()))
        );
        assert_eq!(ota.phase(), OtaPhase::Verified);
        // Com hook: test-mode comita (OK + marker); release nega NEED_UP.
        let hooked = req_ctx_hook(true, false, true, pubkey);
        let (st, _) = dispatch_ota_request(&mut ota, &mut sink, OP_OTA_COMMIT, &[], &hooked)
            .expect("commit dispatch");
        #[cfg(feature = "test-mode")]
        {
            assert_eq!(st, OTA_STATUS_OK);
            assert_eq!(ota.phase(), OtaPhase::Committed);
            assert_eq!(sink.committed_marker(), Some(OTA_NEXT));
        }
        #[cfg(not(feature = "test-mode"))]
        {
            assert_eq!(st, OTA_STATUS_NEED_UP);
            assert_eq!(ota.phase(), OtaPhase::Verified);
            assert!(!sink.has_commit_marker());
        }
    }
}
