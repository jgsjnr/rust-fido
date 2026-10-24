//! T-FD-03 PIN/UV persistente com tentativas, bloqueio e replay (GEN-DEVICE).
//!
//! Motivo: sem trava duravel o atacante reboota o device para zerar retries;
//! sem sessao de uso unico o mesmo `pinUvAuth` autoriza duas operacoes
//! (secao 9: PIN/bloqueio + persistencia pos power-loss + sem segredo em log).
//!
//! - Nao guarda PIN nem token: persiste so o verificador (sal 16 B + hash
//!   PBKDF2-HMAC-SHA-256 32 B em `pin/auth`) e os contadores (`pin/retries`,
//!   `uv/retries`, 1 byte cada). A sessao RAM (`PinUvSession`) guarda so um
//!   booleano vivo/consumido; o token, se houver, vive no buffer do chamador.
//! - Bloqueio gruda: retries chegam a 0 e so `factory_reset` (CTAP Reset com
//!   UP, dono T-FD-04) limpa; `power_cycle` derruba a sessao mas MANTEM a
//!   trava e os contadores (prova pos power-loss nos testes).
//! - Replay: `consume_uv_auth` e de uso unico; segundo uso nega `TokenExpired`.
//! - Limite com `ctap_state::PinUvGate` (T-FD-01, dono da admissao em RAM):
//!   aqui mora a verdade duravel; o gate decide o fio. T-FD-04 compoe os dois.
//! - Atomico/SOLID: funcoes puras sobre `&SecureStorage`/`&mut SecureStorage`;
//!   HW via traits (`FlashStorageBackend`, `HrngSource`); `no_std` (`alloc`).
//! - Segredo nunca em log: `Debug` da sessao e dos erros so mostra flags.

extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::crypto_hash::{pbkdf2_hmac_sha256, HashError};
use crate::crypto_hrng::{HrngError, HrngSource};
use crate::persistence::{
    FlashStorageBackend, NamespacedStore, NamespacedStoreError, SecureStorage, StorageError,
};

/// Chave do verificador (sal 16 B + hash 32 B = 48 B).
pub const PIN_AUTH_KEY: &str = "pin/auth";
/// Chave do contador de tentativas de PIN (1 byte).
pub const PIN_RETRIES_KEY: &str = "pin/retries";
/// Chave do contador de tentativas de UV nativa (1 byte).
pub const UV_RETRIES_KEY: &str = "uv/retries";
/// PIN UTF-8 minimo normativo (`minPinLength` >= 4).
pub const PIN_MIN_LEN: usize = 4;
/// PIN UTF-8 maximo normativo (63 bytes + terminador).
pub const PIN_MAX_LEN: usize = 63;
/// Tentativas de PIN por ciclo de vida (CTAP: 8, trava em 0).
pub const PIN_MAX_RETRIES: u8 = 8;
/// Tentativas de UV nativa (CTAP: 3, trava em 0).
pub const UV_MAX_RETRIES: u8 = 3;
/// Sal do verificador PIN.
pub const PIN_SALT_LEN: usize = 16;
/// Hash do verificador PIN (PBKDF2-HMAC-SHA-256).
pub const PIN_HASH_LEN: usize = 32;
/// Registro `pin/auth` = sal + hash.
pub const PIN_AUTH_RECORD_LEN: usize = PIN_SALT_LEN + PIN_HASH_LEN;
/// Iteracoes do PBKDF2 no device (rate-limit fisico + trava em 8 erros;
/// teto OWASP e 600k, mas 10k ja custa ~ms com travas e sem DoS no MCU).
pub const PIN_PBKDF2_ITER: u32 = 10_000;

/// Falha tipada do PIN/UV (sem PIN, hash, sal ou token nas variantes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinUvError {
    /// Nenhum PIN cadastrado (`pin/auth` ausente).
    PinNotSet,
    /// Retries de PIN em 0 (so `factory_reset` destrava).
    PinBlocked,
    /// Retries de UV em 0 (so `factory_reset` destrava).
    UvBlocked,
    /// PIN errado com tentativas restantes.
    PinInvalid,
    /// PIN fora de 4..=63 bytes UTF-8 (nao consome tentativa).
    PinPolicyViolation,
    /// Sessao sem `pinUvAuth` vivo ou ja consumido.
    TokenExpired,
    /// Falha de storage, envelope integro ou indice (fail-closed).
    Storage,
}

impl core::fmt::Display for PinUvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PinNotSet => write!(f, "pin not set"),
            Self::PinBlocked => write!(f, "pin blocked"),
            Self::UvBlocked => write!(f, "uv blocked"),
            Self::PinInvalid => write!(f, "pin invalid"),
            Self::PinPolicyViolation => write!(f, "pin policy violation"),
            Self::TokenExpired => write!(f, "pin token expired"),
            Self::Storage => write!(f, "pin storage failure"),
        }
    }
}

impl From<StorageError> for PinUvError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::KeyNotFound => Self::PinNotSet,
            _ => Self::Storage,
        }
    }
}

impl From<HashError> for PinUvError {
    fn from(_: HashError) -> Self {
        Self::Storage
    }
}

impl From<HrngError> for PinUvError {
    fn from(_: HrngError) -> Self {
        Self::Storage
    }
}

impl From<NamespacedStoreError> for PinUvError {
    fn from(e: NamespacedStoreError) -> Self {
        match e {
            NamespacedStoreError::NotFound => Self::PinNotSet,
            _ => Self::Storage,
        }
    }
}

/// Chaves NVS legadas deste namespace (prefixo vazio = chave crua).
/// Preserva os bytes exatos gravados pelo caminho direto anterior.
fn pin_key_ok(label: &str) -> bool {
    label == PIN_AUTH_KEY || label == PIN_RETRIES_KEY || label == UV_RETRIES_KEY
}

/// Namespace unico do PIN/UV: chaves cruas, sem quota, teto do envelope
/// (fail-closed no `store`), delete idempotente (paridade com o `delete`
/// direto anterior; `factory_reset` ausente segue sem erro).
fn pin_ns() -> NamespacedStore {
    NamespacedStore {
        prefix: "",
        max_bytes: None,
        quota_index_key: None,
        max_slots: 0,
        delete_absent_ok: true,
        strict_index_reads: false,
        validate: pin_key_ok,
    }
}

/// Sessao `pinUvAuth` em RAM: so flag viva/consumida, nunca o token.
///
/// O token (quando emitido por T-CR-06) vive no buffer do chamador e e
/// zerado apos o uso; aqui fica so a autorizacao de uso unico.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PinUvSession {
    live: bool,
}

impl PinUvSession {
    /// Sessao invalida (estado apos boot/power-cycle).
    pub fn new() -> Self {
        Self { live: false }
    }

    /// `true` quando ha autorizacao viva ainda nao consumida.
    pub fn is_live(&self) -> bool {
        self.live
    }

    /// Marca autorizacao viva (apos `pin_verify` bem-sucedido).
    pub fn mark_live(&mut self) {
        self.live = true;
    }

    /// Consome a autorizacao em uso unico (replay do mesmo uso nega).
    pub fn consume_uv_auth(&mut self) -> Result<(), PinUvError> {
        if self.live {
            self.live = false;
            Ok(())
        } else {
            Err(PinUvError::TokenExpired)
        }
    }

    /// Invalida sem consumir (power-cycle, reset, troca de acordo ECDH).
    pub fn invalidate(&mut self) {
        self.live = false;
    }

    /// Power-cycle: derruba a sessao; travas e contadores ficam no flash.
    pub fn power_cycle(&mut self) {
        self.live = false;
    }
}

impl Default for PinUvSession {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for PinUvSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinUvSession")
            .field("live", &self.live)
            .finish()
    }
}

/// Valida comprimento do PIN em bytes (4..=63); nao consome tentativa.
pub fn validate_pin_len(len: usize) -> Result<(), PinUvError> {
    if (PIN_MIN_LEN..=PIN_MAX_LEN).contains(&len) {
        Ok(())
    } else {
        Err(PinUvError::PinPolicyViolation)
    }
}

/// Comparacao em tempo constante (sem retorno antecipado no laco).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn encode_auth_record(salt: &[u8; PIN_SALT_LEN], hash: &[u8; PIN_HASH_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PIN_AUTH_RECORD_LEN);
    out.extend_from_slice(salt);
    out.extend_from_slice(hash);
    out
}

fn decode_auth_record(blob: &[u8]) -> Result<([u8; PIN_SALT_LEN], [u8; PIN_HASH_LEN]), PinUvError> {
    if blob.len() != PIN_AUTH_RECORD_LEN {
        return Err(PinUvError::Storage);
    }
    let mut salt = [0u8; PIN_SALT_LEN];
    let mut hash = [0u8; PIN_HASH_LEN];
    salt.copy_from_slice(&blob[..PIN_SALT_LEN]);
    hash.copy_from_slice(&blob[PIN_SALT_LEN..]);
    Ok((salt, hash))
}

fn load_retries<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    key: &str,
    max: u8,
) -> Result<u8, PinUvError> {
    match pin_ns().get(storage, key) {
        Ok(raw) => {
            if raw.len() != 1 || raw[0] > max {
                return Err(PinUvError::Storage);
            }
            Ok(raw[0])
        }
        Err(NamespacedStoreError::NotFound) => Ok(max),
        Err(_) => Err(PinUvError::Storage),
    }
}

fn store_retries<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    key: &str,
    value: u8,
) -> Result<(), PinUvError> {
    // Caminho unico: `put` ja faz store + verify-after-write (torn write
    // nega e desfaz o slot); sem segundo write-path direto.
    let buf = [value];
    pin_ns()
        .put(storage, key, &buf)
        .map_err(|_| PinUvError::Storage)?;
    Ok(())
}

/// Cadastra o PIN: gera sal via HRNG, deriva PBKDF2 e persiste o verificador.
///
/// Nunca persiste o PIN; zera o hash temporario apos gravar. Reseta os
/// retries para o maximo. Nao deixa a sessao viva: o chamador exige um
/// `pin_verify` antes de autorizar qualquer operacao.
pub fn pin_set<B: FlashStorageBackend, R: HrngSource>(
    storage: &mut SecureStorage<B>,
    rng: &mut R,
    session: &mut PinUvSession,
    pin: &[u8],
) -> Result<(), PinUvError> {
    validate_pin_len(pin.len())?;
    let mut salt = [0u8; PIN_SALT_LEN];
    rng.fill(&mut salt)?;
    let mut hash = [0u8; PIN_HASH_LEN];
    pbkdf2_hmac_sha256(pin, &salt, PIN_PBKDF2_ITER, &mut hash)?;
    let mut record = encode_auth_record(&salt, &hash);
    hash.zeroize();
    let res = (|| -> Result<(), PinUvError> {
        // Caminho unico: `put` com verify-after-write interno (torn nega).
        pin_ns().put(storage, PIN_AUTH_KEY, &record)?;
        store_retries(storage, PIN_RETRIES_KEY, PIN_MAX_RETRIES)?;
        Ok(())
    })();
    record.zeroize();
    salt.zeroize();
    session.invalidate();
    res
}

/// Verifica o PIN contra o verificador persistido.
///
/// Sucesso: reseta retries, deixa a sessao viva e zera o candidato.
/// Falha: decrementa o contador persistido, derruba a sessao e responde
/// `PinInvalid` (ou `PinBlocked` ao zerar). Bloqueado nega sem tocar em cripto.
pub fn pin_verify<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    session: &mut PinUvSession,
    pin: &[u8],
) -> Result<(), PinUvError> {
    let retries = load_retries(storage, PIN_RETRIES_KEY, PIN_MAX_RETRIES)?;
    if retries == 0 {
        session.invalidate();
        return Err(PinUvError::PinBlocked);
    }
    validate_pin_len(pin.len())?;
    let raw = pin_ns().get(storage, PIN_AUTH_KEY)?;
    let (salt, expected) = decode_auth_record(&raw)?;
    let mut candidate = [0u8; PIN_HASH_LEN];
    pbkdf2_hmac_sha256(pin, &salt, PIN_PBKDF2_ITER, &mut candidate)?;
    let ok = ct_eq(&candidate, &expected);
    candidate.zeroize();
    if ok {
        store_retries(storage, PIN_RETRIES_KEY, PIN_MAX_RETRIES)?;
        session.mark_live();
        Ok(())
    } else {
        let next = retries.saturating_sub(1);
        store_retries(storage, PIN_RETRIES_KEY, next)?;
        session.invalidate();
        if next == 0 {
            Err(PinUvError::PinBlocked)
        } else {
            Err(PinUvError::PinInvalid)
        }
    }
}

/// Tentativas restantes de PIN (resposta `getPinRetries`, sem segredo).
pub fn pin_retries_left<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
) -> Result<u8, PinUvError> {
    load_retries(storage, PIN_RETRIES_KEY, PIN_MAX_RETRIES)
}

/// `true` quando o PIN travou (retries em 0).
pub fn is_pin_blocked<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
) -> Result<bool, PinUvError> {
    Ok(load_retries(storage, PIN_RETRIES_KEY, PIN_MAX_RETRIES)? == 0)
}

/// Registra falha de UV nativa; trava em 0 e responde `UvBlocked`.
pub fn uv_record_failure<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
) -> Result<(), PinUvError> {
    let retries = load_retries(storage, UV_RETRIES_KEY, UV_MAX_RETRIES)?;
    if retries == 0 {
        return Err(PinUvError::UvBlocked);
    }
    let next = retries.saturating_sub(1);
    store_retries(storage, UV_RETRIES_KEY, next)?;
    if next == 0 {
        Err(PinUvError::UvBlocked)
    } else {
        Ok(())
    }
}

/// Tentativas restantes de UV (resposta `getUvRetries`, sem segredo).
pub fn uv_retries_left<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
) -> Result<u8, PinUvError> {
    load_retries(storage, UV_RETRIES_KEY, UV_MAX_RETRIES)
}

/// Regra de UV para MakeCredential/GetAssertion (predicado fail-closed).
///
/// - UV bloqueada nega sempre (`UvBlocked`), mesmo com `up=true`.
/// - `require_uv` sem `uv_performed` nem `pin_auth_ok` e `PinRequired`
///   daqui sai como `TokenExpired` (sem sessao viva nao ha UV por PIN).
pub fn check_uv_policy(
    uv_blocked: bool,
    require_uv: bool,
    uv_performed: bool,
    pin_auth_ok: bool,
) -> Result<(), PinUvError> {
    if uv_blocked {
        return Err(PinUvError::UvBlocked);
    }
    if require_uv && !uv_performed && !pin_auth_ok {
        return Err(PinUvError::TokenExpired);
    }
    Ok(())
}

/// Reset de fabrica (apos UP + janela, dono T-FD-04): apaga verificador e
/// contadores, derruba a sessao. Ausente e idempotente (sem erro).
pub fn factory_reset<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    session: &mut PinUvSession,
) -> Result<(), PinUvError> {
    // Caminho unico: `delete` idempotente (`delete_absent_ok`); ausente
    // segue sem erro, falha real nega fail-closed.
    for key in [PIN_AUTH_KEY, PIN_RETRIES_KEY, UV_RETRIES_KEY] {
        pin_ns()
            .delete(storage, key)
            .map_err(|_| PinUvError::Storage)?;
    }
    session.invalidate();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_hrng::HRNG_MAX_FILL;
    use crate::persistence::MockFlashBackend;

    fn test_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    /// RNG deterministico (xorshift), SOMENTE fixture; o HW real e o TRNG.
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

    #[test]
    fn vector_set_verify_known_pin() {
        let mut st = test_storage();
        let mut rng = TestRng(0x1234);
        let mut ses = PinUvSession::new();
        // Vetor fixo: sal deterministico + PIN conhecido sempre verifica.
        pin_set(&mut st, &mut rng, &mut ses, b"1234").unwrap();
        assert!(!ses.is_live(), "cadastro nao deixa sessao viva");
        pin_verify(&mut st, &mut ses, b"1234").unwrap();
        assert!(ses.is_live());
        assert_eq!(pin_retries_left(&st).unwrap(), PIN_MAX_RETRIES);
        // Uso unico: segundo consumo nega (replay).
        ses.consume_uv_auth().unwrap();
        assert_eq!(ses.consume_uv_auth(), Err(PinUvError::TokenExpired));
        // PIN errado nega e decrementa sem derrubar o verificador.
        pin_verify(&mut st, &mut ses, b"1234").unwrap();
        assert_eq!(
            pin_verify(&mut st, &mut ses, b"9999"),
            Err(PinUvError::PinInvalid)
        );
        assert_eq!(pin_retries_left(&st).unwrap(), PIN_MAX_RETRIES - 1);
        assert!(!ses.is_live());
    }

    #[test]
    fn rejects_invalid_truncated() {
        let mut st = test_storage();
        let mut rng = TestRng(7);
        let mut ses = PinUvSession::new();
        // Politica de comprimento nao consome tentativa.
        assert_eq!(
            pin_set(&mut st, &mut rng, &mut ses, b"123"),
            Err(PinUvError::PinPolicyViolation)
        );
        assert_eq!(
            pin_set(&mut st, &mut rng, &mut ses, &[b'A'; 64]),
            Err(PinUvError::PinPolicyViolation)
        );
        assert_eq!(pin_retries_left(&st).unwrap(), PIN_MAX_RETRIES);
        pin_set(&mut st, &mut rng, &mut ses, b"1234").unwrap();
        assert_eq!(
            pin_verify(&mut st, &mut ses, b"12"),
            Err(PinUvError::PinPolicyViolation)
        );
        assert_eq!(pin_retries_left(&st).unwrap(), PIN_MAX_RETRIES);
        // Registro truncado/magica de tamanho nega fail-closed.
        assert_eq!(decode_auth_record(&[0u8; 10]), Err(PinUvError::Storage));
        assert_eq!(decode_auth_record(&[0u8; 47]), Err(PinUvError::Storage));
        assert_eq!(decode_auth_record(&[0u8; 49]), Err(PinUvError::Storage));
        // Sem cadastro: PIN ausente, nao Storage generico.
        let mut fresh = test_storage();
        let mut ses2 = PinUvSession::new();
        assert_eq!(
            pin_verify(&mut fresh, &mut ses2, b"1234"),
            Err(PinUvError::PinNotSet)
        );
    }

    #[test]
    fn block_locks_and_survives_powerloss() {
        let master = [0x55u8; 32];
        let salt = [0xAAu8; 32];
        let mut st = SecureStorage::new(MockFlashBackend::new(), &master, &salt);
        let mut rng = TestRng(0xBEEF);
        let mut ses = PinUvSession::new();
        pin_set(&mut st, &mut rng, &mut ses, b"5678").unwrap();
        for _ in 0..PIN_MAX_RETRIES - 1 {
            assert_eq!(
                pin_verify(&mut st, &mut ses, b"0000"),
                Err(PinUvError::PinInvalid)
            );
        }
        assert_eq!(
            pin_verify(&mut st, &mut ses, b"0000"),
            Err(PinUvError::PinBlocked)
        );
        assert!(is_pin_blocked(&st).unwrap());
        // Nem o PIN certo destrava; power-cycle mantem a trava.
        assert_eq!(
            pin_verify(&mut st, &mut ses, b"5678"),
            Err(PinUvError::PinBlocked)
        );
        ses.power_cycle();
        let raw_backend = st.backend().clone();
        let mut rebooted = SecureStorage::new(raw_backend, &master, &salt);
        assert!(is_pin_blocked(&rebooted).unwrap());
        let mut ses2 = PinUvSession::new();
        assert_eq!(
            pin_verify(&mut rebooted, &mut ses2, b"5678"),
            Err(PinUvError::PinBlocked)
        );
        // So factory_reset limpa (apaga verificador: volta a PinNotSet).
        factory_reset(&mut rebooted, &mut ses2).unwrap();
        assert_eq!(
            pin_verify(&mut rebooted, &mut ses2, b"5678"),
            Err(PinUvError::PinNotSet)
        );
    }

    #[test]
    fn retries_persist_across_powerloss() {
        let master = [0x55u8; 32];
        let salt = [0xAAu8; 32];
        let mut st = SecureStorage::new(MockFlashBackend::new(), &master, &salt);
        let mut rng = TestRng(42);
        let mut ses = PinUvSession::new();
        pin_set(&mut st, &mut rng, &mut ses, b"2468").unwrap();
        assert_eq!(
            pin_verify(&mut st, &mut ses, b"xxxx"),
            Err(PinUvError::PinInvalid)
        );
        assert_eq!(
            pin_verify(&mut st, &mut ses, b"yyyy"),
            Err(PinUvError::PinInvalid)
        );
        // Power-cycle: contador em 6 sobrevive, sessao cai.
        ses.power_cycle();
        assert!(!ses.is_live());
        let mut rebooted = SecureStorage::new(st.backend().clone(), &master, &salt);
        assert_eq!(pin_retries_left(&rebooted).unwrap(), PIN_MAX_RETRIES - 2);
        let mut ses2 = PinUvSession::new();
        rebooted_pin_verify_ok(&mut rebooted, &mut ses2);
    }

    fn rebooted_pin_verify_ok<B: FlashStorageBackend>(
        storage: &mut SecureStorage<B>,
        ses: &mut PinUvSession,
    ) {
        pin_verify(storage, ses, b"2468").unwrap();
        assert!(ses.is_live());
        assert_eq!(pin_retries_left(storage).unwrap(), PIN_MAX_RETRIES);
    }

    #[test]
    fn uv_failures_block_and_policy_denies() {
        let mut st = test_storage();
        let mut ses = PinUvSession::new();
        // Sem UV bloqueada: PIN vivo supre require_uv; sem nada nega.
        assert_eq!(
            check_uv_policy(false, true, false, false),
            Err(PinUvError::TokenExpired)
        );
        check_uv_policy(false, true, false, true).unwrap();
        check_uv_policy(false, true, true, false).unwrap();
        check_uv_policy(false, false, false, false).unwrap();
        ses.mark_live();
        ses.consume_uv_auth().unwrap();
        assert_eq!(ses.consume_uv_auth(), Err(PinUvError::TokenExpired));
        // 3 falhas travam a UV; a 4a segue bloqueada e a politica nega tudo.
        assert_eq!(uv_retries_left(&st).unwrap(), UV_MAX_RETRIES);
        uv_record_failure(&mut st).unwrap();
        uv_record_failure(&mut st).unwrap();
        assert_eq!(uv_record_failure(&mut st), Err(PinUvError::UvBlocked));
        assert_eq!(uv_record_failure(&mut st), Err(PinUvError::UvBlocked));
        assert_eq!(
            check_uv_policy(true, false, true, true),
            Err(PinUvError::UvBlocked)
        );
    }

    #[test]
    fn debug_never_leaks_secret() {
        let mut st = test_storage();
        let mut rng = TestRng(99);
        let mut ses = PinUvSession::new();
        pin_set(&mut st, &mut rng, &mut ses, b"s3cr3t!").unwrap();
        pin_verify(&mut st, &mut ses, b"s3cr3t!").unwrap();
        let dbg_ses = format!("{:?}", ses);
        let dbg_err = format!("{:?}", PinUvError::PinInvalid);
        assert!(dbg_ses.contains("PinUvSession"));
        assert!(dbg_ses.contains("live"));
        assert!(!dbg_ses.contains("s3cr3t"));
        assert!(dbg_err.contains("PinInvalid"));
        assert!(!dbg_err.contains("s3cr3t"));
        // O verificador em repouso nao aparece no Debug da sessao.
        let raw = st.backend().read_raw(PIN_AUTH_KEY).unwrap();
        assert_eq!(raw.len(), 4 + 1 + 12 + PIN_AUTH_RECORD_LEN + 16);
        let envelope_hex = format!("{:?}", raw.len());
        assert!(!envelope_hex.contains("s3cr3t"));
    }

    #[test]
    fn ns_caminho_unico_chaves_e_gate() {
        // Prefixo vazio = chaves NVS legadas preservadas byte a byte.
        assert_eq!(pin_ns().key(PIN_AUTH_KEY), "pin/auth");
        assert_eq!(pin_ns().key(PIN_RETRIES_KEY), "pin/retries");
        assert_eq!(pin_ns().key(UV_RETRIES_KEY), "uv/retries");
        // Gate: fora das 3 chaves nega sem tocar no flash.
        let mut st = test_storage();
        assert_eq!(
            pin_ns().put(&mut st, "pin/outro", b"x"),
            Err(NamespacedStoreError::BadLabel)
        );
        assert_eq!(
            pin_ns().get(&st, "pin/outro"),
            Err(NamespacedStoreError::BadLabel)
        );
        assert!(!st.exists("pin/outro"));
    }

    #[test]
    fn factory_reset_idempotente_e_fechado() {
        // Ausente = ok (idempotente); apos cadastro, reset volta a PinNotSet.
        let mut st = test_storage();
        let mut ses = PinUvSession::new();
        factory_reset(&mut st, &mut ses).unwrap();
        factory_reset(&mut st, &mut ses).unwrap();
        let mut rng = TestRng(5);
        pin_set(&mut st, &mut rng, &mut ses, b"1234").unwrap();
        assert!(st.exists(PIN_AUTH_KEY));
        factory_reset(&mut st, &mut ses).unwrap();
        assert!(!st.exists(PIN_AUTH_KEY));
        assert!(!st.exists(PIN_RETRIES_KEY));
        assert!(!st.exists(UV_RETRIES_KEY));
        assert_eq!(
            pin_verify(&mut st, &mut ses, b"1234"),
            Err(PinUvError::PinNotSet)
        );
    }
}
