// T-ST-02 Envelope de backup AEGN v1 (GEN-APP-STORE).
//
// Motivo: backup-restore e export-import de passkeys exigem envelope
// autenticado com anti-replay, mas nenhum modulo provava o formato AEGN;
// sem este modulo, cada chamador inventaria o proprio framing (secao 9).
//
// - GEN-APP-STORE: o app gera a chave e sela (envelope), o device guarda o
//   blob e so abre sob binding -> UP -> PIN; as funcoes sao puras e rodam
//   nos dois lados com o mesmo codigo.
// - Layout: MAGIC(4)=AEGN || VER(1) || SUITE(1) || CTR(8 be) || NONCE(12)
//   || CT || TAG(16). AAD = dominio fixo + ctx + ctr (cabecalho tambem
//   autenticado: adulterar o ctr nega em vez de dessincronizar).
// - Anti-replay: open exige ctr > min_ctr (o chamador persiste o maior ctr
//   ja visto com verify-after-write; crash entre seal e persist e
//   at-least-once por desenho, documentado e testado). ctr 0 e reservado
//   (nunca abre); o primeiro envelope usa ctr 1 com min_ctr 0.
// - AEAD real via SoftwareAead (AES-256-GCM); EspAead ancora o HW do S3.
// - Limites: claro <= 2048 B; ctx <= 64 B (teto de RAM, secao 9).
// - Fail-closed: magia/versao/suite/tamanho negam antes do GCM; truncado
//   (fuzz) nega sem panico; chave != 32 B nega.
// - Sem segredo em log: erros nao carregam chave, nonce, ctx ou claro.

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto_aead::{AeadAlgorithm, AeadBackend, AeadError, SoftwareAead, NONCE_LEN};
use crate::crypto_hrng::{HrngError, HrngSource};

/// Magia do envelope (4 B ASCII).
pub const BACKUP_MAGIC: [u8; 4] = *b"AEGN";
/// Versao do formato.
pub const BACKUP_VER: u8 = 0x01;
/// Suite: AES-256-GCM (unica compilada hoje).
pub const BACKUP_SUITE_AES256GCM: u8 = 0x01;
/// Claro maximo por envelope (teto de RAM).
pub const BACKUP_MAX_PLAINTEXT: usize = 2048;
/// Contexto (AAD) maximo do chamador.
pub const BACKUP_MAX_CTX: usize = 64;
/// Tamanho minimo: 4 + 1 + 1 + 8 + 12 + 16 (tag sem claro).
pub const BACKUP_MIN_LEN: usize = 4 + 1 + 1 + 8 + NONCE_LEN + 16;
/// Dominio do AAD (separa este envelope de outros usos do GCM).
pub const BACKUP_AAD_DOMAIN: &[u8] = b"aegis-backup-env-v1:";

/// Erros do envelope. Sem chave, nonce, ctx ou claro nas variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupError {
    /// Magia diferente de AEGN.
    BadMagic,
    /// Versao desconhecida.
    BadVersion,
    /// Suite nao compilada (so 0x01 abre hoje).
    UnsupportedSuite,
    /// Envelope menor que o minimo ou truncado.
    Truncated,
    /// Chave fora de 32 B.
    BadKey,
    /// Claro acima de 2048 B ou ctx acima de 64 B.
    TooLarge,
    /// Falha de abertura autenticada (adulterado ou chave/ctx errados).
    Decrypt,
    /// Contador nao avancou (replay ou duplicata).
    Replay,
    /// Contador reservado (0) ou no teto (sem sucessor possivel).
    CounterExhausted,
    /// HRNG indisponivel para o nonce.
    Rng,
}

impl core::fmt::Display for BackupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "bad backup magic"),
            Self::BadVersion => write!(f, "bad backup version"),
            Self::UnsupportedSuite => write!(f, "unsupported backup suite"),
            Self::Truncated => write!(f, "truncated backup envelope"),
            Self::BadKey => write!(f, "bad backup key length"),
            Self::TooLarge => write!(f, "backup payload too large"),
            Self::Decrypt => write!(f, "backup decrypt failed"),
            Self::Replay => write!(f, "backup replay rejected"),
            Self::CounterExhausted => write!(f, "backup counter exhausted"),
            Self::Rng => write!(f, "backup rng failure"),
        }
    }
}

impl From<HrngError> for BackupError {
    fn from(_: HrngError) -> Self {
        Self::Rng
    }
}

impl From<AeadError> for BackupError {
    fn from(_: AeadError) -> Self {
        Self::Decrypt
    }
}

/// AAD = dominio + ctx + ctr (cabecalho autenticado junto).
fn aad(ctx: &[u8], ctr: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(BACKUP_AAD_DOMAIN.len() + ctx.len() + 8);
    out.extend_from_slice(BACKUP_AAD_DOMAIN);
    out.extend_from_slice(ctx);
    out.extend_from_slice(&ctr.to_be_bytes());
    out
}

/// Gera um nonce de 12 B via HRNG injetado.
pub fn fresh_nonce<R: HrngSource>(rng: &mut R) -> Result<[u8; NONCE_LEN], BackupError> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce)?;
    Ok(nonce)
}

/// Sela o claro em envelope AEGNv1 (ctr >= 1, monotono por chamador).
pub fn seal(
    key: &[u8],
    nonce12: &[u8; NONCE_LEN],
    ctr: u64,
    ctx: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, BackupError> {
    if key.len() != 32 {
        return Err(BackupError::BadKey);
    }
    if ctr == 0 || ctr == u64::MAX {
        return Err(BackupError::CounterExhausted);
    }
    if plaintext.len() > BACKUP_MAX_PLAINTEXT || ctx.len() > BACKUP_MAX_CTX {
        return Err(BackupError::TooLarge);
    }
    let ct = SoftwareAead::seal(
        AeadAlgorithm::Aes256Gcm,
        key,
        nonce12,
        &aad(ctx, ctr),
        plaintext,
    )?;
    let mut out = Vec::with_capacity(4 + 1 + 1 + 8 + NONCE_LEN + ct.len());
    out.extend_from_slice(&BACKUP_MAGIC);
    out.push(BACKUP_VER);
    out.push(BACKUP_SUITE_AES256GCM);
    out.extend_from_slice(&ctr.to_be_bytes());
    out.extend_from_slice(nonce12);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Abre o envelope exigindo ctr > min_ctr (anti-replay por contador).
pub fn open(
    env: &[u8],
    key: &[u8],
    ctx: &[u8],
    min_ctr: u64,
) -> Result<(Vec<u8>, u64), BackupError> {
    if key.len() != 32 {
        return Err(BackupError::BadKey);
    }
    if env.len() < BACKUP_MIN_LEN {
        return Err(BackupError::Truncated);
    }
    if env[0..4] != BACKUP_MAGIC {
        return Err(BackupError::BadMagic);
    }
    if env[4] != BACKUP_VER {
        return Err(BackupError::BadVersion);
    }
    if env[5] != BACKUP_SUITE_AES256GCM {
        return Err(BackupError::UnsupportedSuite);
    }
    let mut ctr_raw = [0u8; 8];
    ctr_raw.copy_from_slice(&env[6..14]);
    let ctr = u64::from_be_bytes(ctr_raw);
    if ctr == 0 || ctr <= min_ctr {
        // ctr 0 reservado cai aqui como Replay (fail-closed p/ genesis).
        return Err(BackupError::Replay);
    }
    let mut nonce12 = [0u8; NONCE_LEN];
    nonce12.copy_from_slice(&env[14..14 + NONCE_LEN]);
    let pt = SoftwareAead::open(
        AeadAlgorithm::Aes256Gcm,
        key,
        &nonce12,
        &aad(ctx, ctr),
        &env[14 + NONCE_LEN..],
    )?;
    Ok((pt, ctr))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRng(u64);

    impl HrngSource for TestRng {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), HrngError> {
            if dest.is_empty() {
                return Err(HrngError::TooShort);
            }
            for b in dest.iter_mut() {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *b = (self.0 & 0xFF) as u8;
            }
            Ok(())
        }
    }

    const KEY: [u8; 32] = [0u8; 32];
    const NONCE: [u8; 12] = [0u8; 12];

    #[test]
    fn layout_e_kat_regressao() {
        // KAT de regressao (AES-256-GCM via SoftwareAead): chave/nonce zero,
        // ctr 1, ctx vazio, PT 16 B zero. Fixa o fio byte a byte.
        let env = seal(&KEY, &NONCE, 1, b"", &[0u8; 16]).unwrap();
        assert_eq!(&env[..4], b"AEGN");
        assert_eq!(env[4], 0x01);
        assert_eq!(env[5], 0x01);
        assert_eq!(&env[6..14], &[0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&env[14..26], &NONCE);
        assert_eq!(env.len(), 26 + 32);
        // Valor obtido de build auditado (aes-gcm); se mudar, o fio mudou.
        let body = &env[26..];
        assert_eq!(
            body,
            &hex::decode("cea7403d4d606b6e074ec5d3baf39d18b158f7aa69af17df6fcbb154f8a8280d")
                .unwrap()[..]
        );
        let (pt, ctr) = open(&env, &KEY, b"", 0).unwrap();
        assert_eq!(pt, alloc::vec![0u8; 16]);
        assert_eq!(ctr, 1);
    }

    #[test]
    fn roundtrip_e_ctx_vinculado() {
        let key = [0x42u8; 32];
        let mut rng = TestRng(0xC0FFEE);
        let nonce = fresh_nonce(&mut rng).unwrap();
        let env = seal(&key, &nonce, 7, b"vault:slot1", b"segredo-do-backup").unwrap();
        let (pt, ctr) = open(&env, &key, b"vault:slot1", 6).unwrap();
        assert_eq!(pt, b"segredo-do-backup".to_vec());
        assert_eq!(ctr, 7);
        assert_eq!(
            open(&env, &key, b"vault:slot2", 6),
            Err(BackupError::Decrypt)
        );
        assert_eq!(
            open(&env, &[0x43u8; 32], b"vault:slot1", 6),
            Err(BackupError::Decrypt)
        );
    }

    #[test]
    fn replay_e_duplicata() {
        let env = seal(&KEY, &NONCE, 5, b"", b"dados").unwrap();
        assert!(open(&env, &KEY, b"", 4).is_ok());
        assert_eq!(open(&env, &KEY, b"", 5), Err(BackupError::Replay));
        assert_eq!(open(&env, &KEY, b"", 9), Err(BackupError::Replay));
    }

    #[test]
    fn power_loss_at_least_once() {
        let env = seal(&KEY, &NONCE, 6, b"", b"dados").unwrap();
        let (pt, ctr) = open(&env, &KEY, b"", 5).unwrap();
        assert_eq!(pt, b"dados".to_vec());
        assert_eq!(ctr, 6);
        assert_eq!(open(&env, &KEY, b"", ctr), Err(BackupError::Replay));
    }

    #[test]
    fn adulterado_e_truncado() {
        let env = seal(&KEY, &NONCE, 1, b"c", b"abcdef").unwrap();
        let mut bad = env.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert_eq!(open(&bad, &KEY, b"c", 0), Err(BackupError::Decrypt));
        // ctr adulterado nega (cabecalho autenticado no AAD).
        let mut badc = env.clone();
        badc[12] ^= 0x01;
        assert_eq!(open(&badc, &KEY, b"c", 0), Err(BackupError::Decrypt));
        let mut badm = env.clone();
        badm[0] ^= 0xFF;
        assert_eq!(open(&badm, &KEY, b"c", 0), Err(BackupError::BadMagic));
        let mut badv = env.clone();
        badv[4] = 0x02;
        assert_eq!(open(&badv, &KEY, b"c", 0), Err(BackupError::BadVersion));
        let mut bads = env.clone();
        bads[5] = 0x02;
        assert_eq!(
            open(&bads, &KEY, b"c", 0),
            Err(BackupError::UnsupportedSuite)
        );
        for cut in [0, 1, 10, BACKUP_MIN_LEN - 1] {
            assert_eq!(
                open(&env[..cut], &KEY, b"c", 0),
                Err(BackupError::Truncated)
            );
        }
        assert_eq!(
            open(&env[..env.len() - 1], &KEY, b"c", 0),
            Err(BackupError::Decrypt)
        );
    }

    #[test]
    fn limites() {
        let big = alloc::vec![0xAAu8; BACKUP_MAX_PLAINTEXT + 1];
        assert_eq!(seal(&KEY, &NONCE, 1, b"", &big), Err(BackupError::TooLarge));
        let bigctx = alloc::vec![0xAAu8; BACKUP_MAX_CTX + 1];
        assert_eq!(
            seal(&KEY, &NONCE, 1, &bigctx, b"x"),
            Err(BackupError::TooLarge)
        );
        assert_eq!(
            seal(&[0u8; 16], &NONCE, 1, b"", b"x"),
            Err(BackupError::BadKey)
        );
        assert_eq!(
            seal(&KEY, &NONCE, 0, b"", b"x"),
            Err(BackupError::CounterExhausted)
        );
        assert_eq!(
            seal(&KEY, &NONCE, u64::MAX, b"", b"x"),
            Err(BackupError::CounterExhausted)
        );
        let max = alloc::vec![0xBBu8; BACKUP_MAX_PLAINTEXT];
        let env = seal(&KEY, &NONCE, 1, b"", &max).unwrap();
        let (pt, _) = open(&env, &KEY, b"", 0).unwrap();
        assert_eq!(pt, max);
        assert!(seal(&KEY, &NONCE, 1, b"", b"").is_ok());
    }
}
