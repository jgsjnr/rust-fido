// T-PI-03 Canal seguro AEGIS-SM-v1 (GEN-DEVICE).
//
// Motivo: PIV/OpenPGP pedem "secure messaging", mas nenhum modulo provava
// um canal com confidencialidade + integridade + anti-replay vinculado a
// sequencia; sem este modulo, APDUs sensiveis trafegariam sem protecao
// (secao 9).
//
// - GEN-DEVICE: sessao estabelecida no device (chaves via provisionamento
//   fora deste modulo); wrap/unwrap executam no device.
// - Construcao documentada AEGIS-SM-v1 (perfil propro, NAO afirma ser
//   SCP02/SCP03/GP): keystream = HMAC-SHA256(kenc, ssc_be8 || ctr_be4) em
//   modo contador (XOR); tag = 8 B iniciais de HMAC-SHA256(kmac, ssc||ct).
//   HMAC-SHA256 real (hmac+sha2); sem cifra inventada.
// - Anti-replay: SSC monotono de 64 bits por direcao; unwrap exige ssc >
//   last_recv; wrap nega em SSC = u64::MAX (SscExhausted: re-estabelecer).
// - Layout: SSC(8 be) || CT || TAG(8). Limites: claro <= 255 B (APDU
//   curto), envelope <= 271 B.
// - Fail-closed: truncado nega antes do MAC; MAC errado nega sem dica;
//   SSC repetido/antigo nega (Replay); comparacao em tempo constante.
// - Power-loss: o tracker e volatil; o chamador persiste last_recv e usa
//   restore() apos reboot (testado); ssc de envio perdido = buraco p/
//   frente, nunca reuso (next_send so anda).
// - Sem segredo em log: erros nao carregam chaves, ssc, ct ou claro.

extern crate alloc;

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

/// Chave de cifra do canal (16 B).
pub const SM_KENC_LEN: usize = 16;
/// Chave de MAC do canal (32 B).
pub const SM_KMAC_LEN: usize = 32;
/// Tamanho da tag (8 B truncados do HMAC-SHA256).
pub const SM_TAG_LEN: usize = 8;
/// Claro maximo (cabe no APDU curto).
pub const SM_MAX_PLAINTEXT: usize = 255;
/// Tamanho do cabecalho SSC.
pub const SM_HDR_LEN: usize = 8;
/// Tamanho minimo do envelope (hdr + tag, claro vazio).
pub const SM_MIN_LEN: usize = SM_HDR_LEN + SM_TAG_LEN;

/// Chaves da sessao. Zera no drop.
#[derive(Debug, Clone)]
pub struct SmKeys {
    /// Chave do keystream (16 B).
    pub kenc: [u8; SM_KENC_LEN],
    /// Chave do MAC (32 B).
    pub kmac: [u8; SM_KMAC_LEN],
}

impl SmKeys {
    /// Constroi validando comprimentos.
    pub fn new(kenc: &[u8], kmac: &[u8]) -> Result<Self, SmError> {
        if kenc.len() != SM_KENC_LEN || kmac.len() != SM_KMAC_LEN {
            return Err(SmError::BadKey);
        }
        let mut k = SmKeys {
            kenc: [0u8; SM_KENC_LEN],
            kmac: [0u8; SM_KMAC_LEN],
        };
        k.kenc.copy_from_slice(kenc);
        k.kmac.copy_from_slice(kmac);
        Ok(k)
    }

    /// Apaga as chaves.
    pub fn wipe(&mut self) {
        self.kenc.zeroize();
        self.kmac.zeroize();
    }
}

impl Drop for SmKeys {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Rastreador de SSC (volatil; persistir last_recv fora, ver restore).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SscTracker {
    next_send: u64,
    last_recv: u64,
}

impl SscTracker {
    /// Novo tracker (sessao recem-estabelecida; last_recv persistido antes).
    pub fn new(last_recv: u64) -> Self {
        Self {
            next_send: last_recv.wrapping_add(1),
            last_recv,
        }
    }

    /// Restaura apos reboot a partir do last_recv persistido.
    pub fn restore(last_recv: u64) -> Self {
        Self::new(last_recv)
    }

    /// Proximo SSC de envio (apoio a persistencia do par).
    pub fn next_send(&self) -> u64 {
        self.next_send
    }

    /// Ultimo SSC recebido (persistir com verify-after-write).
    pub fn last_recv(&self) -> u64 {
        self.last_recv
    }
}

/// Erros do canal. Sem chaves, ssc, ct ou claro nas variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmError {
    /// Chave fora de 16/32 B.
    BadKey,
    /// Claro acima de 255 B.
    TooLarge,
    /// Envelope menor que hdr + tag.
    Truncated,
    /// MAC invalido (adulterado ou chave/ssc errados).
    BadTag,
    /// SSC repetido ou anterior (replay).
    Replay,
    /// SSC de envio no teto (re-estabelecer a sessao).
    SscExhausted,
    /// Falha interna do HMAC (inatingivel; fail-closed sem panic).
    Internal,
}

impl core::fmt::Display for SmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadKey => write!(f, "bad sm key length"),
            Self::TooLarge => write!(f, "sm payload too large"),
            Self::Truncated => write!(f, "truncated sm message"),
            Self::BadTag => write!(f, "sm tag mismatch"),
            Self::Replay => write!(f, "sm replay rejected"),
            Self::SscExhausted => write!(f, "sm ssc exhausted"),
            Self::Internal => write!(f, "sm internal failure"),
        }
    }
}

fn hmac256(key: &[u8], data: &[u8]) -> Result<[u8; 32], SmError> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).map_err(|_| SmError::Internal)?;
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    Ok(buf)
}

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

/// Gera keystream HMAC-CTR e aplica XOR (in-place reversivel).
fn xor_stream(kenc: &[u8; SM_KENC_LEN], ssc: u64, buf: &mut [u8]) -> Result<(), SmError> {
    let mut ctr: u32 = 0;
    let mut off = 0;
    while off < buf.len() {
        let mut inp = [0u8; 12];
        inp[..8].copy_from_slice(&ssc.to_be_bytes());
        inp[8..12].copy_from_slice(&ctr.to_be_bytes());
        let blk = hmac256(kenc, &inp)?;
        for b in blk.iter() {
            if off >= buf.len() {
                break;
            }
            buf[off] ^= *b;
            off += 1;
        }
        ctr = ctr.wrapping_add(1);
    }
    Ok(())
}

/// Protege o claro: SSC(8) || CT || TAG(8); avanca next_send.
pub fn wrap(tracker: &mut SscTracker, keys: &SmKeys, plaintext: &[u8]) -> Result<Vec<u8>, SmError> {
    if plaintext.len() > SM_MAX_PLAINTEXT {
        return Err(SmError::TooLarge);
    }
    let ssc = tracker.next_send;
    if ssc == u64::MAX {
        return Err(SmError::SscExhausted);
    }
    let mut ct = plaintext.to_vec();
    xor_stream(&keys.kenc, ssc, &mut ct)?;
    let mut mac_in = Vec::with_capacity(8 + ct.len());
    mac_in.extend_from_slice(&ssc.to_be_bytes());
    mac_in.extend_from_slice(&ct);
    let tag_full = hmac256(&keys.kmac, &mac_in)?;
    let mut out = Vec::with_capacity(SM_HDR_LEN + ct.len() + SM_TAG_LEN);
    out.extend_from_slice(&ssc.to_be_bytes());
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag_full[..SM_TAG_LEN]);
    tracker.next_send = ssc.wrapping_add(1);
    Ok(out)
}

/// Abre e autentica: exige ssc > last_recv; avanca last_recv.
pub fn unwrap(tracker: &mut SscTracker, keys: &SmKeys, msg: &[u8]) -> Result<Vec<u8>, SmError> {
    if msg.len() < SM_MIN_LEN {
        return Err(SmError::Truncated);
    }
    let mut ssc_raw = [0u8; 8];
    ssc_raw.copy_from_slice(&msg[..8]);
    let ssc = u64::from_be_bytes(ssc_raw);
    if ssc <= tracker.last_recv {
        return Err(SmError::Replay);
    }
    let (ct, tag) = msg[8..].split_at(msg[8..].len() - SM_TAG_LEN);
    let mut mac_in = Vec::with_capacity(8 + ct.len());
    mac_in.extend_from_slice(&ssc_raw);
    mac_in.extend_from_slice(ct);
    let expect = hmac256(&keys.kmac, &mac_in)?;
    if !ct_eq(tag, &expect[..SM_TAG_LEN]) {
        return Err(SmError::BadTag);
    }
    let mut pt = ct.to_vec();
    xor_stream(&keys.kenc, ssc, &mut pt)?;
    tracker.last_recv = ssc;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> SmKeys {
        SmKeys::new(&[0x11u8; SM_KENC_LEN], &[0x22u8; SM_KMAC_LEN]).unwrap()
    }

    /// Construcao independente (mesmo algoritmo, caminho direto no teste):
    /// ancora cruzada contra a implementacao do modulo.
    fn oracle_wrap(kenc: &[u8; 16], kmac: &[u8; 32], ssc: u64, pt: &[u8]) -> Vec<u8> {
        use hmac::Mac as _;
        let mut ct = pt.to_vec();
        let mut block: u32 = 0;
        let mut off = 0;
        while off < ct.len() {
            let mut mac = Hmac::<Sha256>::new_from_slice(kenc).unwrap();
            mac.update(&ssc.to_be_bytes());
            mac.update(&block.to_be_bytes());
            let ks = mac.finalize().into_bytes();
            for b in ks.iter() {
                if off >= ct.len() {
                    break;
                }
                ct[off] ^= *b;
                off += 1;
            }
            block = block.wrapping_add(1);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(kmac).unwrap();
        mac.update(&ssc.to_be_bytes());
        mac.update(&ct);
        let tag = mac.finalize().into_bytes();
        let mut out = Vec::with_capacity(8 + ct.len() + 8);
        out.extend_from_slice(&ssc.to_be_bytes());
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag[..8]);
        out
    }

    #[test]
    fn kat_construcao_cruzada() {
        // Vetor fixo (chaves/ssc/pt congelados) + ancora independente.
        let k = keys();
        let pt = b"GET-DATA-C4";
        let mut tx = SscTracker::new(0);
        let wrapped = wrap(&mut tx, &k, pt).unwrap();
        assert_eq!(&wrapped[..8], &[0, 0, 0, 0, 0, 0, 0, 1]);
        let expect = oracle_wrap(&k.kenc, &k.kmac, 1, pt);
        assert_eq!(wrapped, expect);
        // KAT de regressao: fio congelado byte a byte.
        assert_eq!(
            &wrapped[8..],
            &hex::decode("bb5d846a183df09ef8fb75733abd1662635a6c").unwrap()[..]
        );
        let mut rx = SscTracker::new(0);
        assert_eq!(unwrap(&mut rx, &k, &wrapped).unwrap(), pt.to_vec());
    }

    #[test]
    fn ssc_avanca_e_replay() {
        let k = keys();
        let mut tx = SscTracker::new(10);
        let mut rx = SscTracker::new(10);
        let m1 = wrap(&mut tx, &k, b"um").unwrap();
        let m2 = wrap(&mut tx, &k, b"dois").unwrap();
        assert_eq!(&m1[..8], &[0, 0, 0, 0, 0, 0, 0, 11]);
        assert_eq!(&m2[..8], &[0, 0, 0, 0, 0, 0, 0, 12]);
        assert_eq!(unwrap(&mut rx, &k, &m1).unwrap(), b"um".to_vec());
        // Replay do mesmo nega; pulo p/ frente aceita; antigo nega.
        assert_eq!(unwrap(&mut rx, &k, &m1), Err(SmError::Replay));
        assert_eq!(unwrap(&mut rx, &k, &m2).unwrap(), b"dois".to_vec());
        assert_eq!(unwrap(&mut rx, &k, &m1), Err(SmError::Replay));
    }

    #[test]
    fn tampernega() {
        let k = keys();
        let mut tx = SscTracker::new(0);
        let m = wrap(&mut tx, &k, b"segredo").unwrap();
        // Flip no CT.
        let mut bad = m.clone();
        bad[9] ^= 0x01;
        let mut rx = SscTracker::new(0);
        assert_eq!(unwrap(&mut rx, &k, &bad), Err(SmError::BadTag));
        // Flip na tag.
        let mut badt = m.clone();
        let last = badt.len() - 1;
        badt[last] ^= 0x80;
        assert_eq!(unwrap(&mut rx, &k, &badt), Err(SmError::BadTag));
        // Flip no SSC vira replay (ssc 1 -> outro valor <= last apos ajuste?)
        // ou BadTag: constroi ssc futuro com tag velha.
        let mut bads = m.clone();
        bads[7] = 0x02;
        assert_eq!(unwrap(&mut rx, &k, &bads), Err(SmError::BadTag));
        // Truncados (fuzz): todo corte abaixo do minimo nega.
        for cut in [0, 5, SM_MIN_LEN - 1] {
            assert_eq!(unwrap(&mut rx, &k, &m[..cut]), Err(SmError::Truncated));
        }
        // Corte de 1 B da tag nega (len < min).
        assert_eq!(unwrap(&mut rx, &k, &m[..m.len() - 1]), Err(SmError::BadTag));
    }

    #[test]
    fn limites_e_exaustao() {
        let k = keys();
        let mut tx = SscTracker::new(0);
        assert_eq!(
            wrap(&mut tx, &k, &[0u8; SM_MAX_PLAINTEXT + 1]),
            Err(SmError::TooLarge)
        );
        assert!(wrap(&mut tx, &k, &[0u8; SM_MAX_PLAINTEXT]).is_ok());
        assert!(wrap(&mut tx, &k, b"").is_ok());
        assert!(matches!(
            SmKeys::new(&[0u8; 15], &[0u8; 32]),
            Err(SmError::BadKey)
        ));
        assert!(matches!(
            SmKeys::new(&[0u8; 16], &[0u8; 31]),
            Err(SmError::BadKey)
        ));
        // Exaustao: tracker no teto nega envio.
        let mut full = SscTracker {
            next_send: u64::MAX,
            last_recv: 0,
        };
        assert_eq!(wrap(&mut full, &k, b"x"), Err(SmError::SscExhausted));
    }

    #[test]
    fn power_loss_resync() {
        // last_recv persistido = 20; crash; restore reaceita o proximo.
        let k = keys();
        let mut tx = SscTracker::new(20);
        let m = wrap(&mut tx, &k, b"apos-queda").unwrap();
        let mut rx = SscTracker::restore(20);
        assert_eq!(unwrap(&mut rx, &k, &m).unwrap(), b"apos-queda".to_vec());
        assert_eq!(rx.last_recv(), 21);
        // Envios perdidos no crash (buraco) nao reusam SSC: replay do velho nega.
        assert_eq!(unwrap(&mut rx, &k, &m), Err(SmError::Replay));
    }
}
