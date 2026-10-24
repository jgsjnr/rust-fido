//! APDU curto comum (PIV/OpenPGP): parser estrito, sem estendido.
//!
//! Extraido de piv_cmd (corte auditoria): piv_cmd e openpgp_cmd dependem daqui.
//! Contrato: [CLA INS P1 P2] + [Lc dados] + [Le?]; Lc=0 nega (UnsupportedExtended);
//! total > 261 B nega (TooLarge). no_std (alloc-only); sem segredo em log.

extern crate alloc;

use alloc::vec::Vec;

/// Total maximo do APDU curto (CLA INS P1 P2 + Lc + 255 B + Le).
pub const APDU_MAX_TOTAL: usize = 4 + 1 + 255 + 1;

/// APDU curto ja validado (sem estendido).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apdu {
    /// Byte de classe.
    pub cla: u8,
    /// Instrucao.
    pub ins: u8,
    /// Parametro 1.
    pub p1: u8,
    /// Parametro 2.
    pub p2: u8,
    /// Campo de dados (Lc bytes, pode ser vazio).
    pub data: Vec<u8>,
    /// Verdadeiro se Le de 1 byte estava presente.
    pub le_present: bool,
}

/// Erros do parser APDU. Sem eco de bytes de entrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduError {
    /// Menos de 4 B (sem cabecalho completo).
    TooShort,
    /// Lc alem do fim ou sobra apos Le.
    BadLength,
    /// Total acima de 261 B.
    TooLarge,
    /// Lc = 0 (APDU estendido nao suportado neste device).
    UnsupportedExtended,
}

/// Parser estrito de APDU curto: `[CLA INS P1 P2] [Lc dados] [Le?]`.
pub fn parse_apdu(raw: &[u8]) -> Result<Apdu, ApduError> {
    if raw.len() < 4 {
        return Err(ApduError::TooShort);
    }
    if raw.len() > APDU_MAX_TOTAL {
        return Err(ApduError::TooLarge);
    }
    let (cla, ins, p1, p2) = (raw[0], raw[1], raw[2], raw[3]);
    if raw.len() == 4 {
        return Ok(Apdu {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le_present: false,
        });
    }
    let lc = raw[4] as usize;
    if lc == 0 {
        return Err(ApduError::UnsupportedExtended);
    }
    if raw.len() < 5 + lc {
        return Err(ApduError::BadLength);
    }
    let rest = &raw[5 + lc..];
    if rest.len() > 1 {
        return Err(ApduError::BadLength);
    }
    Ok(Apdu {
        cla,
        ins,
        p1,
        p2,
        data: raw[5..5 + lc].to_vec(),
        le_present: rest.len() == 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn cabecalho_sozinho_sem_lc() {
        let a = parse_apdu(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
        assert_eq!((a.cla, a.ins, a.p1, a.p2), (0x00, 0xA4, 0x04, 0x00));
        assert!(a.data.is_empty());
        assert!(!a.le_present);
    }

    #[test]
    fn lc_dados_e_le() {
        // CLA INS P1 P2 Lc=3 "abc" Le=0x00.
        let raw = [0x00, 0xCA, 0x00, 0x5E, 0x03, b'a', b'b', b'c', 0x00];
        let a = parse_apdu(&raw).unwrap();
        assert_eq!(a.data, b"abc");
        assert!(a.le_present);
        // Sem Le: valido, le_present=false.
        let raw2 = [0x00, 0xCA, 0x00, 0x5E, 0x03, b'a', b'b', b'c'];
        let b = parse_apdu(&raw2).unwrap();
        assert_eq!(b.data, b"abc");
        assert!(!b.le_present);
    }

    #[test]
    fn curto_demais_nega() {
        assert_eq!(parse_apdu(&[]), Err(ApduError::TooShort));
        assert_eq!(parse_apdu(&[0x00, 0xA4, 0x04]), Err(ApduError::TooShort));
    }

    #[test]
    fn lc_zero_nega_estendido() {
        assert_eq!(
            parse_apdu(&[0x00, 0xA4, 0x04, 0x00, 0x00]),
            Err(ApduError::UnsupportedExtended)
        );
    }

    #[test]
    fn comprimento_ruim_nega() {
        // Lc=3 mas so 2 B apos.
        assert_eq!(
            parse_apdu(&[0x00, 0xCA, 0x00, 0x5E, 0x03, b'a', b'b']),
            Err(ApduError::BadLength)
        );
        // Sobra de 2 B apos Le.
        assert_eq!(
            parse_apdu(&[0x00, 0xCA, 0x00, 0x5E, 0x01, b'a', 0x00, 0x00]),
            Err(ApduError::BadLength)
        );
    }

    #[test]
    fn teto_261b() {
        // Maximo valido: 4 + 1 + 255 + 1 = 261.
        let mut raw = vec![0x00, 0xDA, 0x00, 0x5E, 255];
        raw.extend(vec![0x41; 255]);
        raw.push(0x00);
        assert_eq!(raw.len(), APDU_MAX_TOTAL);
        let a = parse_apdu(&raw).unwrap();
        assert_eq!(a.data.len(), 255);
        assert!(a.le_present);
        // 262 B nega com TooLarge.
        raw.push(0x00);
        assert_eq!(parse_apdu(&raw), Err(ApduError::TooLarge));
    }
}
