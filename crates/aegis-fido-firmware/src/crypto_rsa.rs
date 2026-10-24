//! T-CR-04 RSA 2048/3072/4096 (PKCS#1 v1.5, PSS, OAEP) fail-closed (GEN-DEVICE).
//!
//! Motivo: PIV/OpenPGP exigem RSA; gerar 1024 bits hoje seria vulneravel, e
//! operar sem padding correto (raw/X.509 legado) quebra a secao 9.
//!
//! - Sem crate RSA nas deps do firmware: toda operacao criptografica passa
//!   pelo trait `RsaBackend`, cujo software retorna `NotCompiled`
//!   (fail-closed, sem mock falso). O device gerara via HW quando ancorado.
//! - Politica local e dura: 1024 so verifica legado, NUNCA gera; tamanhos
//!   arbitrarios, raw e X.509 sem padding sao rejeitados aqui.
//! - Limites de mensagem por esquema (secao 9: entradas invalidas/truncadas).

/// Tamanhos RSA suportados pela matriz (bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeyBits {
    B1024,
    B2048,
    B3072,
    B4096,
}

impl RsaKeyBits {
    pub fn bits(self) -> u32 {
        match self {
            RsaKeyBits::B1024 => 1024,
            RsaKeyBits::B2048 => 2048,
            RsaKeyBits::B3072 => 3072,
            RsaKeyBits::B4096 => 4096,
        }
    }

    pub fn bytes(self) -> usize {
        (self.bits() / 8) as usize
    }

    /// Converte bits em variante; rejeita tamanhos arbitrarios (NA da matriz).
    pub fn from_bits(bits: u32) -> Result<Self, RsaError> {
        match bits {
            1024 => Ok(RsaKeyBits::B1024),
            2048 => Ok(RsaKeyBits::B2048),
            3072 => Ok(RsaKeyBits::B3072),
            4096 => Ok(RsaKeyBits::B4096),
            _ => Err(RsaError::UnsupportedSize),
        }
    }
}

/// Esquemas com padding moderno. Raw e X.509 legado nao existem aqui.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaScheme {
    Pkcs1v15,
    PssSha256,
    OaepSha256,
}

/// Erros RSA. Sem material de chave nas variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaError {
    /// Gerar 1024 bits e proibido (so verificacao legada, fora do device).
    Generate1024Forbidden,
    UnsupportedSize,
    UnsupportedScheme,
    InputTooLarge,
    InvalidInput,
    /// Sem backend compilado: operacao real bloqueada, nao simulada.
    NotCompiled,
}

/// Politica de geracao: 1024 nunca gera; demais passam ao backend.
pub fn check_generate(bits: RsaKeyBits) -> Result<(), RsaError> {
    match bits {
        RsaKeyBits::B1024 => Err(RsaError::Generate1024Forbidden),
        RsaKeyBits::B2048 | RsaKeyBits::B3072 | RsaKeyBits::B4096 => Ok(()),
    }
}

/// Teto de mensagem em bytes para o esquema (HMAC/SHA-256 com hlen=32).
pub fn max_msg_len(bits: RsaKeyBits, scheme: RsaScheme) -> usize {
    let k = bits.bytes();
    match scheme {
        // PKCS#1 v1.5 cifragem: k - 11.
        RsaScheme::Pkcs1v15 => k.saturating_sub(11),
        // PSS/OAEP com SHA-256: k - 2*32 - 2.
        RsaScheme::PssSha256 | RsaScheme::OaepSha256 => k.saturating_sub(66),
    }
}

/// Valida operacao antes de qualquer backend: tamanho + teto do esquema.
pub fn check_operation(
    bits: RsaKeyBits,
    scheme: RsaScheme,
    msg_len: usize,
) -> Result<(), RsaError> {
    let _ = scheme;
    check_generate_size_ok(bits)?;
    if msg_len == 0 || msg_len > max_msg_len(bits, scheme) {
        return Err(RsaError::InputTooLarge);
    }
    Ok(())
}

fn check_generate_size_ok(bits: RsaKeyBits) -> Result<(), RsaError> {
    match bits {
        RsaKeyBits::B1024 => Err(RsaError::Generate1024Forbidden),
        RsaKeyBits::B2048 | RsaKeyBits::B3072 | RsaKeyBits::B4096 => Ok(()),
    }
}

/// Backend RSA (R14): operacao real so no HW do device; software e NotCompiled.
pub trait RsaBackend {
    fn generate(bits: RsaKeyBits) -> Result<(), RsaError>;
    fn sign(bits: RsaKeyBits, scheme: RsaScheme, msg_len: usize) -> Result<(), RsaError>;
    fn decrypt(bits: RsaKeyBits, scheme: RsaScheme, ct_len: usize) -> Result<(), RsaError>;
}

/// Software fail-closed: politica passa, criptografia real nao existe aqui.
pub struct SoftwareRsa;

impl RsaBackend for SoftwareRsa {
    fn generate(bits: RsaKeyBits) -> Result<(), RsaError> {
        check_generate(bits)?;
        Err(RsaError::NotCompiled)
    }

    fn sign(bits: RsaKeyBits, scheme: RsaScheme, msg_len: usize) -> Result<(), RsaError> {
        check_operation(bits, scheme, msg_len)?;
        Err(RsaError::NotCompiled)
    }

    fn decrypt(bits: RsaKeyBits, scheme: RsaScheme, ct_len: usize) -> Result<(), RsaError> {
        check_generate_size_ok(bits)?;
        if ct_len != bits.bytes() {
            return Err(RsaError::InvalidInput);
        }
        let _ = scheme;
        Err(RsaError::NotCompiled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_1024_generate() {
        assert_eq!(
            check_generate(RsaKeyBits::B1024),
            Err(RsaError::Generate1024Forbidden)
        );
        assert_eq!(
            SoftwareRsa::generate(RsaKeyBits::B1024),
            Err(RsaError::Generate1024Forbidden)
        );
        assert_eq!(
            SoftwareRsa::sign(RsaKeyBits::B1024, RsaScheme::PssSha256, 32),
            Err(RsaError::Generate1024Forbidden)
        );
    }

    #[test]
    fn allows_modern_sizes_but_not_compiled() {
        for bits in [RsaKeyBits::B2048, RsaKeyBits::B3072, RsaKeyBits::B4096] {
            assert_eq!(check_generate(bits), Ok(()));
            // Fail-closed: politica ok, backend ausente (sem mock falso).
            assert_eq!(SoftwareRsa::generate(bits), Err(RsaError::NotCompiled));
        }
    }

    #[test]
    fn rejects_arbitrary_sizes() {
        for bad in [512u32, 1023, 1025, 2047, 4097, 8192] {
            assert_eq!(RsaKeyBits::from_bits(bad), Err(RsaError::UnsupportedSize));
        }
        assert_eq!(RsaKeyBits::from_bits(2048).unwrap().bits(), 2048);
    }

    #[test]
    fn enforces_scheme_limits() {
        // OAEP-SHA256 2048: 256 - 66 = 190.
        assert_eq!(max_msg_len(RsaKeyBits::B2048, RsaScheme::OaepSha256), 190);
        assert_eq!(
            max_msg_len(RsaKeyBits::B3072, RsaScheme::PssSha256),
            384 - 66
        );
        assert_eq!(
            check_operation(RsaKeyBits::B2048, RsaScheme::OaepSha256, 191),
            Err(RsaError::InputTooLarge)
        );
        assert_eq!(
            check_operation(RsaKeyBits::B2048, RsaScheme::OaepSha256, 0),
            Err(RsaError::InputTooLarge)
        );
        assert_eq!(
            check_operation(RsaKeyBits::B2048, RsaScheme::OaepSha256, 190),
            Ok(())
        );
        // decrypt exige bloco cheio; truncado nao entra no backend.
        assert_eq!(
            SoftwareRsa::decrypt(RsaKeyBits::B2048, RsaScheme::OaepSha256, 255),
            Err(RsaError::InvalidInput)
        );
        assert_eq!(
            SoftwareRsa::decrypt(RsaKeyBits::B2048, RsaScheme::OaepSha256, 256),
            Err(RsaError::NotCompiled)
        );
    }

    #[test]
    fn pkcs1_vectors_sizes_documented() {
        // Tetos PKCS#1 v1.5 cifragem: k-11 (vetores oficiais entram com o backend).
        assert_eq!(max_msg_len(RsaKeyBits::B2048, RsaScheme::Pkcs1v15), 245);
        assert_eq!(
            max_msg_len(RsaKeyBits::B4096, RsaScheme::OaepSha256),
            512 - 66
        );
    }
}
