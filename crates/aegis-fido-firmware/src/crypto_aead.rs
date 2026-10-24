//! T-CR-02 AEAD: AES-256/128-GCM real; CCM/ChaCha20-Poly1305 fail-closed.
//!
//! Motivo: persistencia cifrada e envelopes exigem AEAD com prova de vetor;
//! sem este modulo, `persistence.rs` nao teria cifra autenticada fim-a-fim.
//!
//! - GEN-DEVICE: selo/abertura executam no device; chave nunca sai em claro.
//! - AES-GCM via `aes-gcm` (alloc); CCM e ChaCha20 sem crate no firmware
//!   retornam `UnsupportedAlgorithm` (fail-closed, sem mock falso).
//! - Limite de 4096 bytes por operacao (teto de memoria, secao 9).
//! - Hardware via trait `AeadBackend` (R14); `EspAead` ancora o HW do S3.

extern crate alloc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use alloc::vec::Vec;

/// Tamanho do nonce GCM (96 bits).
pub const NONCE_LEN: usize = 12;
/// Tamanho da tag GCM.
pub const TAG_LEN: usize = 16;
/// Teto por operacao (bloco arbitrario de 4 KiB da matriz funcional).
pub const MAX_AEAD_BYTES: usize = 4096;

/// Algoritmos AEAD da matriz. So GCM tem backend compilado hoje.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    Aes256Gcm,
    Aes128Gcm,
    Aes128Ccm,
    ChaCha20Poly1305,
}

/// Erros AEAD. Nenhuma variante carrega chave, nonce ou claro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    UnsupportedAlgorithm,
    InvalidKey,
    TooLarge,
    EncryptFailed,
    DecryptFailed,
}

/// Backend AEAD (R14): software auditavel; `EspAead` ancora o HW.
pub trait AeadBackend {
    fn seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError>;

    fn open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError>;
}

/// Implementacao software real (AES-GCM verdadeiro, sem mock).
pub struct SoftwareAead;

impl AeadBackend for SoftwareAead {
    fn seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        check_args(alg, key, plaintext.len())?;
        let nonce = Nonce::from(*nonce12);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match alg {
            AeadAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
                cipher
                    .encrypt(&nonce, payload)
                    .map_err(|_| AeadError::EncryptFailed)
            }
            AeadAlgorithm::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
                cipher
                    .encrypt(&nonce, payload)
                    .map_err(|_| AeadError::EncryptFailed)
            }
            AeadAlgorithm::Aes128Ccm | AeadAlgorithm::ChaCha20Poly1305 => {
                Err(AeadError::UnsupportedAlgorithm)
            }
        }
    }

    fn open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        check_args(alg, key, ciphertext_and_tag.len())?;
        // Fuzz truncado: sem tag completa nao ha o que abrir.
        if ciphertext_and_tag.len() < TAG_LEN {
            return Err(AeadError::DecryptFailed);
        }
        let nonce = Nonce::from(*nonce12);
        let payload = Payload {
            msg: ciphertext_and_tag,
            aad,
        };
        match alg {
            AeadAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
                cipher
                    .decrypt(&nonce, payload)
                    .map_err(|_| AeadError::DecryptFailed)
            }
            AeadAlgorithm::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
                cipher
                    .decrypt(&nonce, payload)
                    .map_err(|_| AeadError::DecryptFailed)
            }
            AeadAlgorithm::Aes128Ccm | AeadAlgorithm::ChaCha20Poly1305 => {
                Err(AeadError::UnsupportedAlgorithm)
            }
        }
    }
}

/// Ancoragem ESP32-S3: delega ao software; acelerador GCM entra aqui.
pub struct EspAead;

impl AeadBackend for EspAead {
    fn seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        SoftwareAead::seal(alg, key, nonce12, aad, plaintext)
    }

    fn open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce12: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        SoftwareAead::open(alg, key, nonce12, aad, ciphertext_and_tag)
    }
}

fn check_args(alg: AeadAlgorithm, key: &[u8], body_len: usize) -> Result<(), AeadError> {
    let want = match alg {
        AeadAlgorithm::Aes256Gcm => 32,
        AeadAlgorithm::Aes128Gcm => 16,
        AeadAlgorithm::Aes128Ccm | AeadAlgorithm::ChaCha20Poly1305 => {
            return Err(AeadError::UnsupportedAlgorithm)
        }
    };
    if key.len() != want {
        return Err(AeadError::InvalidKey);
    }
    if body_len > MAX_AEAD_BYTES + TAG_LEN {
        return Err(AeadError::TooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_128: [u8; 16] = [0u8; 16];
    const ZERO_256: [u8; 32] = [0u8; 32];
    const ZERO_NONCE: [u8; NONCE_LEN] = [0u8; NONCE_LEN];

    fn nonce_of(hex_str: &str) -> [u8; NONCE_LEN] {
        let v = hex::decode(hex_str).expect("hex valido");
        let mut out = [0u8; NONCE_LEN];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn gcm_cavs_kat() {
        // NIST CAVS: gcmEncryptExtIV128.rsp e gcmEncryptExtIV256.rsp.
        let k128 = hex::decode("11754cd72aec309bf52f7687212e8957").unwrap();
        let n128 = nonce_of("3c819d9a9bed087615030b65");
        let ct = SoftwareAead::seal(AeadAlgorithm::Aes128Gcm, &k128, &n128, b"", b"")
            .expect("vetor CAVS 128");
        assert_eq!(
            ct.as_slice(),
            hex::decode("250327c674aaf477aef2675748cf6971")
                .unwrap()
                .as_slice()
        );
        let pt = SoftwareAead::open(AeadAlgorithm::Aes128Gcm, &k128, &n128, b"", &ct)
            .expect("abre CAVS 128");
        assert!(pt.is_empty());

        let k256 = hex::decode("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4")
            .unwrap();
        let n256 = nonce_of("516c33929df5a3284ff463d7");
        let ct = SoftwareAead::seal(AeadAlgorithm::Aes256Gcm, &k256, &n256, b"", b"")
            .expect("vetor CAVS 256");
        assert_eq!(
            ct.as_slice(),
            hex::decode("bdc1ac884d332457a1d2664f168c76f0")
                .unwrap()
                .as_slice()
        );
        let pt = SoftwareAead::open(AeadAlgorithm::Aes256Gcm, &k256, &n256, b"", &ct)
            .expect("abre CAVS 256");
        assert!(pt.is_empty());
    }

    #[test]
    fn gcm256_roundtrip_with_aad() {
        let ct = SoftwareAead::seal(
            AeadAlgorithm::Aes256Gcm,
            &ZERO_256,
            &ZERO_NONCE,
            b"header",
            b"credencial",
        )
        .expect("selo");
        assert_eq!(ct.len(), b"credencial".len() + TAG_LEN);
        let pt = SoftwareAead::open(
            AeadAlgorithm::Aes256Gcm,
            &ZERO_256,
            &ZERO_NONCE,
            b"header",
            &ct,
        )
        .expect("abre");
        assert_eq!(pt.as_slice(), b"credencial");
    }

    #[test]
    fn rejects_tampered_truncated_wrong_key() {
        let ct = SoftwareAead::seal(
            AeadAlgorithm::Aes256Gcm,
            &ZERO_256,
            &ZERO_NONCE,
            b"aad",
            b"dados",
        )
        .unwrap();
        // Bit flip no corpo.
        let mut bit = ct.clone();
        bit[0] ^= 0x01;
        assert_eq!(
            SoftwareAead::open(
                AeadAlgorithm::Aes256Gcm,
                &ZERO_256,
                &ZERO_NONCE,
                b"aad",
                &bit
            ),
            Err(AeadError::DecryptFailed)
        );
        // Tag truncada e corpo vazio.
        assert_eq!(
            SoftwareAead::open(
                AeadAlgorithm::Aes256Gcm,
                &ZERO_256,
                &ZERO_NONCE,
                b"aad",
                &ct[..ct.len() - 1]
            ),
            Err(AeadError::DecryptFailed)
        );
        assert_eq!(
            SoftwareAead::open(
                AeadAlgorithm::Aes256Gcm,
                &ZERO_256,
                &ZERO_NONCE,
                b"aad",
                &[]
            ),
            Err(AeadError::DecryptFailed)
        );
        // AAD divergente e chave errada.
        assert_eq!(
            SoftwareAead::open(
                AeadAlgorithm::Aes256Gcm,
                &ZERO_256,
                &ZERO_NONCE,
                b"outro",
                &ct
            ),
            Err(AeadError::DecryptFailed)
        );
        let mut wrong = ZERO_256;
        wrong[0] = 1;
        assert_eq!(
            SoftwareAead::open(AeadAlgorithm::Aes256Gcm, &wrong, &ZERO_NONCE, b"aad", &ct),
            Err(AeadError::DecryptFailed)
        );
    }

    #[test]
    fn rejects_limits_and_unsupported() {
        let big = alloc::vec![0xA5u8; MAX_AEAD_BYTES + TAG_LEN + 1];
        assert_eq!(
            SoftwareAead::seal(AeadAlgorithm::Aes256Gcm, &ZERO_256, &ZERO_NONCE, b"", &big),
            Err(AeadError::TooLarge)
        );
        assert_eq!(
            SoftwareAead::seal(AeadAlgorithm::Aes256Gcm, &[0u8; 31], &ZERO_NONCE, b"", b"x"),
            Err(AeadError::InvalidKey)
        );
        for alg in [AeadAlgorithm::Aes128Ccm, AeadAlgorithm::ChaCha20Poly1305] {
            assert_eq!(
                SoftwareAead::seal(alg, &ZERO_128, &ZERO_NONCE, b"", b"x"),
                Err(AeadError::UnsupportedAlgorithm)
            );
            assert_eq!(
                SoftwareAead::open(alg, &ZERO_128, &ZERO_NONCE, b"", &[0u8; 16]),
                Err(AeadError::UnsupportedAlgorithm)
            );
        }
    }

    #[test]
    fn esp_backend_delegates() {
        let ct = EspAead::seal(
            AeadAlgorithm::Aes128Gcm,
            &ZERO_128,
            &ZERO_NONCE,
            b"",
            b"ping",
        )
        .unwrap();
        let pt = EspAead::open(AeadAlgorithm::Aes128Gcm, &ZERO_128, &ZERO_NONCE, b"", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"ping");
    }
}
