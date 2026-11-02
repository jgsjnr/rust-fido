use super::parse::PivSlot;
/// Erro tipado do store PIV (firmware mapeia do `StorageError`; sem panics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivStoreError {
    /// Registro ausente (= não provisionado).
    NotFound,
    /// Registro parcial/corrompido.
    Corrupted,
    /// Falha de escrita/leitura.
    Io,
}

/// Store byte-a-byte dos registros PIV.
///
/// O firmware implementa com `SecureStorage` (envelope AES-GCM AEGN v1 +
/// retry de escrita); aqui só o contrato. Exemplo de adapter no firmware:
/// `load_record(k)` = `secure.load(k).map_err(...)`, `store_record(k, v)` =
/// `secure.store(k, v, &IGNORED)` (nonce TRNG interno).
pub trait PivRecordStore {
    /// Lê o registro `key`; `NotFound` = ausente.
    fn load_record(&self, key: &str) -> Result<Vec<u8>, PivStoreError>;
    /// Grava o registro `key` (sobrescreve).
    fn store_record(&mut self, key: &str, value: &[u8]) -> Result<(), PivStoreError>;
    /// Apaga o registro `key` (ausente = ok, idempotente).
    fn delete_record(&mut self, key: &str) -> Result<(), PivStoreError>;
}

/// Erro tipado do backend cripto PIV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivCryptoError {
    /// Operação indisponível (sem backend injetado).
    Unavailable,
    /// Algoritmo não suportado pelo backend.
    BadAlg,
    /// Falha na operação.
    Failed,
}

/// Backend cripto dos slots (firmware injeta; chave/RNG/assinatura ficam no firmware).
///
/// `generate` retorna a chave pública (bytes do template `7F 49`);
/// `authenticate` recebe o desafio (`7C` interno) e retorna a resposta (`82`).
pub trait PivKeyBackend {
    /// Gera par no `slot` para `alg` (byte `80` do template `AC`); retorna pública.
    fn generate(&mut self, slot: PivSlot, alg: u8) -> Result<Vec<u8>, PivCryptoError>;
    /// Opera com a privada do `slot` sobre `challenge`; retorna resposta.
    fn authenticate(
        &mut self,
        slot: PivSlot,
        alg: u8,
        challenge: &[u8],
    ) -> Result<Vec<u8>, PivCryptoError>;
}

/// Backend ausente: toda operação = `Unavailable` (vira `69 85` fail-closed).
pub struct NoBackend;

impl PivKeyBackend for NoBackend {
    fn generate(&mut self, _slot: PivSlot, _alg: u8) -> Result<Vec<u8>, PivCryptoError> {
        Err(PivCryptoError::Unavailable)
    }

    fn authenticate(
        &mut self,
        _slot: PivSlot,
        _alg: u8,
        _challenge: &[u8],
    ) -> Result<Vec<u8>, PivCryptoError> {
        Err(PivCryptoError::Unavailable)
    }
}