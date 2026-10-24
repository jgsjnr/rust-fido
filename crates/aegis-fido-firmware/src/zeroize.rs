//! T-SF-03 RAM scrub: apagamento de segredos em RAM (GEN-DEVICE).
//!
//! Motivo: chave/PIN residuais apos o uso permitem dump por falha fisica;
//! scrub deterministico na queda fecha a janela (secao 6: canal lateral).
//!
//! - `scrub` zera qualquer fatia mutavel (escritas volateis via `zeroize`).
//! - `SecretBytes<N>`: dono de N bytes, apaga no `Drop` e no `clear`, e seu
//!   `Debug` mostra so o tamanho (segredo nunca em log).
//! - Sem mock falso: o teste le a memoria apos o scrub e prova os zeros.

use core::fmt;

use zeroize::Zeroize;

/// Zera a fatia na hora. Chame antes de liberar buffers de chave/PIN.
pub fn scrub(buf: &mut [u8]) {
    buf.zeroize();
}

/// Dono de N bytes secretos com apagamento garantido na queda.
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Leitura emprestada; prefira `clear` assim que terminar de usar.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Apaga agora, sem esperar o `Drop`.
    pub fn clear(&mut self) {
        self.bytes.zeroize();
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(len={}, redacted)", N)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_zeroes_memory() {
        let mut buf = [0xA5u8; 64];
        scrub(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
        // Fatiado tambem zera.
        let mut big = [0xFFu8; 32];
        scrub(&mut big[..16]);
        assert!(big[..16].iter().all(|&b| b == 0));
        assert!(big[16..].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn clear_zeroes_owner() {
        let mut s = SecretBytes::new([0x5Au8; 32]);
        assert_eq!(s.as_slice().len(), 32);
        s.clear();
        assert!(s.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn debug_never_leaks_secret() {
        let s = SecretBytes::new([0xABu8; 4]);
        let dbg = format!("{:?}", s);
        assert!(dbg.contains("len=4"));
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("ab"));
        assert!(!dbg.contains("AB"));
    }
}
