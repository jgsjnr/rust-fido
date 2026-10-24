//! T-CR-06 HRNG (`esp_fill_random`) + health check de entropia (GEN-DEVICE).
//!
//! Motivo: toda chave do device nasce desta fonte; amostra travada/viesada
//! geraria chaves fracas sem ninguem notar (secao 9: health + sem segredo).
//!
//! - Fonte via trait `HrngSource` (R14); `DeviceHrng` chama o ROM do S3 no
//!   alvo ESP-IDF e retorna `Unsupported` no host (fail-closed, sem mock).
//! - `health_check` (SP 800-90B simplificado): trava, monobit e rajada.
//! - `collect_checked` = enche + valida; amostra ruim nunca vira chave.

/// Minimo de bytes para o health check ter sentido estatistico.
pub const HRNG_MIN_HEALTH_BYTES: usize = 64;
/// Teto por coleta (evita esgotar o pool e travar o scheduler).
pub const HRNG_MAX_FILL: usize = 4096;
/// Maior rajada tolerada do mesmo byte em sequencia.
pub const HRNG_MAX_RUN: usize = 8;

/// Erros do HRNG. Sem amostra nas variantes (sem segredo em log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HrngError {
    TooShort,
    TooLarge,
    StuckSample,
    BiasedSample,
    NotSeeded,
    Unsupported,
}

/// Fonte de entropia (R14). O device implementa com o HW; teste usa fixture.
pub trait HrngSource {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), HrngError>;
}

/// HRNG do ESP32-S3 via `esp_fill_random` (ROM/bootloader).
pub struct DeviceHrng;

impl HrngSource for DeviceHrng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), HrngError> {
        if dest.is_empty() {
            return Err(HrngError::TooShort);
        }
        if dest.len() > HRNG_MAX_FILL {
            return Err(HrngError::TooLarge);
        }
        #[cfg(target_os = "espidf")]
        {
            // ESP-IDF: fonte real do silicio (nunca simulada no alvo).
            unsafe {
                esp_idf_sys::esp_fill_random(
                    dest.as_mut_ptr() as *mut core::ffi::c_void,
                    dest.len(),
                );
            }
            return Ok(());
        }
        #[cfg(not(target_os = "espidf"))]
        {
            // Host: sem silicio, sem simulacao silenciosa.
            Err(HrngError::Unsupported)
        }
    }
}

/// Health check SP 800-90B simplificado: trava + monobit + rajada.
pub fn health_check(sample: &[u8]) -> Result<(), HrngError> {
    if sample.len() < HRNG_MIN_HEALTH_BYTES {
        return Err(HrngError::TooShort);
    }
    // 1. Travada: todos os bytes iguais (inclui zero e 0xFF).
    if sample.iter().all(|&b| b == sample[0]) {
        return Err(HrngError::StuckSample);
    }
    // 2. Monobit: proporcao de uns em [35%, 65%].
    let ones: u64 = sample.iter().map(|b| b.count_ones() as u64).sum();
    let total = (sample.len() as u64) * 8;
    if ones * 100 < total * 35 || ones * 100 > total * 65 {
        return Err(HrngError::BiasedSample);
    }
    // 3. Rajada: sequencia longa do mesmo byte indica fonte colada.
    let mut run = 1usize;
    for w in sample.windows(2) {
        if w[0] == w[1] {
            run += 1;
            if run >= HRNG_MAX_RUN {
                return Err(HrngError::StuckSample);
            }
        } else {
            run = 1;
        }
    }
    Ok(())
}

/// Enche e valida; erro aqui significa NAO usar a amostra como chave.
pub fn collect_checked<S: HrngSource>(src: &mut S, dest: &mut [u8]) -> Result<(), HrngError> {
    if dest.len() < HRNG_MIN_HEALTH_BYTES {
        return Err(HrngError::TooShort);
    }
    if dest.len() > HRNG_MAX_FILL {
        return Err(HrngError::TooLarge);
    }
    src.fill(dest)?;
    health_check(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PRNG xorshift deterministico, SOMENTE fixture de teste.
    struct TestRng(u64);

    impl TestRng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            if x == 0 {
                x = 0x9E3779B97F4A7C15;
            }
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    impl HrngSource for TestRng {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), HrngError> {
            if dest.is_empty() {
                return Err(HrngError::TooShort);
            }
            if dest.len() > HRNG_MAX_FILL {
                return Err(HrngError::TooLarge);
            }
            for chunk in dest.chunks_mut(8) {
                let v = self.next().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            Ok(())
        }
    }

    /// Fonte travada: sempre o mesmo byte (simula HW colado).
    struct StuckRng(u8);

    impl HrngSource for StuckRng {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), HrngError> {
            if dest.is_empty() {
                return Err(HrngError::TooShort);
            }
            dest.fill(self.0);
            Ok(())
        }
    }

    #[test]
    fn good_sample_passes_collect() {
        let mut rng = TestRng(0x12345678);
        let mut buf = [0u8; 128];
        collect_checked(&mut rng, &mut buf).expect("amostra boa passa");
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn stuck_samples_rejected() {
        assert_eq!(health_check(&[0u8; 128]), Err(HrngError::StuckSample));
        assert_eq!(health_check(&[0xFFu8; 128]), Err(HrngError::StuckSample));
        let mut rng = StuckRng(0xA5);
        let mut buf = [0u8; 128];
        assert_eq!(
            collect_checked(&mut rng, &mut buf),
            Err(HrngError::StuckSample)
        );
    }

    #[test]
    fn biased_sample_rejected() {
        // 90% dos bits zero: monobit acusa.
        let mut buf = [0u8; 128];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = if i % 10 == 0 { 0x80 } else { 0x00 };
        }
        assert_eq!(health_check(&buf), Err(HrngError::BiasedSample));
    }

    #[test]
    fn limits_enforced() {
        let mut rng = TestRng(1);
        let mut tiny = [0u8; 8];
        assert_eq!(
            collect_checked(&mut rng, &mut tiny),
            Err(HrngError::TooShort)
        );
        assert_eq!(health_check(&[1u8; 8]), Err(HrngError::TooShort));
        let mut huge = std::vec![0u8; HRNG_MAX_FILL + 1];
        assert_eq!(
            collect_checked(&mut rng, &mut huge),
            Err(HrngError::TooLarge)
        );
    }

    #[test]
    fn device_hrng_fails_closed_on_host() {
        // Host nao tem silicio: erro explicito, nunca bytes falsos.
        let mut buf = [0u8; 128];
        assert_eq!(DeviceHrng.fill(&mut buf), Err(HrngError::Unsupported));
    }
}
