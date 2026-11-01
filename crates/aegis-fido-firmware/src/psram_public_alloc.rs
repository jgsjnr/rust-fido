//! AegisKey - Segregação Segura de Memória: SRAM Interna (Segredos) vs PSRAM de 8 MB (Público/Rede/OTA/Logs)
//!
//! # Modelo de Ameaça e Arquitetura de Memória
//! No chip ESP32-S3 (WROOM-1 / N8R8), o firmware dispõe de:
//! 1. **512 KiB de SRAM Interna (On-Chip Die):**
//!    - Rápida, privada, integrada ao silício da CPU.
//!    - **EXCLUSIVA** para segredos criptográficos: Chaves mestras, chaves P-256 / RSA / Ed25519,
//!      HKDF, buffers de cifra Just-in-Time com `Zeroize`, pilhas FreeRTOS e `SecureGuardEngine`.
//!    - Com `CONFIG_SPIRAM_USE_CAPS_ALLOC=y`, todo `malloc` padrão do Rust e pilhas FreeRTOS
//!      são alocados **100% da SRAM Interna**.
//!
//! 2. **8 MB de Octal PSRAM Externa (SPIRAM):**
//!    - Conectada via barramento Octal SPI externo ao silício.
//!    - **EXCLUSIVA para coisas públicas, dados não-sensíveis ou dados já cifrados:**
//!      - Imagens de firmware OTA em trânsito (já autenticadas/assinadas ou encriptadas).
//!      - Framebuffer do display OLED virtual / gráfico (`VirtualOledDisplayBuffer`).
//!      - Ring-buffer de logs e telemetria de diagnóstico (sem segredos).
//!      - Buffers de rede Wi-Fi / lwIP e filas de pacotes de transporte BLE NimBLE.
//!
//! Este módulo impõe em tempo de compilação e execução via [`PublicNonSensitivePsramBuffer`] que
//! apenas buffers declarados como não-sensíveis possam ser alocados na PSRAM de 8 MB.

#[cfg(not(target_os = "espidf"))]
extern crate std;
#[cfg(not(target_os = "espidf"))]
use std::vec::Vec;

#[cfg(target_os = "espidf")]
use esp_idf_sys::{heap_caps_free, heap_caps_malloc, MALLOC_CAP_SPIRAM};

/// Categorias permitidas de dados na PSRAM de 8 MB.
/// Segredos (chaves privadas, PINs, seeds, master keys) são PROIBIDOS por arquitetura.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsramBufferCategory {
    /// Imagens de atualização de firmware (staging OTA).
    OtaFirmwareStaging,
    /// Framebuffer gráfico de display (ex: 1024B OLED 128x64 ou matrizes gráficas).
    DisplayFrameBuffer,
    /// Ring-buffer de telemetria e logs públicos de diagnóstico.
    PublicDiagnosticLogs,
    /// Pacotes brutos de transporte de rede (Wi-Fi frame / BLE transport packets).
    NetworkTransportPayload,
}

impl PsramBufferCategory {
    /// Nome descritivo da categoria para auditoria e logs.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::OtaFirmwareStaging => "OTA Firmware Staging Buffer",
            Self::DisplayFrameBuffer => "Display Frame Buffer (128x64 OLED)",
            Self::PublicDiagnosticLogs => "Public Diagnostic Logs Ring-Buffer",
            Self::NetworkTransportPayload => "Network Transport Payload (Wi-Fi/BLE)",
        }
    }
}

/// Buffer alocado especificamente na PSRAM externa de 8 MB para cargas de dados não-sensíveis.
pub struct PublicNonSensitivePsramBuffer {
    category: PsramBufferCategory,
    len: usize,
    capacity: usize,
    #[cfg(target_os = "espidf")]
    ptr: *mut u8,
    #[cfg(not(target_os = "espidf"))]
    storage: Vec<u8>,
}

unsafe impl Send for PublicNonSensitivePsramBuffer {}
unsafe impl Sync for PublicNonSensitivePsramBuffer {}

impl PublicNonSensitivePsramBuffer {
    /// Aloca um novo buffer de tamanho `capacity` na PSRAM externa de 8 MB.
    ///
    /// Exige a especificação explícita da categoria para fins de auditoria de segurança.
    pub fn allocate(category: PsramBufferCategory, capacity: usize) -> Result<Self, &'static str> {
        if capacity == 0 {
            return Err("Capacity must be greater than 0");
        }

        #[cfg(target_os = "espidf")]
        {
            let raw_ptr = unsafe { heap_caps_malloc(capacity, MALLOC_CAP_SPIRAM) as *mut u8 };
            if raw_ptr.is_null() {
                return Err("Failed to allocate memory from 8MB PSRAM (MALLOC_CAP_SPIRAM)");
            }
            // Zera o buffer alocado na PSRAM
            unsafe {
                core::ptr::write_bytes(raw_ptr, 0, capacity);
            }
            Ok(Self {
                category,
                len: 0,
                capacity,
                ptr: raw_ptr,
            })
        }

        #[cfg(not(target_os = "espidf"))]
        {
            let storage = std::vec![0u8; capacity];
            Ok(Self {
                category,
                len: 0,
                capacity,
                storage,
            })
        }
    }

    /// Retorna a categoria do buffer na PSRAM.
    #[inline]
    pub const fn category(&self) -> PsramBufferCategory {
        self.category
    }

    /// Capacidade total alocada na PSRAM em bytes.
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Tamanho lógico preenchido do buffer em bytes.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Verifica se o buffer está vazio.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Define o comprimento lógico de dados válidos.
    pub fn set_len(&mut self, new_len: usize) -> Result<(), &'static str> {
        if new_len > self.capacity {
            return Err("New length exceeds allocated PSRAM capacity");
        }
        self.len = new_len;
        Ok(())
    }

    /// Escreve uma fatia de bytes no início do buffer na PSRAM.
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > self.capacity {
            return Err("Data length exceeds PSRAM buffer capacity");
        }
        let slice = self.as_mut_slice();
        slice[..data.len()].copy_from_slice(data);
        self.len = data.len();
        Ok(())
    }

    /// Fatia imutável dos dados na PSRAM.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        #[cfg(target_os = "espidf")]
        unsafe {
            core::slice::from_raw_parts(self.ptr, self.capacity)
        }

        #[cfg(not(target_os = "espidf"))]
        {
            &self.storage[..self.capacity]
        }
    }

    /// Fatia mutável dos dados na PSRAM.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        #[cfg(target_os = "espidf")]
        unsafe {
            core::slice::from_raw_parts_mut(self.ptr, self.capacity)
        }

        #[cfg(not(target_os = "espidf"))]
        {
            &mut self.storage[..self.capacity]
        }
    }
}

impl Drop for PublicNonSensitivePsramBuffer {
    fn drop(&mut self) {
        #[cfg(target_os = "espidf")]
        {
            if !self.ptr.is_null() {
                // Limpeza antes de desalocar
                unsafe {
                    core::ptr::write_bytes(self.ptr, 0, self.capacity);
                    heap_caps_free(self.ptr as *mut _);
                }
                self.ptr = core::ptr::null_mut();
            }
        }
        #[cfg(not(target_os = "espidf"))]
        {
            for b in self.storage.iter_mut() {
                *b = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psram_buffer_allocation_and_categories() {
        let mut ota_buf = PublicNonSensitivePsramBuffer::allocate(
            PsramBufferCategory::OtaFirmwareStaging,
            64 * 1024,
        ).expect("Allocation of 64KB OTA staging buffer in PSRAM should succeed");

        assert_eq!(ota_buf.category(), PsramBufferCategory::OtaFirmwareStaging);
        assert_eq!(ota_buf.capacity(), 64 * 1024);
        assert_eq!(ota_buf.len(), 0);

        let test_payload = [0x5A; 1024];
        ota_buf.write_bytes(&test_payload).expect("Write to PSRAM should succeed");
        assert_eq!(ota_buf.len(), 1024);
        assert_eq!(&ota_buf.as_slice()[..1024], &test_payload[..]);
    }

    #[test]
    fn test_psram_oled_framebuffer() {
        let mut oled_buf = PublicNonSensitivePsramBuffer::allocate(
            PsramBufferCategory::DisplayFrameBuffer,
            1024,
        ).expect("Allocation of 1024B virtual OLED framebuffer in PSRAM should succeed");

        assert_eq!(oled_buf.category(), PsramBufferCategory::DisplayFrameBuffer);
        assert_eq!(oled_buf.capacity(), 1024);

        // Pattern write
        oled_buf.as_mut_slice()[0] = 0xAA;
        oled_buf.as_mut_slice()[1023] = 0x55;
        assert_eq!(oled_buf.as_slice()[0], 0xAA);
        assert_eq!(oled_buf.as_slice()[1023], 0x55);
    }

    #[test]
    fn test_psram_capacity_overflow_protection() {
        let mut log_buf = PublicNonSensitivePsramBuffer::allocate(
            PsramBufferCategory::PublicDiagnosticLogs,
            512,
        ).expect("Allocation should succeed");

        let oversize = [0xFF; 513];
        let err = log_buf.write_bytes(&oversize);
        assert!(err.is_err(), "Oversize write to PSRAM buffer must fail safely");
    }
}
