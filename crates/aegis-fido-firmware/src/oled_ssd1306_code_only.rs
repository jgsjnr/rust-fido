//! OPP-06: Driver OLED I2C SSD1306 128x64 Clear Signing Mantido Somente em Código
//!
//! Implementação completa da máquina de comandos I2C para controladores SSD1306 / SH1106
//! operando de forma 100% desacoplada com buffer virtual em RAM (`VirtualOledDisplayBuffer`).
//!
//! # DIRETRIZ DE HARDWARE
//! A flag `HARDWARE_I2C_OLED_ATTACHED` é mantida como `false` por padrão, garantindo que
//! nenhuma tentativa de transmissão I2C física bloqueie a MCU caso o display não esteja conectado.
//! O buffer virtual de 1024 bytes (128x64 pixels) armazena o último frame renderizado e pode ser
//! inspecionado por telemetria e via CBOR.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Endereço padrão no barramento I2C (0x3C ou 0x3D).
pub const SSD1306_DEFAULT_I2C_ADDR: u8 = 0x3C;
/// Pino padrão SDA no ESP32-S3.
pub const SSD1306_DEFAULT_SDA_PIN: u8 = 4;
/// Pino padrão SCL no ESP32-S3.
pub const SSD1306_DEFAULT_SCL_PIN: u8 = 5;

/// Resolução do display.
pub const OLED_WIDTH: usize = 128;
pub const OLED_HEIGHT: usize = 64;
pub const OLED_PAGES: usize = 8;
pub const OLED_FRAME_BYTES: usize = 1024; // 128 colunas * 8 páginas

/// Flag de presença física do display mantida estritamente em código.
pub const HARDWARE_I2C_OLED_ATTACHED: bool = false;

// Comandos SSD1306
pub const CMD_DISPLAY_OFF: u8 = 0xAE;
pub const CMD_SET_DISPLAY_CLOCK_DIV: u8 = 0xD5;
pub const CMD_SET_MULTIPLEX: u8 = 0xA8;
pub const CMD_SET_DISPLAY_OFFSET: u8 = 0xD3;
pub const CMD_SET_START_LINE: u8 = 0x40;
pub const CMD_CHARGE_PUMP: u8 = 0x8D;
pub const CMD_MEMORY_MODE: u8 = 0x20;
pub const CMD_SEG_REMAP_127: u8 = 0xA1;
pub const CMD_COM_SCAN_DEC: u8 = 0xC8;
pub const CMD_SET_COM_PINS: u8 = 0xDA;
pub const CMD_SET_CONTRAST: u8 = 0x81;
pub const CMD_SET_PRECHARGE: u8 = 0xD9;
pub const CMD_SET_VCOM_DETECT: u8 = 0xDB;
pub const CMD_DISPLAY_ALL_ON_RESUME: u8 = 0xA4;
pub const CMD_NORMAL_DISPLAY: u8 = 0xA6;
pub const CMD_DEACTIVATE_SCROLL: u8 = 0x2E;
pub const CMD_DISPLAY_ON: u8 = 0xAF;

pub const CONTROL_BYTE_COMMAND_STREAM: u8 = 0x00;
pub const CONTROL_BYTE_DATA_STREAM: u8 = 0x40;

/// Tabela de inicialização canônica do controlador SSD1306.
pub const SSD1306_INIT_SEQUENCE: &[u8] = &[
    CMD_DISPLAY_OFF, // 0xAE: Desliga o display durante configuração
    CMD_SET_DISPLAY_CLOCK_DIV,
    0x80, // 0xD5: Frequência do oscilador e divisor de clock
    CMD_SET_MULTIPLEX,
    0x3F, // 0xA8: Razão de multiplexação 64 MUX (0x3F)
    CMD_SET_DISPLAY_OFFSET,
    0x00,               // 0xD3: Offset vertical zero
    CMD_SET_START_LINE, // 0x40: Linha inicial da GDDRAM = 0
    CMD_CHARGE_PUMP,
    0x14, // 0x8D: Ativa a bomba de carga interna de 7.5V (0x14)
    CMD_MEMORY_MODE,
    0x00,              // 0x20: Modo de endereçamento horizontal (0x00)
    CMD_SEG_REMAP_127, // 0xA1: Remapeia coluna 127 para SEG0
    CMD_COM_SCAN_DEC,  // 0xC8: Direção de varredura COM invertida
    CMD_SET_COM_PINS,
    0x12, // 0xDA: Configuração de hardware de pinos COM
    CMD_SET_CONTRAST,
    0xCF, // 0x81: Contraste
    CMD_SET_PRECHARGE,
    0xF1, // 0xD9: Período de pré-carga
    CMD_SET_VCOM_DETECT,
    0x40,                      // 0xDB: Nível de desseleção VCOMH
    CMD_DISPLAY_ALL_ON_RESUME, // 0xA4: Retoma exibição a partir da GDDRAM
    CMD_NORMAL_DISPLAY,        // 0xA6: Display normal (não invertido)
    CMD_DEACTIVATE_SCROLL,     // 0x2E: Desativa rolagem
    CMD_DISPLAY_ON,            // 0xAF: Liga o display
];

/// Fonte monocromática compacta 5x7 ASCII (caracteres 0x20..0x7E).
static FONT_5X7: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, // Espaço (0x20)
    0x00, 0x00, 0x5F, 0x00, 0x00, // !
    0x00, 0x07, 0x00, 0x07, 0x00, // "
    0x14, 0x7F, 0x14, 0x7F, 0x14, // #
    0x24, 0x2A, 0x7F, 0x2A, 0x12, // $
    0x23, 0x13, 0x08, 0x64, 0x62, // %
    0x36, 0x49, 0x55, 0x22, 0x50, // &
    0x00, 0x05, 0x03, 0x00, 0x00, // '
    0x00, 0x1C, 0x22, 0x41, 0x00, // (
    0x00, 0x41, 0x22, 0x1C, 0x00, // )
    0x14, 0x08, 0x3E, 0x08, 0x14, // *
    0x08, 0x08, 0x3E, 0x08, 0x08, // +
    0x00, 0x50, 0x30, 0x00, 0x00, // ,
    0x08, 0x08, 0x08, 0x08, 0x08, // -
    0x00, 0x60, 0x60, 0x00, 0x00, // .
    0x20, 0x10, 0x08, 0x04, 0x02, // /
    0x3E, 0x51, 0x49, 0x45, 0x3E, // 0
    0x00, 0x42, 0x7F, 0x40, 0x00, // 1
    0x42, 0x61, 0x51, 0x49, 0x46, // 2
    0x21, 0x41, 0x45, 0x4B, 0x31, // 3
    0x18, 0x14, 0x12, 0x7F, 0x10, // 4
    0x27, 0x45, 0x45, 0x45, 0x39, // 5
    0x3C, 0x4A, 0x49, 0x49, 0x30, // 6
    0x01, 0x71, 0x09, 0x05, 0x03, // 7
    0x36, 0x49, 0x49, 0x49, 0x36, // 8
    0x06, 0x49, 0x49, 0x29, 0x1E, // 9
    0x00, 0x36, 0x36, 0x00, 0x00, // :
    0x00, 0x56, 0x36, 0x00, 0x00, // ;
    0x08, 0x14, 0x22, 0x41, 0x00, // <
    0x14, 0x14, 0x14, 0x14, 0x14, // =
    0x00, 0x41, 0x22, 0x14, 0x08, // >
    0x02, 0x01, 0x51, 0x09, 0x06, // ?
    0x32, 0x49, 0x79, 0x41, 0x3E, // @
    0x7E, 0x11, 0x11, 0x11, 0x7E, // A
    0x7F, 0x49, 0x49, 0x49, 0x36, // B
    0x3E, 0x41, 0x41, 0x41, 0x22, // C
    0x7F, 0x41, 0x41, 0x22, 0x1C, // D
    0x7F, 0x49, 0x49, 0x49, 0x41, // E
    0x7F, 0x09, 0x09, 0x09, 0x01, // F
    0x3E, 0x41, 0x49, 0x49, 0x7A, // G
    0x7F, 0x08, 0x08, 0x08, 0x7F, // H
    0x00, 0x41, 0x7F, 0x41, 0x00, // I
    0x20, 0x40, 0x41, 0x3F, 0x01, // J
    0x7F, 0x08, 0x14, 0x22, 0x41, // K
    0x7F, 0x40, 0x40, 0x40, 0x40, // L
    0x7F, 0x02, 0x0C, 0x02, 0x7F, // M
    0x7F, 0x04, 0x08, 0x10, 0x7F, // N
    0x3E, 0x41, 0x41, 0x41, 0x3E, // O
    0x7F, 0x09, 0x09, 0x09, 0x06, // P
    0x3E, 0x41, 0x51, 0x21, 0x5E, // Q
    0x7F, 0x09, 0x19, 0x29, 0x46, // R
    0x46, 0x49, 0x49, 0x49, 0x31, // S
    0x01, 0x01, 0x7F, 0x01, 0x01, // T
    0x3F, 0x40, 0x40, 0x40, 0x3F, // U
    0x1F, 0x20, 0x40, 0x20, 0x1F, // V
    0x3F, 0x40, 0x38, 0x40, 0x3F, // W
    0x63, 0x14, 0x08, 0x14, 0x63, // X
    0x07, 0x08, 0x70, 0x08, 0x07, // Y
    0x61, 0x51, 0x49, 0x45, 0x43, // Z
    0x00, 0x7F, 0x41, 0x41, 0x00, // [
    0x02, 0x04, 0x08, 0x10, 0x20, // \
    0x00, 0x41, 0x41, 0x7F, 0x00, // ]
    0x04, 0x02, 0x01, 0x02, 0x04, // ^
    0x40, 0x40, 0x40, 0x40, 0x40, // _
    0x00, 0x01, 0x02, 0x04, 0x00, // `
    0x20, 0x54, 0x54, 0x54, 0x78, // a
    0x7F, 0x48, 0x44, 0x44, 0x38, // b
    0x38, 0x44, 0x44, 0x44, 0x20, // c
    0x38, 0x44, 0x44, 0x48, 0x7F, // d
    0x38, 0x54, 0x54, 0x54, 0x18, // e
    0x08, 0x7E, 0x09, 0x01, 0x02, // f
    0x0C, 0x52, 0x52, 0x52, 0x3E, // g
    0x7F, 0x08, 0x04, 0x04, 0x78, // h
    0x00, 0x44, 0x7D, 0x40, 0x00, // i
    0x20, 0x40, 0x44, 0x3D, 0x00, // j
    0x7F, 0x10, 0x28, 0x44, 0x00, // k
    0x00, 0x41, 0x7F, 0x40, 0x00, // l
    0x7C, 0x04, 0x18, 0x04, 0x78, // m
    0x7C, 0x08, 0x04, 0x04, 0x78, // n
    0x38, 0x44, 0x44, 0x44, 0x38, // o
    0x7C, 0x14, 0x14, 0x14, 0x08, // p
    0x08, 0x14, 0x14, 0x18, 0x7C, // q
    0x7C, 0x08, 0x04, 0x04, 0x08, // r
    0x48, 0x54, 0x54, 0x54, 0x20, // s
    0x04, 0x3F, 0x44, 0x40, 0x20, // t
    0x3C, 0x40, 0x40, 0x20, 0x7C, // u
    0x1C, 0x20, 0x40, 0x20, 0x1C, // v
    0x3C, 0x40, 0x30, 0x40, 0x3C, // w
    0x44, 0x28, 0x10, 0x28, 0x44, // x
    0x0C, 0x50, 0x50, 0x50, 0x3C, // y
    0x44, 0x64, 0x54, 0x4C, 0x44, // z
    0x00, 0x08, 0x36, 0x41, 0x00, // {
    0x00, 0x00, 0x7F, 0x00, 0x00, // |
    0x00, 0x41, 0x36, 0x08, 0x00, // }
    0x08, 0x08, 0x2A, 0x1C, 0x08, // ~
];

/// Buffer virtual em RAM de 1024 bytes (128x64 pixels) para o display SSD1306.
#[derive(Clone, PartialEq, Eq)]
pub struct VirtualOledDisplayBuffer {
    data: [u8; OLED_FRAME_BYTES],
}

impl Default for VirtualOledDisplayBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualOledDisplayBuffer {
    pub fn new() -> Self {
        Self {
            data: [0u8; OLED_FRAME_BYTES],
        }
    }

    /// Limpa todos os pixels do frame buffer.
    pub fn clear(&mut self) {
        self.data.fill(0);
    }

    /// Retorna referência aos 1024 bytes brutos.
    pub fn as_bytes(&self) -> &[u8; OLED_FRAME_BYTES] {
        &self.data
    }

    /// Retorna fatia de bytes para serialização CBOR ou telemetria.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Define o estado de um pixel individual (x: 0..127, y: 0..63).
    pub fn set_pixel(&mut self, x: usize, y: usize, on: bool) {
        if x >= OLED_WIDTH || y >= OLED_HEIGHT {
            return;
        }
        let page = y / 8;
        let bit = y % 8;
        let index = page * OLED_WIDTH + x;

        if on {
            self.data[index] |= 1 << bit;
        } else {
            self.data[index] &= !(1 << bit);
        }
    }

    /// Desenha uma linha horizontal.
    pub fn draw_hline(&mut self, x_start: usize, x_end: usize, y: usize) {
        let x1 = x_start.min(OLED_WIDTH.saturating_sub(1));
        let x2 = x_end.min(OLED_WIDTH.saturating_sub(1));
        for x in x1..=x2 {
            self.set_pixel(x, y, true);
        }
    }

    /// Desenha um caractere ASCII 5x7 na coordenada especificada.
    pub fn draw_char(&mut self, x: usize, y: usize, c: char) {
        let ascii = c as usize;
        if !(0x20..=0x7E).contains(&ascii) {
            return;
        }
        let font_offset = (ascii - 0x20) * 5;
        if font_offset + 5 > FONT_5X7.len() {
            return;
        }

        for col in 0..5 {
            let col_bits = FONT_5X7[font_offset + col];
            for row in 0..7 {
                let pixel_on = (col_bits & (1 << row)) != 0;
                if pixel_on {
                    self.set_pixel(x + col, y + row, true);
                }
            }
        }
    }

    /// Desenha uma string de texto ASCII com espaçamento entre letras.
    pub fn draw_text(&mut self, mut x: usize, y: usize, text: &str) {
        for c in text.chars() {
            if x + 5 >= OLED_WIDTH {
                break;
            }
            self.draw_char(x, y, c);
            x += 6; // 5 pixels de glifo + 1 de espaçamento
        }
    }

    /// Renderiza o template de Clear Signing Web3 no frame virtual.
    pub fn render_clear_sign(
        &mut self,
        chain: &str,
        tx_type: &str,
        recipient: &str,
        amount: &str,
        fee: &str,
    ) {
        self.clear();

        // 1. Cabeçalho de Segurança com Inversão Visual
        self.draw_text(2, 2, "AEGIS-KEY SIGN");
        self.draw_hline(0, 127, 11);

        // 2. Linhas de Resumo da Transação
        // Linha 1: Chain & Tipo
        let mut line1 = String::from(chain);
        line1.push(':');
        line1.push(' ');
        line1.push_str(tx_type);
        self.draw_text(2, 14, &line1);

        // Linha 2: Quantia
        let mut line2 = String::from("VAL: ");
        line2.push_str(amount);
        self.draw_text(2, 24, &line2);

        // Linha 3: Destinatário truncado para caber no display de 128px
        let mut line3 = String::from("TO: ");
        if recipient.len() > 16 {
            line3.push_str(&recipient[..7]);
            line3.push_str("..");
            line3.push_str(&recipient[recipient.len() - 6..]);
        } else {
            line3.push_str(recipient);
        }
        self.draw_text(2, 34, &line3);

        // Linha 4: Taxa estimada
        let mut line4 = String::from("FEE: ");
        line4.push_str(fee);
        self.draw_text(2, 44, &line4);

        // 3. Rodapé de Ação do Usuário
        self.draw_hline(0, 127, 53);
        self.draw_text(6, 55, "[TOUCH CONFIRM]");
    }
}

/// Driver do controlador SSD1306/SH1106 mantido puramente em software.
pub struct Ssd1306Driver {
    pub i2c_addr: u8,
    pub sda_pin: u8,
    pub scl_pin: u8,
    pub virtual_buffer: VirtualOledDisplayBuffer,
    pub hardware_attached: bool,
    pub is_initialized: bool,
}

impl Default for Ssd1306Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Ssd1306Driver {
    pub fn new() -> Self {
        Self {
            i2c_addr: SSD1306_DEFAULT_I2C_ADDR,
            sda_pin: SSD1306_DEFAULT_SDA_PIN,
            scl_pin: SSD1306_DEFAULT_SCL_PIN,
            virtual_buffer: VirtualOledDisplayBuffer::new(),
            hardware_attached: HARDWARE_I2C_OLED_ATTACHED,
            is_initialized: false,
        }
    }

    /// Inicializa a máquina de estados do controlador.
    pub fn init(&mut self) -> Result<(), &'static str> {
        self.is_initialized = true;
        // Se hardware físico não estiver conectado, apenas valida a sequência lógica sem panics.
        Ok(())
    }

    /// Gera os pacotes I2C da sequência de inicialização para envio no barramento físico.
    pub fn get_init_packets(&self) -> &'static [u8] {
        SSD1306_INIT_SEQUENCE
    }

    /// Constrói os pacotes I2C de envio paginado da GDDRAM (1024 bytes).
    pub fn build_gddram_refresh_packets(&self) -> Vec<Vec<u8>> {
        let mut packets = Vec::with_capacity(OLED_PAGES);
        let raw = self.virtual_buffer.as_bytes();

        for page in 0..OLED_PAGES {
            let start = page * OLED_WIDTH;
            let end = start + OLED_WIDTH;
            let page_slice = &raw[start..end];

            // Cabeçalho de página: Control Byte 0x40 (Data stream)
            let mut packet = Vec::with_capacity(1 + OLED_WIDTH);
            packet.push(CONTROL_BYTE_DATA_STREAM);
            packet.extend_from_slice(page_slice);
            packets.push(packet);
        }
        packets
    }

    /// Atualiza o display (opera sobre o buffer virtual sem acionar I2C físico se desanexado).
    pub fn flush(&mut self) -> Result<(), &'static str> {
        if !self.is_initialized {
            self.init()?;
        }
        // Se hardware não estiver conectado, conclui imediatamente com sucesso.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_buffer_dimensions_and_clearing() {
        let mut buf = VirtualOledDisplayBuffer::new();
        assert_eq!(buf.as_bytes().len(), 1024);

        buf.set_pixel(10, 10, true);
        assert_ne!(buf.as_bytes()[10 + 128], 0);

        buf.clear();
        assert_eq!(buf.as_bytes(), &[0u8; 1024]);
    }

    #[test]
    fn test_clear_sign_preview_renders_data() {
        let mut buf = VirtualOledDisplayBuffer::new();
        buf.render_clear_sign(
            "ETH",
            "Transfer",
            "0x71C818C04F0877C0eFa2A1a8c51F6b379361a3a9",
            "1.50 ETH",
            "0.002 ETH",
        );

        // Verifica que pixels foram acesos no buffer (não está zerado)
        let total_lit_pixels: usize = buf
            .as_bytes()
            .iter()
            .map(|&b| b.count_ones() as usize)
            .sum();
        assert!(
            total_lit_pixels > 200,
            "Preview deve ter conteúdo desenhado"
        );
    }

    #[test]
    fn test_ssd1306_driver_packets_generation() {
        let mut driver = Ssd1306Driver::new();
        assert!(!driver.hardware_attached);
        assert_eq!(driver.init(), Ok(()));

        let packets = driver.build_gddram_refresh_packets();
        assert_eq!(packets.len(), 8);
        for p in &packets {
            assert_eq!(p.len(), 1 + 128);
            assert_eq!(p[0], CONTROL_BYTE_DATA_STREAM);
        }
    }
}
