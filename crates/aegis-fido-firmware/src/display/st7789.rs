//! ST7789 IPS LCD Driver for LilyGO T-Display and T-Display-S3.

extern crate alloc;

use super::ui::{DisplayBuffer, UiScreen};
#[cfg(target_os = "espidf")]
use alloc::vec::Vec;

#[cfg(target_os = "espidf")]
extern "C" {
    fn aegis_display_init() -> esp_idf_sys::esp_err_t;
    fn aegis_display_set_backlight(on: bool);
    fn aegis_display_flush(
        x1: u16,
        y1: u16,
        x2: u16,
        y2: u16,
        pixels: *const u16,
        count: u32,
    );
}

/// ST7789 Display Controller Configuration
pub struct St7789Config {
    pub backlight_gpio: i32,
    pub power_gpio: i32,
    pub width: u16,
    pub height: u16,
}

impl Default for St7789Config {
    fn default() -> Self {
        #[cfg(feature = "board-ttgo-classic")]
        {
            Self {
                backlight_gpio: 4,
                power_gpio: 23,
                width: 135,
                height: 240,
            }
        }
        #[cfg(not(feature = "board-ttgo-classic"))]
        {
            Self {
                backlight_gpio: 38,
                power_gpio: 15,
                width: 320,
                height: 170,
            }
        }
    }
}

/// Hardware ST7789 Display Driver
pub struct St7789Display {
    pub config: St7789Config,
    pub is_initialized: bool,
}

impl St7789Display {
    pub fn new(config: St7789Config) -> Self {
        Self {
            config,
            is_initialized: false,
        }
    }

    /// Initializes SPI Bus, GPIOs and ST7789 Controller
    pub fn init_hardware(&mut self) -> Result<(), &'static str> {
        #[cfg(target_os = "espidf")]
        unsafe {
            let ret = aegis_display_init();
            if ret != esp_idf_sys::ESP_OK {
                return Err("Failed to initialize ST7789 hardware");
            }
        }

        self.is_initialized = true;
        Ok(())
    }

    /// Sets the backlight state (on / off)
    pub fn set_backlight(&mut self, on: bool) {
        let _ = on;
        #[cfg(target_os = "espidf")]
        if self.is_initialized {
            unsafe {
                aegis_display_set_backlight(on);
            }
        }
    }

    /// Flushes the framebuffer in bands reusing a small BE temp.
    ///
    /// Antes duplicava o full 64800B (`be_pixels` do tamanho do framebuffer):
    /// pico de 129600B que abortava o classic em loop. Agora fatia por
    /// `DISPLAY_BAND_HEIGHT` (classic 135x40 = 10800B) com o mesmo
    /// `aegis_display_flush(x1,y1,x2,y2)` por banda; mesmos pixels finais.
    pub fn flush_framebuffer(&mut self, buffer: &DisplayBuffer) -> Result<(), &'static str> {
        if !self.is_initialized {
            return Err("Display not initialized");
        }

        #[cfg(target_os = "espidf")]
        unsafe {
            use super::ui::{DISPLAY_BAND_HEIGHT, DISPLAY_HEIGHT, DISPLAY_WIDTH};
            use embedded_graphics::prelude::IntoStorage;

            let width = DISPLAY_WIDTH as u16;
            let band_h = DISPLAY_BAND_HEIGHT.max(1);
            let mut be: Vec<u16> = Vec::with_capacity(DISPLAY_WIDTH * band_h);
            let mut y0 = 0usize;
            while y0 < DISPLAY_HEIGHT {
                let h = (DISPLAY_HEIGHT - y0).min(band_h);
                be.clear();
                be.extend(
                    buffer.pixels[y0 * DISPLAY_WIDTH..(y0 + h) * DISPLAY_WIDTH]
                        .iter()
                        .map(|px| (*px).into_storage().swap_bytes()),
                );
                aegis_display_flush(
                    0,
                    y0 as u16,
                    width - 1,
                    (y0 + h - 1) as u16,
                    be.as_ptr(),
                    be.len() as u32,
                );
                y0 += h;
            }
        }

        let _ = buffer;
        Ok(())
    }

    /// Renders `screen` directly band-by-band without the full 64800B buffer.
    ///
    /// Classic: pico ~10800B (banda RGB565) + ~10800B (BE temporario
    /// compartilhado e reutilizado), nunca o full. S3 mantem o caminho
    /// `flush_framebuffer` com buffer cheio; mesma imagem final, so fatiamento.
    pub fn flush_screen_banded(&mut self, screen: &UiScreen) -> Result<(), &'static str> {
        if !self.is_initialized {
            return Err("Display not initialized");
        }
        #[cfg(target_os = "espidf")]
        unsafe {
            use super::ui::{
                AegisUiRenderer, DisplayBand, DISPLAY_BAND_HEIGHT, DISPLAY_HEIGHT, DISPLAY_WIDTH,
            };
            use embedded_graphics::prelude::IntoStorage;

            let width = DISPLAY_WIDTH as u16;
            let band_h = DISPLAY_BAND_HEIGHT.max(1);
            let mut band = DisplayBand::new(0, band_h.min(DISPLAY_HEIGHT));
            let mut be: Vec<u16> = Vec::with_capacity(DISPLAY_WIDTH * band_h);
            let mut y0 = 0usize;
            while y0 < DISPLAY_HEIGHT {
                let h = (DISPLAY_HEIGHT - y0).min(band_h);
                band.set_window(y0, h);
                AegisUiRenderer::render(screen, &mut band);
                be.clear();
                be.extend(band.pixels.iter().map(|px| (*px).into_storage().swap_bytes()));
                aegis_display_flush(
                    0,
                    y0 as u16,
                    width - 1,
                    (y0 + h - 1) as u16,
                    be.as_ptr(),
                    be.len() as u32,
                );
                y0 += h;
            }
        }
        #[cfg(not(target_os = "espidf"))]
        {
            use super::ui::{AegisUiRenderer, DisplayBand, DISPLAY_BAND_HEIGHT, DISPLAY_HEIGHT};
            let band_h = DISPLAY_BAND_HEIGHT.max(1);
            let mut y0 = 0usize;
            while y0 < DISPLAY_HEIGHT {
                let h = (DISPLAY_HEIGHT - y0).min(band_h);
                let mut band = DisplayBand::new(y0, h);
                AegisUiRenderer::render(screen, &mut band);
                let _ = &band;
                y0 += h;
            }
        }
        let _ = screen;
        Ok(())
    }
}
