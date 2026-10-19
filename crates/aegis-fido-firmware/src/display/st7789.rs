//! ST7789 IPS LCD Driver for LilyGO T-Display and T-Display-S3.

use super::ui::DisplayBuffer;
#[cfg(target_os = "espidf")]
use super::ui::{DISPLAY_HEIGHT, DISPLAY_WIDTH};
#[cfg(target_os = "espidf")]
use embedded_graphics::prelude::IntoStorage;
#[cfg(target_os = "espidf")]
use std::vec::Vec;

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

    /// Flushes the complete framebuffer to the ST7789 controller over SPI
    pub fn flush_framebuffer(&mut self, buffer: &DisplayBuffer) -> Result<(), &'static str> {
        if !self.is_initialized {
            return Err("Display not initialized");
        }

        #[cfg(target_os = "espidf")]
        unsafe {
            let width = DISPLAY_WIDTH as u16;
            let height = DISPLAY_HEIGHT as u16;

            let mut be_pixels = Vec::with_capacity(buffer.pixels.len());
            for p in &buffer.pixels {
                be_pixels.push((*p).into_storage().swap_bytes());
            }

            aegis_display_flush(
                0,
                0,
                width - 1,
                height - 1,
                be_pixels.as_ptr(),
                be_pixels.len() as u32,
            );
        }

        let _ = buffer;
        Ok(())
    }
}
