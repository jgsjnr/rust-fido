//! AegisKey S3 Unified Display Subsystem.
//!
//! Provides support for:
//! - LilyGO T-Display-S3 (170x320 IPS ST7789 Color Display)
//! - DevKitC-1 (WS2812 RGB LED synchronization + Serial Console UI mirror)

pub mod st7789;
pub mod ui;

pub use st7789::{St7789Config, St7789Display};
pub use ui::{colors, AegisUiRenderer, DisplayBuffer, UiScreen, DISPLAY_HEIGHT, DISPLAY_WIDTH};

use crate::led::{Color, LedEffect, LedOutput, Ws2812Controller};

/// Unified Display Manager coordinating LCD screen and WS2812 LED feedback
pub struct DisplayManager<L: LedOutput> {
    pub display: St7789Display,
    pub buffer: DisplayBuffer,
    pub current_screen: UiScreen,
    pub led_controller: Option<Ws2812Controller<L>>,
    pub is_t_display: bool,
}

impl<L: LedOutput> DisplayManager<L> {
    pub fn new(led_controller: Option<Ws2812Controller<L>>) -> Self {
        #[cfg(any(feature = "board-t-display", feature = "board-ttgo-classic"))]
        let is_t_display = true;
        #[cfg(not(any(feature = "board-t-display", feature = "board-ttgo-classic")))]
        let is_t_display = false;

        Self {
            display: St7789Display::new(St7789Config::default()),
            buffer: DisplayBuffer::new(),
            current_screen: UiScreen::IdleStandby {
                status_text: "Inicializando...".into(),
            },
            led_controller,
            is_t_display,
        }
    }

    /// Initializes hardware peripherals for the display subsystem
    pub fn init_hardware(&mut self) -> Result<(), &'static str> {
        if self.is_t_display {
            self.display.init_hardware()?;
        }
        Ok(())
    }

    /// Switches the active screen and synchronizes the WS2812 RGB LED
    pub fn set_screen(&mut self, screen: UiScreen) {
        self.current_screen = screen.clone();

        // 1. Synchronize WS2812 RGB LED effect matching screen state
        if let Some(ref mut led) = self.led_controller {
            match &screen {
                UiScreen::BootSplash { .. } => {
                    led.set_effect(LedEffect::RainbowCycle { speed_ms: 1000 });
                }
                UiScreen::IdleStandby { .. } => {
                    led.set_effect(LedEffect::Breathing {
                        color: Color::CYAN,
                        period_ms: 2000,
                    });
                }
                UiScreen::UserPresencePrompt { .. } => {
                    led.set_effect(LedEffect::PromptTouch);
                }
                UiScreen::Success { .. } => {
                    led.set_effect(LedEffect::AuthSuccessPulse);
                }
                UiScreen::Error { .. } => {
                    led.set_effect(LedEffect::ErrorFlash);
                }
                UiScreen::TotpCode { .. } => {
                    led.set_effect(LedEffect::Solid(Color::BLUE));
                }
            }
        }

        // 2. Render UI to FrameBuffer
        AegisUiRenderer::render(&self.current_screen, &mut self.buffer);

        // 3. Flush to ST7789 if LilyGO T-Display-S3 is enabled
        if self.is_t_display {
            let _ = self.display.flush_framebuffer(&self.buffer);
        }
    }

    /// Updates countdown timers and animation frames
    pub fn tick(&mut self, elapsed: core::time::Duration) {
        if let Some(ref mut led) = self.led_controller {
            let _ = led.update(elapsed);
        }
    }
}
