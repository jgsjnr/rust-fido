//! AegisKey S3 Unified Display Subsystem.
//!
//! Provides support for:
//! - LilyGO T-Display-S3 (170x320 IPS ST7789 Color Display)
//! - DevKitC-1 (WS2812 RGB LED synchronization + Serial Console UI mirror)
//!
//! Boards with an LCD enable `has-display`; headless boards (DevKitC-1)
//! build a stub `DisplayManager` with the same LED + screen-state contract.

#[cfg(feature = "has-display")]
pub mod st7789;
pub mod ui;

#[cfg(feature = "has-display")]
pub use st7789::{St7789Config, St7789Display};
#[cfg(feature = "has-display")]
pub use ui::{
    band_count, band_range, AegisUiRenderer, DisplayBand, DisplayBuffer, CLASSIC_BAND_HEIGHT,
    CLASSIC_HEIGHT, CLASSIC_WIDTH, DISPLAY_BAND_HEIGHT, DISPLAY_HEIGHT, DISPLAY_WIDTH,
};
pub use ui::{colors, UiScreen};

use crate::led::{Color, LedEffect, LedOutput, Ws2812Controller};

/// Synchronizes the WS2812 RGB LED effect with the active screen state.
///
/// Shared by the full and stub managers so headless boards keep the same
/// LED contract as LCD boards.
fn apply_screen_led_effect<L: LedOutput>(
    led_controller: &mut Option<Ws2812Controller<L>>,
    screen: &UiScreen,
) {
    if let Some(ref mut led) = led_controller {
        match screen {
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
}

/// Unified Display Manager coordinating LCD screen and WS2812 LED feedback
#[cfg(feature = "has-display")]
pub struct DisplayManager<L: LedOutput> {
    pub display: St7789Display,
    /// Buffer cheio so fora do classic (S3 cabe; classic usa banda de 10800B).
    #[cfg(not(feature = "board-ttgo-classic"))]
    pub buffer: DisplayBuffer,
    pub current_screen: UiScreen,
    pub led_controller: Option<Ws2812Controller<L>>,
    pub is_t_display: bool,
}

#[cfg(feature = "has-display")]
impl<L: LedOutput> DisplayManager<L> {
    pub fn new(led_controller: Option<Ws2812Controller<L>>) -> Self {
        #[cfg(any(feature = "board-t-display", feature = "board-ttgo-classic"))]
        let is_t_display = true;
        #[cfg(not(any(feature = "board-t-display", feature = "board-ttgo-classic")))]
        let is_t_display = false;

        Self {
            display: St7789Display::new(St7789Config::default()),
            #[cfg(not(feature = "board-ttgo-classic"))]
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
        apply_screen_led_effect(&mut self.led_controller, &screen);

        // 2+3. Render + flush (classic: bandado sem full 64800B; S3: cheio).
        #[cfg(feature = "board-ttgo-classic")]
        {
            if self.is_t_display {
                let _ = self.display.flush_screen_banded(&self.current_screen);
            }
        }
        #[cfg(not(feature = "board-ttgo-classic"))]
        {
            AegisUiRenderer::render(&self.current_screen, &mut self.buffer);
            if self.is_t_display {
                let _ = self.display.flush_framebuffer(&self.buffer);
            }
        }
    }

    /// Updates countdown timers and animation frames
    pub fn tick(&mut self, elapsed: core::time::Duration) {
        if let Some(ref mut led) = self.led_controller {
            let _ = led.update(elapsed);
        }
    }
}

/// Headless Display Manager (no LCD): same screen-state + LED contract.
///
/// DevKitC-1 has no display hardware (`is_t_display = false`); the stub
/// keeps `new` / `init_hardware` / `set_screen` / `tick` signatures so all
/// call sites build unchanged, minus the ~106 KiB framebuffer and the
/// `embedded-graphics` dependency.
#[cfg(not(feature = "has-display"))]
pub struct DisplayManager<L: LedOutput> {
    pub current_screen: UiScreen,
    pub led_controller: Option<Ws2812Controller<L>>,
    pub is_t_display: bool,
}

#[cfg(not(feature = "has-display"))]
impl<L: LedOutput> DisplayManager<L> {
    pub fn new(led_controller: Option<Ws2812Controller<L>>) -> Self {
        Self {
            current_screen: UiScreen::IdleStandby {
                status_text: "Inicializando...".into(),
            },
            led_controller,
            is_t_display: false,
        }
    }

    /// No display hardware to initialize; always succeeds.
    pub fn init_hardware(&mut self) -> Result<(), &'static str> {
        Ok(())
    }

    /// Switches the active screen and synchronizes the WS2812 RGB LED
    pub fn set_screen(&mut self, screen: UiScreen) {
        self.current_screen = screen.clone();

        // Synchronize WS2812 RGB LED effect matching screen state
        apply_screen_led_effect(&mut self.led_controller, &screen);
    }

    /// Updates countdown timers and animation frames
    pub fn tick(&mut self, elapsed: core::time::Duration) {
        if let Some(ref mut led) = self.led_controller {
            let _ = led.update(elapsed);
        }
    }
}
