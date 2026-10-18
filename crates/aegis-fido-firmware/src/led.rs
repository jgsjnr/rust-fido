//! RGB LED Driver (WS2812 on GPIO 48) with Visual Feedback Effects.
//!
//! ESP32-S3 boards (like ESP32-S3-DevKitC-1) integrate an addressable WS2812 RGB LED on GPIO 48.
//! WS2812 protocol transmits 24-bit GRB data (Green-Red-Blue) at 800 kHz.
//! 100% Native Rust implementation.

use core::time::Duration;

pub const WS2812_GPIO_PIN: u32 = 48;

/// Standard RGB color representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    pub const BLACK: Color = Color { r: 0, g: 0, b: 0 };
    pub const RED: Color = Color { r: 255, g: 0, b: 0 };
    pub const GREEN: Color = Color { r: 0, g: 255, b: 0 };
    pub const BLUE: Color = Color { r: 0, g: 0, b: 255 };
    pub const CYAN: Color = Color { r: 0, g: 255, b: 255 };
    pub const MAGENTA: Color = Color { r: 255, g: 0, b: 255 };
    pub const YELLOW: Color = Color { r: 255, g: 255, b: 0 };
    pub const WHITE: Color = Color { r: 255, g: 255, b: 255 };
    pub const AMBER: Color = Color { r: 255, g: 128, b: 0 };

    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Scales the color by a brightness factor (0.0 to 1.0 represented as 0..255).
    pub fn scale_brightness(&self, scale: u8) -> Self {
        let r = ((self.r as u16 * scale as u16) / 255) as u8;
        let g = ((self.g as u16 * scale as u16) / 255) as u8;
        let b = ((self.b as u16 * scale as u16) / 255) as u8;
        Self { r, g, b }
    }

    /// Converts to WS2812 native wire format (Green, Red, Blue).
    pub fn to_grb_bytes(&self) -> [u8; 3] {
        [self.g, self.r, self.b]
    }
}

/// Visual feedback states for the authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedEffect {
    /// LED turned off
    Off,
    /// Solid static color
    Solid(Color),
    /// Breathing effect (pulsing brightness) in specified color
    Breathing { color: Color, period_ms: u32 },
    /// Single quick pulse (e.g. on successful auth)
    AuthSuccessPulse,
    /// Rapid red flash (e.g. on error or touch timeout)
    ErrorFlash,
    /// Rapid white flash (CTAPHID_WINK)
    Wink,
}

/// Trait for the physical or simulated LED output.
pub trait LedOutput {
    fn write_color(&mut self, color: Color) -> Result<(), &'static str>;
}

/// Controller managing LED effects and animations.
pub struct Ws2812Controller<O: LedOutput> {
    output: O,
    current_effect: LedEffect,
}

impl<O: LedOutput> Ws2812Controller<O> {
    pub fn new(output: O) -> Self {
        Self {
            output,
            current_effect: LedEffect::Off,
        }
    }

    /// Sets the active visual effect.
    pub fn set_effect(&mut self, effect: LedEffect) {
        self.current_effect = effect;
    }

    /// Advances the animation by `elapsed` duration and updates the physical LED.
    pub fn update(&mut self, elapsed: Duration) -> Result<(), &'static str> {
        let elapsed_ms = elapsed.as_millis() as u32;

        match self.current_effect {
            LedEffect::Off => {
                self.output.write_color(Color::BLACK)?;
            }
            LedEffect::Solid(color) => {
                self.output.write_color(color)?;
            }
            LedEffect::Breathing { color, period_ms } => {
                // Compute triangular breathing curve (0 -> 255 -> 0)
                let half_period = period_ms / 2;
                let phase = elapsed_ms % period_ms;
                let factor = if phase < half_period {
                    (phase * 255) / half_period
                } else {
                    ((period_ms - phase) * 255) / half_period
                };

                // Keep minimum brightness at 15/255 so LED doesn't fully turn off
                let brightness = (15 + (factor * 240) / 255) as u8;
                let scaled = color.scale_brightness(brightness);
                self.output.write_color(scaled)?;
            }
            LedEffect::AuthSuccessPulse => {
                // Bright green pulse for 400ms then off
                let color = if elapsed_ms < 400 {
                    Color::GREEN
                } else {
                    Color::BLACK
                };
                self.output.write_color(color)?;
            }
            LedEffect::ErrorFlash => {
                // 3 rapid red flashes (100ms on, 100ms off)
                let phase = elapsed_ms % 200;
                let color = if phase < 100 && elapsed_ms < 600 {
                    Color::RED
                } else {
                    Color::BLACK
                };
                self.output.write_color(color)?;
            }
            LedEffect::Wink => {
                // 5 rapid white flashes (80ms on, 80ms off)
                let phase = elapsed_ms % 160;
                let color = if phase < 80 && elapsed_ms < 800 {
                    Color::WHITE
                } else {
                    Color::BLACK
                };
                self.output.write_color(color)?;
            }
        }

        Ok(())
    }
}

/// Simulated LED output for unit testing.
#[derive(Debug, Clone, Default)]
pub struct MockLedOutput {
    pub last_color: Color,
    pub write_count: usize,
}

impl MockLedOutput {
    pub fn new() -> Self {
        Self {
            last_color: Color::BLACK,
            write_count: 0,
        }
    }
}

impl LedOutput for MockLedOutput {
    fn write_color(&mut self, color: Color) -> Result<(), &'static str> {
        self.last_color = color;
        self.write_count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_grb_conversion() {
        let c = Color::new(0x12, 0x34, 0x56);
        assert_eq!(c.to_grb_bytes(), [0x34, 0x12, 0x56]); // Green, Red, Blue
    }

    #[test]
    fn test_color_scaling() {
        let white = Color::WHITE;
        let dim = white.scale_brightness(128);
        assert_eq!(dim.r, 128);
        assert_eq!(dim.g, 128);
        assert_eq!(dim.b, 128);
    }

    #[test]
    fn test_breathing_effect() {
        let mock = MockLedOutput::new();
        let mut ctrl = Ws2812Controller::new(mock);
        ctrl.set_effect(LedEffect::Breathing {
            color: Color::BLUE,
            period_ms: 1000,
        });

        // Test at start
        ctrl.update(Duration::from_millis(0)).unwrap();
        assert_eq!(ctrl.output.last_color.b > 0, true);
        assert_eq!(ctrl.output.last_color.r, 0);

        // Test at peak (500ms)
        ctrl.update(Duration::from_millis(500)).unwrap();
        assert_eq!(ctrl.output.last_color.b, 255);
    }

    #[test]
    fn test_auth_success_pulse() {
        let mock = MockLedOutput::new();
        let mut ctrl = Ws2812Controller::new(mock);
        ctrl.set_effect(LedEffect::AuthSuccessPulse);

        ctrl.update(Duration::from_millis(100)).unwrap();
        assert_eq!(ctrl.output.last_color, Color::GREEN);

        ctrl.update(Duration::from_millis(500)).unwrap();
        assert_eq!(ctrl.output.last_color, Color::BLACK);
    }
}
