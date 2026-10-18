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
    pub const YELLOW: Color = Color { r: 255, g: 220, b: 0 };
    pub const AMBER: Color = Color { r: 255, g: 140, b: 0 };
    pub const ORANGE: Color = Color { r: 255, g: 70, b: 0 };
    pub const PURPLE: Color = Color { r: 180, g: 0, b: 255 };
    pub const WHITE: Color = Color { r: 255, g: 255, b: 255 };

    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Scales the color by a brightness factor (0..255).
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

    /// Generates a color from an HSV color wheel hue (0..255).
    pub fn from_hue(hue: u8) -> Self {
        let h = hue as u16 * 6; // 0..1530
        let x = (h % 255) as u8;
        match h / 255 {
            0 => Color::new(255, x, 0),
            1 => Color::new(255 - x, 255, 0),
            2 => Color::new(0, 255, x),
            3 => Color::new(0, 255 - x, 255),
            4 => Color::new(x, 0, 255),
            _ => Color::new(255, 0, 255 - x),
        }
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
    /// Waiting for user presence touch on GPIO 0 (rapid amber/yellow pulsing)
    PromptTouch,
    /// Single quick green pulse on successful authentication / credential registration
    AuthSuccessPulse,
    /// Rapid red flash on error, bad PIN, or touch timeout
    ErrorFlash,
    /// White strobe (CTAPHID_WINK)
    Wink,
    /// Rainbow color cycle during boot self-test
    RainbowCycle { speed_ms: u32 },
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

    /// Gets current active visual effect.
    pub fn current_effect(&self) -> LedEffect {
        self.current_effect
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
                let p = if period_ms == 0 { 2000 } else { period_ms };
                let half_period = p / 2;
                let phase = elapsed_ms % p;
                let factor = if phase < half_period {
                    (phase * 255) / half_period
                } else {
                    ((p - phase) * 255) / half_period
                };

                // Keep minimum brightness at 12/255 for smooth ambient glow
                let brightness = (12 + (factor * 243) / 255) as u8;
                let scaled = color.scale_brightness(brightness);
                self.output.write_color(scaled)?;
            }
            LedEffect::PromptTouch => {
                // Pulsing Amber (800ms cycle) inviting user to touch the BOOT button
                let half_period = 400;
                let phase = elapsed_ms % 800;
                let factor = if phase < half_period {
                    (phase * 255) / half_period
                } else {
                    ((800 - phase) * 255) / half_period
                };
                let brightness = (30 + (factor * 225) / 255) as u8;
                let scaled = Color::AMBER.scale_brightness(brightness);
                self.output.write_color(scaled)?;
            }
            LedEffect::AuthSuccessPulse => {
                // Bright green pulse for 500ms then smooth fade
                let color = if elapsed_ms < 500 {
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
            LedEffect::RainbowCycle { speed_ms } => {
                let s = if speed_ms == 0 { 3000 } else { speed_ms };
                let hue = ((elapsed_ms % s) * 255 / s) as u8;
                let color = Color::from_hue(hue).scale_brightness(160);
                self.output.write_color(color)?;
            }
        }

        Ok(())
    }
}

/// Real hardware driver for WS2812 RGB LED on ESP32-S3 (GPIO 48).
pub struct EspWs2812Output {
    gpio: u32,
    initialized: bool,
}

impl EspWs2812Output {
    pub fn new(gpio: u32) -> Self {
        Self {
            gpio,
            initialized: false,
        }
    }

    pub fn init_hardware(&mut self) {
        #[cfg(target_os = "espidf")]
        unsafe {
            // Configure GPIO pin as output with pullup/pulldown disabled
            let conf = esp_idf_sys::gpio_config_t {
                pin_bit_mask: 1u64 << self.gpio,
                mode: esp_idf_sys::gpio_mode_t_GPIO_MODE_OUTPUT,
                pull_up_en: esp_idf_sys::gpio_pullup_t_GPIO_PULLUP_DISABLE,
                pull_down_en: esp_idf_sys::gpio_pulldown_t_GPIO_PULLDOWN_DISABLE,
                intr_type: esp_idf_sys::gpio_int_type_t_GPIO_INTR_DISABLE,
            };
            esp_idf_sys::gpio_config(&conf);

            // Explicitly set output enable register for GPIO Bank 1 (GPIO 32-48)
            if self.gpio >= 32 {
                const GPIO_ENABLE1_W1TS: *mut u32 = 0x6000_4030 as *mut u32;
                core::ptr::write_volatile(GPIO_ENABLE1_W1TS, 1 << (self.gpio - 32));
            } else {
                const GPIO_ENABLE_W1TS: *mut u32 = 0x6000_4024 as *mut u32;
                core::ptr::write_volatile(GPIO_ENABLE_W1TS, 1 << self.gpio);
            }

            esp_idf_sys::gpio_set_level(self.gpio as i32, 0);
        }
        self.initialized = true;
    }
}

impl LedOutput for EspWs2812Output {
    fn write_color(&mut self, color: Color) -> Result<(), &'static str> {
        if !self.initialized {
            self.init_hardware();
        }

        #[cfg(target_os = "espidf")]
        unsafe {
            let grb = color.to_grb_bytes();
            
            // GPIO 48 register addresses on ESP32-S3 (bank 1, bit 16):
            const GPIO_OUT1_W1TS: *mut u32 = 0x6000_4014 as *mut u32;
            const GPIO_OUT1_W1TC: *mut u32 = 0x6000_4018 as *mut u32;
            const PIN_MASK: u32 = 1 << 16; // 48 - 32 = 16

            let freq_mhz: u32 = esp_idf_sys::esp_rom_get_cpu_ticks_per_us();
            let freq_mhz: u32 = if freq_mhz > 0 { freq_mhz } else { 160 };

            // Calibrated WS2812 cycle counts for ESP32-S3:
            // Register writes over the APB bus to GPIO_OUT1_W1TS take ~25-28 CPU cycles.
            // Bit 0: Target wire HIGH = ~350ns (56 cycles @ 160MHz).
            //        Subtracting 28 cycles overhead -> delay = 28 cycles (~175ns).
            // Bit 1: Target wire HIGH = ~700ns (112 cycles @ 160MHz).
            //        Subtracting 28 cycles overhead -> delay = 84 cycles (~525ns).
            let t0h_cycles: u32 = (175 * freq_mhz) / 1000;
            let t0_tot_cycles: u32 = (1200 * freq_mhz) / 1000;
            let t1h_cycles: u32 = (525 * freq_mhz) / 1000;
            let t1_tot_cycles: u32 = (1250 * freq_mhz) / 1000;

            #[inline(always)]
            unsafe fn get_ccount() -> u32 {
                esp_idf_sys::xthal_get_ccount() as u32
            }

            #[inline(always)]
            unsafe fn delay_cycles(cycles: u32) {
                let start = get_ccount();
                while get_ccount().wrapping_sub(start) < cycles {
                    core::hint::spin_loop();
                }
            }

            // Suspend FreeRTOS task switching during the 30us pulse train
            esp_idf_sys::vTaskSuspendAll();

            for &byte in &grb {
                for bit_idx in (0..8).rev() {
                    let bit = (byte >> bit_idx) & 1;
                    if bit == 1 {
                        core::ptr::write_volatile(GPIO_OUT1_W1TS, PIN_MASK);
                        delay_cycles(t1h_cycles);
                        core::ptr::write_volatile(GPIO_OUT1_W1TC, PIN_MASK);
                        delay_cycles(t1_tot_cycles.saturating_sub(t1h_cycles));
                    } else {
                        core::ptr::write_volatile(GPIO_OUT1_W1TS, PIN_MASK);
                        delay_cycles(t0h_cycles);
                        core::ptr::write_volatile(GPIO_OUT1_W1TC, PIN_MASK);
                        delay_cycles(t0_tot_cycles.saturating_sub(t0h_cycles));
                    }
                }
            }

            // Hold LOW for reset time (> 50 us -> 80 us)
            core::ptr::write_volatile(GPIO_OUT1_W1TC, PIN_MASK);
            delay_cycles(80 * freq_mhz);

            esp_idf_sys::xTaskResumeAll();
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
