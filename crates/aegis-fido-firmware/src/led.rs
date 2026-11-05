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
    pub const CYAN: Color = Color {
        r: 0,
        g: 255,
        b: 255,
    };
    pub const MAGENTA: Color = Color {
        r: 255,
        g: 0,
        b: 255,
    };
    pub const YELLOW: Color = Color {
        r: 255,
        g: 220,
        b: 0,
    };
    pub const AMBER: Color = Color {
        r: 255,
        g: 140,
        b: 0,
    };
    pub const ORANGE: Color = Color {
        r: 255,
        g: 70,
        b: 0,
    };
    pub const PURPLE: Color = Color {
        r: 180,
        g: 0,
        b: 255,
    };
    pub const WHITE: Color = Color {
        r: 255,
        g: 255,
        b: 255,
    };
    pub const SECURE_GUARD_UNPROVISIONED: Color = Color { r: 0, g: 40, b: 60 };
    pub const SECURE_GUARD_LOCKED: Color = Color { r: 60, g: 25, b: 0 };
    pub const SECURE_GUARD_UNLOCKED: Color = Color { r: 0, g: 60, b: 15 };

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

/// OTA reception progress color for the single WS2812 pixel.
///
/// Maps `0..=100` to a red-to-green hue ramp (`0` = red, `100` = green) via
/// the existing [`Color::from_hue`] wheel (hue `0..=85`). Pure: no
/// RMT/hardware touch — the main loop feeds the result to
/// [`Ws2812Controller`] with [`LedEffect::Solid`] after each `BEGIN`/`CHUNK`
/// (single pixel: hue carries the "bar"). Inputs above `100` clamp.
pub fn ota_progress_color(progress: u8) -> Color {
    let p = progress.min(100);
    Color::from_hue(((p as u16 * 85) / 100) as u8)
}

/// LED effect for OTA reception progress (`BEGIN`/`CHUNK` path).
///
/// Below `100` yields [`LedEffect::Solid`] in [`ota_progress_color`];
/// `100` yields [`LedEffect::AuthSuccessPulse`] (visual confirmation of a
/// fully received image, before verify/commit). Pure mapping — the caller
/// applies it with `Ws2812Controller::set_effect`; no hardware touch here.
pub fn ota_progress_effect(progress: u8) -> LedEffect {
    if progress >= 100 {
        LedEffect::AuthSuccessPulse
    } else {
        LedEffect::Solid(ota_progress_color(progress))
    }
}

/// Distinct LED pattern for an OTA reception error (failed/empty/out-of-order
/// chunk, overflow, verify deny): rapid red flash, visually distinct from the
/// progress ramp and from the `100%` confirmation pulse.
pub fn ota_error_effect() -> LedEffect {
    LedEffect::ErrorFlash
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
    rendered_effect: LedEffect,
    effect_start_ms: u64,
}

impl<O: LedOutput> Ws2812Controller<O> {
    pub fn new(output: O) -> Self {
        Self {
            output,
            current_effect: LedEffect::Off,
            rendered_effect: LedEffect::Off,
            effect_start_ms: 0,
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
        // One-shot effects run on time-since-set: the main loop feeds absolute
        // uptime, so without this anchor pulses/flashes die ~500ms after boot
        // (IRL the LED would stick to black instead of pulsing/flashing).
        let now_ms = elapsed.as_millis() as u64;
        if self.rendered_effect != self.current_effect {
            self.rendered_effect = self.current_effect;
            self.effect_start_ms = now_ms;
        }
        let elapsed_ms = now_ms.saturating_sub(self.effect_start_ms) as u32;

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
                // Rapid blue/white flash (150ms Blue, 150ms White) inviting user to touch BOOT button
                let phase = elapsed_ms % 300;
                let color = if phase < 150 {
                    Color::new(0, 80, 255)
                } else {
                    Color::new(220, 220, 255)
                };
                self.output.write_color(color)?;
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

/// RMT peripheral clock resolution for the WS2812 driver.
///
/// 10 MHz => 100 ns per RMT tick. Every WS2812 phase below is an exact
/// multiple of one tick, so no rounding error is introduced.
pub const WS2812_RMT_RESOLUTION_HZ: u32 = 10_000_000;
/// HIGH phase of a `0` bit, in RMT ticks (400 ns).
pub const WS2812_T0H_TICKS: u16 = 4;
/// LOW phase of a `0` bit, in RMT ticks (1000 ns; 1400 ns period).
pub const WS2812_T0L_TICKS: u16 = 10;
/// HIGH phase of a `1` bit, in RMT ticks (800 ns).
pub const WS2812_T1H_TICKS: u16 = 8;
/// LOW phase of a `1` bit, in RMT ticks (600 ns; 1400 ns period).
pub const WS2812_T1L_TICKS: u16 = 6;

/// Packs one RMT symbol into its 32-bit wire value.
///
/// Layout (see `rmt_symbol_word_t`): `duration0[14:0] | level0[15] |
/// duration1[30:16] | level1[31]`. WS2812 symbols idle LOW, so `level0 = 1`
/// and `level1 = 0`.
pub fn rmt_symbol_word_value(hi: u16, lo: u16) -> u32 {
    (hi as u32) | (1u32 << 15) | ((lo as u32) << 16)
}

/// Encodes 3 GRB bytes into 24 RMT `(high_ticks, low_ticks)` symbols.
///
/// Bits travel MSB-first within each byte, in GRB order, matching what the
/// RMT bytes encoder (`msb_first = 1`) emits on the wire.
pub fn encode_grb_to_rmt_ticks(grb: [u8; 3]) -> [(u16, u16); 24] {
    let t0 = (WS2812_T0H_TICKS, WS2812_T0L_TICKS);
    let t1 = (WS2812_T1H_TICKS, WS2812_T1L_TICKS);
    let mut out = [t0; 24];
    for (i, &byte) in grb.iter().enumerate() {
        for bit in 0..8 {
            let is_one = (byte >> (7 - bit)) & 1 == 1;
            out[i * 8 + bit] = if is_one { t1 } else { t0 };
        }
    }
    out
}

/// Real hardware driver for WS2812 RGB LED on ESP32-S3 (GPIO 48).
/// Raw RMT driver handles owned by [`EspWs2812Output`].
///
/// The RMT TX channel owns the GPIO pin for the life of the process. Handles
/// are only touched through `&mut self` from the single-owner LED task, so no
/// sharing or teardown race is possible.
#[cfg(target_os = "espidf")]
#[derive(Debug, Clone, Copy)]
struct RmtHandles {
    channel: esp_idf_sys::rmt_channel_handle_t,
    encoder: esp_idf_sys::rmt_encoder_handle_t,
}

/// Real hardware driver for WS2812 RGB LED on ESP32-S3 (GPIO 48).
///
/// Bits are clocked by the RMT peripheral (jitter-free); the CPU only queues
/// the GRB payload and spins 80 us for the reset window.
pub struct EspWs2812Output {
    #[cfg_attr(not(target_os = "espidf"), allow(dead_code))]
    gpio: u32,
    #[cfg(target_os = "espidf")]
    rmt: Option<RmtHandles>,
    initialized: bool,
}

impl EspWs2812Output {
    pub fn new(gpio: u32) -> Self {
        Self {
            gpio,
            #[cfg(target_os = "espidf")]
            rmt: None,
            initialized: false,
        }
    }

    pub fn init_hardware(&mut self) {
        #[cfg(target_os = "espidf")]
        {
            // Best-effort eager RMT setup; `write_color` retries lazily.
            let _ = self.setup_rmt();
        }
        self.initialized = true;
        let _ = self.write_color(Color::SECURE_GUARD_UNPROVISIONED);
    }

    /// Creates and enables the RMT TX channel plus bytes encoder (idempotent).
    ///
    /// Each failure step undoes the previous ones, so a later retry starts
    /// from a clean slate. The RMT channel owns the GPIO pin from here on:
    /// no GPIO bit-bang pokes are used anywhere in this driver.
    #[cfg(target_os = "espidf")]
    fn setup_rmt(&mut self) -> Result<(), &'static str> {
        if self.rmt.is_some() {
            return Ok(());
        }
        // SAFETY: exclusive `&mut self` access from the single-owner LED task.
        // Config structs are zero-initialised via `Default` then fully
        // populated with valid values before each driver call; partially
        // created handles are deleted on every failure path below.
        unsafe {
            let mut channel: esp_idf_sys::rmt_channel_handle_t = core::ptr::null_mut();
            let mut tx_config = esp_idf_sys::rmt_tx_channel_config_t::default();
            tx_config.gpio_num = self.gpio as esp_idf_sys::gpio_num_t;
            tx_config.clk_src = esp_idf_sys::soc_periph_rmt_clk_src_t_RMT_CLK_SRC_DEFAULT;
            tx_config.resolution_hz = WS2812_RMT_RESOLUTION_HZ;
            tx_config.mem_block_symbols = 64;
            tx_config.trans_queue_depth = 4;
            if esp_idf_sys::rmt_new_tx_channel(&tx_config, &mut channel) != esp_idf_sys::ESP_OK
                || channel.is_null()
            {
                return Err("ws2812: rmt tx channel");
            }

            let mut encoder: esp_idf_sys::rmt_encoder_handle_t = core::ptr::null_mut();
            let mut enc_config = esp_idf_sys::rmt_bytes_encoder_config_t::default();
            enc_config.bit0 = esp_idf_sys::rmt_symbol_word_t {
                val: rmt_symbol_word_value(WS2812_T0H_TICKS, WS2812_T0L_TICKS),
            };
            enc_config.bit1 = esp_idf_sys::rmt_symbol_word_t {
                val: rmt_symbol_word_value(WS2812_T1H_TICKS, WS2812_T1L_TICKS),
            };
            enc_config.flags.set_msb_first(1);
            if esp_idf_sys::rmt_new_bytes_encoder(&enc_config, &mut encoder) != esp_idf_sys::ESP_OK
                || encoder.is_null()
            {
                esp_idf_sys::rmt_del_channel(channel);
                return Err("ws2812: rmt bytes encoder");
            }

            if esp_idf_sys::rmt_enable(channel) != esp_idf_sys::ESP_OK {
                esp_idf_sys::rmt_del_encoder(encoder);
                esp_idf_sys::rmt_del_channel(channel);
                return Err("ws2812: rmt enable");
            }

            self.rmt = Some(RmtHandles { channel, encoder });
            Ok(())
        }
    }
}

impl LedOutput for EspWs2812Output {
    fn write_color(&mut self, color: Color) -> Result<(), &'static str> {
        #[cfg(not(target_os = "espidf"))]
        let _ = color;
        if !self.initialized {
            self.init_hardware();
        }

        // SAFETY: handles in `self.rmt` are owned exclusively by `self` and
        // only touched through `&mut self` from the single-owner LED task
        // (ESP-IDF build only). The GRB payload is a stack local that outlives
        // `rmt_transmit` + `rmt_tx_wait_all_done`, satisfying the driver's
        // validity requirement; the trailing 80 us reset spin only reads the
        // cycle counter and masks no interrupt.
        #[cfg(target_os = "espidf")]
        unsafe {
            if self.rmt.is_none() {
                self.setup_rmt()?;
            }
            let handles = self.rmt.ok_or("ws2812: rmt unavailable")?;
            let grb = color.to_grb_bytes();
            let tx_config = esp_idf_sys::rmt_transmit_config_t {
                loop_count: 0,
                flags: Default::default(),
            };
            if esp_idf_sys::rmt_transmit(
                handles.channel,
                handles.encoder,
                grb.as_ptr() as *const core::ffi::c_void,
                grb.len(),
                &tx_config,
            ) != esp_idf_sys::ESP_OK
            {
                return Err("ws2812: rmt transmit");
            }
            if esp_idf_sys::rmt_tx_wait_all_done(handles.channel, 100) != esp_idf_sys::ESP_OK {
                return Err("ws2812: rmt wait done");
            }
            // WS2812 reset window (> 50 us): busy-spin 80 us on the cycle
            // counter. No scheduler suspend or interrupt masking is needed:
            // the RMT peripheral already clocked the bits out jitter-free.
            let ticks_per_us = esp_idf_sys::esp_rom_get_cpu_ticks_per_us();
            let ticks_per_us = if ticks_per_us > 0 { ticks_per_us } else { 160 };
            let start = esp_idf_sys::xthal_get_ccount();
            let wait = 80u32.saturating_mul(ticks_per_us);
            while esp_idf_sys::xthal_get_ccount().wrapping_sub(start) < wait {
                core::hint::spin_loop();
            }
        }

        Ok(())
    }
}

/// CI-GREP: MOCK-ONLY-IN-TEST — test/host-only; nem compila no device.
/// Simulated LED output for unit testing and host-side development.
#[cfg(any(test, not(target_os = "espidf")))]
#[derive(Debug, Clone, Default)]
pub struct MockLedOutput {
    pub last_color: Color,
    pub write_count: usize,
}

#[cfg(any(test, not(target_os = "espidf")))]
impl MockLedOutput {
    pub fn new() -> Self {
        Self {
            last_color: Color::BLACK,
            write_count: 0,
        }
    }
}

#[cfg(any(test, not(target_os = "espidf")))]
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
        assert!(ctrl.output.last_color.b > 0);
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

        ctrl.update(Duration::from_millis(600)).unwrap();
        assert_eq!(ctrl.output.last_color, Color::BLACK);
    }

    #[test]
    fn rmt_symbol_encoding_matches_ws2812_spec() {
        // 10 MHz RMT resolution => 100 ns per tick.
        const NS_PER_TICK: u32 = 100;
        let t0h_ns = u32::from(WS2812_T0H_TICKS) * NS_PER_TICK;
        let t1h_ns = u32::from(WS2812_T1H_TICKS) * NS_PER_TICK;
        // Datasheet windows (WS2812/WS2812B): T0H 200-500 ns, T1H 550-850 ns.
        assert!(
            (200..=500).contains(&t0h_ns),
            "T0H {t0h_ns}ns outside window"
        );
        assert!(
            (550..=850).contains(&t1h_ns),
            "T1H {t1h_ns}ns outside window"
        );
        // Both symbols share a 1400 ns period.
        let period0 = (u32::from(WS2812_T0H_TICKS) + u32::from(WS2812_T0L_TICKS)) * NS_PER_TICK;
        let period1 = (u32::from(WS2812_T1H_TICKS) + u32::from(WS2812_T1L_TICKS)) * NS_PER_TICK;
        assert_eq!(period0, 1400);
        assert_eq!(period1, 1400);

        // RED (255, 0, 0) travels as GRB bytes [0, 255, 0]: 8x T0, 8x T1, 8x T0.
        let t0 = (WS2812_T0H_TICKS, WS2812_T0L_TICKS);
        let t1 = (WS2812_T1H_TICKS, WS2812_T1L_TICKS);
        let red = encode_grb_to_rmt_ticks(Color::RED.to_grb_bytes());
        assert!(
            red[..8].iter().all(|&s| s == t0),
            "green byte must be all T0"
        );
        assert!(
            red[8..16].iter().all(|&s| s == t1),
            "red byte must be all T1"
        );
        assert!(
            red[16..].iter().all(|&s| s == t0),
            "blue byte must be all T0"
        );

        // 0xA5 = 0b1010_0101, MSB-first.
        let a5 = encode_grb_to_rmt_ticks([0xA5, 0x00, 0x00]);
        assert_eq!(&a5[..8], &[t1, t0, t1, t0, t0, t1, t0, t1]);

        // Word layout: duration0[14:0] | level0[15] | duration1[30:16] | level1[31].
        let word = rmt_symbol_word_value(WS2812_T1H_TICKS, WS2812_T1L_TICKS);
        assert_eq!(word & 0x7FFF, u32::from(WS2812_T1H_TICKS));
        assert_eq!((word >> 15) & 1, 1);
        assert_eq!((word >> 16) & 0x7FFF, u32::from(WS2812_T1L_TICKS));
        assert_eq!((word >> 31) & 1, 0);
    }

    #[test]
    fn ota_progress_color_ramps_red_to_green() {
        assert_eq!(ota_progress_color(0), Color::RED);
        assert_eq!(ota_progress_color(100), Color::GREEN);
        // Clamp defensivo: >100 comporta-se como 100.
        assert_eq!(ota_progress_color(255), Color::GREEN);
        // Rampa monotona: vermelho cai, verde sobe (vermelho puro -> verde puro).
        let mut prev_r = u8::MAX;
        let mut prev_g = 0u8;
        for p in (0..=100).step_by(10) {
            let c = ota_progress_color(p);
            assert!(c.r <= prev_r, "r deve cair em p={p}");
            assert!(c.g >= prev_g, "g deve subir em p={p}");
            prev_r = c.r;
            prev_g = c.g;
        }
    }

    #[test]
    fn ota_progress_effect_confirms_at_hundred_and_errors_distinct() {
        // Progresso parcial = cor solida do progresso.
        assert_eq!(
            ota_progress_effect(0),
            LedEffect::Solid(ota_progress_color(0))
        );
        assert_eq!(
            ota_progress_effect(57),
            LedEffect::Solid(ota_progress_color(57))
        );
        // 100% = confirmacao visual (pulso verde), nao solido.
        assert_eq!(ota_progress_effect(100), LedEffect::AuthSuccessPulse);
        assert_eq!(ota_progress_effect(200), LedEffect::AuthSuccessPulse);
        // Erro = padrao distinto (flash vermelho), diferente de qualquer
        // efeito de progresso parcial ou do pulso de 100%.
        assert_eq!(ota_error_effect(), LedEffect::ErrorFlash);
        assert_ne!(ota_error_effect(), ota_progress_effect(100));
        assert_ne!(ota_error_effect(), ota_progress_effect(0));
    }

    #[test]
    fn ota_progress_drives_controller_solid_then_pulse() {
        let mock = MockLedOutput::new();
        let mut ctrl = Ws2812Controller::new(mock);
        ctrl.set_effect(ota_progress_effect(0));
        ctrl.update(Duration::from_millis(0)).unwrap();
        assert_eq!(ctrl.output.last_color, ota_progress_color(0));
        ctrl.set_effect(ota_progress_effect(100));
        ctrl.update(Duration::from_millis(10_000)).unwrap();
        assert_eq!(ctrl.output.last_color, Color::GREEN);
    }

    #[test]
    fn oneshot_effects_use_time_since_set() {
        let mock = MockLedOutput::new();
        let mut ctrl = Ws2812Controller::new(mock);
        ctrl.set_effect(LedEffect::AuthSuccessPulse);

        // Far past boot: the pulse still shows green, then fades on its own clock.
        ctrl.update(Duration::from_millis(100_000)).unwrap();
        assert_eq!(ctrl.output.last_color, Color::GREEN);
        ctrl.update(Duration::from_millis(100_400)).unwrap();
        assert_eq!(ctrl.output.last_color, Color::GREEN);
        ctrl.update(Duration::from_millis(100_600)).unwrap();
        assert_eq!(ctrl.output.last_color, Color::BLACK);

        // Switching effect restarts the clock: error flashes red again.
        ctrl.set_effect(LedEffect::ErrorFlash);
        ctrl.update(Duration::from_millis(200_000)).unwrap();
        assert_eq!(ctrl.output.last_color, Color::RED);
        ctrl.update(Duration::from_millis(200_100)).unwrap();
        assert_eq!(ctrl.output.last_color, Color::BLACK);
    }
}
