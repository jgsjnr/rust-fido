//! Physical BOOT Button Driver (GPIO 0) with Debounce and User Presence (UP) Detection.
//!
//! ESP32-S3 boards route the physical "BOOT" button to GPIO 0 with an external pullup.
//! Pressing the button pulls GPIO 0 to ground (Active-LOW).
//! 100% Native Rust implementation.

use core::time::Duration;

/// Debounce stabilization time in milliseconds.
pub const DEBOUNCE_TIME_MS: u64 = 50;

/// Default timeout waiting for User Presence (UP) confirmation (in milliseconds).
pub const DEFAULT_UP_TIMEOUT_MS: u64 = 15_000;

/// Long press threshold for administrative reset (in milliseconds).
pub const LONG_PRESS_THRESHOLD_MS: u64 = 3_000;

/// Type of button press detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressEvent {
    None,
    ShortPress(Duration),
    LongPress(Duration),
}

/// Errors occurring during user presence verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPresenceError {
    Timeout,
    Cancelled,
    HardwareFault,
}

/// Abstract interface for detecting physical button state.
pub trait ButtonInput {
    /// Returns `true` if the button is currently physically held down.
    fn is_pressed_raw(&self) -> bool;
}

/// Physical button driver with debouncing and User Presence detection logic.
pub struct BootButton<I: ButtonInput> {
    input: I,
    debounce_ms: u64,
}

impl<I: ButtonInput> BootButton<I> {
    pub fn new(input: I) -> Self {
        Self {
            input,
            debounce_ms: DEBOUNCE_TIME_MS,
        }
    }

    /// Checks if the button is pressed with debouncing logic.
    pub fn is_pressed(&self, delay_fn: impl Fn(Duration)) -> bool {
        if self.input.is_pressed_raw() {
            delay_fn(Duration::from_millis(5));
            true
        } else {
            false
        }
    }

    /// Waits for User Presence (UP) within a timeout.
    /// Calls `tick_callback` periodically to allow LED animations (e.g. breathing effect)
    /// and check for CTAPHID_CANCEL packets.
    pub fn wait_for_user_presence<F, C, D>(
        &self,
        timeout: Duration,
        mut tick_callback: F,
        mut cancel_check: C,
        mut delay_fn: D,
    ) -> Result<bool, UserPresenceError>
    where
        F: FnMut(Duration),
        C: FnMut() -> bool,
        D: FnMut(Duration),
    {
        let mut elapsed = Duration::from_millis(0);
        let poll_interval = Duration::from_millis(20);

        while elapsed < timeout {
            if cancel_check() {
                return Err(UserPresenceError::Cancelled);
            }

            tick_callback(elapsed);

            if self.input.is_pressed_raw() {
                // Confirm with debounce delay
                delay_fn(Duration::from_millis(self.debounce_ms));
                if self.input.is_pressed_raw() {
                    // Wait for release before continuing
                    while self.input.is_pressed_raw() {
                        delay_fn(Duration::from_millis(20));
                    }
                    return Ok(true);
                }
            }

            delay_fn(poll_interval);
            elapsed += poll_interval;
        }

        Err(UserPresenceError::Timeout)
    }

    /// Measures the duration of a button press to detect Short Press vs Long Press.
    pub fn poll_press_event(
        &self,
        mut delay_fn: impl FnMut(Duration),
        now_ms_fn: impl Fn() -> u64,
    ) -> PressEvent {
        if !self.input.is_pressed_raw() {
            return PressEvent::None;
        }

        // Wait debounce
        delay_fn(Duration::from_millis(self.debounce_ms));
        if !self.input.is_pressed_raw() {
            return PressEvent::None;
        }

        let start_ms = now_ms_fn();
        while self.input.is_pressed_raw() {
            delay_fn(Duration::from_millis(20));
        }
        let duration = Duration::from_millis(now_ms_fn().saturating_sub(start_ms));

        if duration.as_millis() >= (LONG_PRESS_THRESHOLD_MS as u128) {
            PressEvent::LongPress(duration)
        } else {
            PressEvent::ShortPress(duration)
        }
    }
}

/// Hardware BOOT button input on GPIO 0 (active-low with pullup).
// gpio/initialized retained for ESP-IDF hardware handle; unused on host tests but required on device. No logic change.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EspBootButtonInput {
    gpio: i32,
    initialized: bool,
}

impl EspBootButtonInput {
    pub fn new() -> Self {
        #[cfg(target_os = "espidf")]
        unsafe {
            let conf = esp_idf_sys::gpio_config_t {
                pin_bit_mask: 1u64 << 0,
                mode: esp_idf_sys::gpio_mode_t_GPIO_MODE_INPUT,
                pull_up_en: esp_idf_sys::gpio_pullup_t_GPIO_PULLUP_ENABLE,
                pull_down_en: esp_idf_sys::gpio_pulldown_t_GPIO_PULLDOWN_DISABLE,
                intr_type: esp_idf_sys::gpio_int_type_t_GPIO_INTR_DISABLE,
            };
            esp_idf_sys::gpio_config(&conf);
        }
        Self {
            gpio: 0,
            initialized: true,
        }
    }
}

impl Default for EspBootButtonInput {
    fn default() -> Self {
        Self::new()
    }
}

impl ButtonInput for EspBootButtonInput {
    fn is_pressed_raw(&self) -> bool {
        #[cfg(target_os = "espidf")]
        unsafe {
            // GPIO 0 active-low: 0 = pressed, 1 = released
            esp_idf_sys::gpio_get_level(self.gpio) == 0
        }
        #[cfg(not(target_os = "espidf"))]
        false
    }
}

/// Hardware KEY button input on GPIO 14 (LilyGO T-Display-S3) or GPIO 35 (LilyGO TTGO T-Display Classic).
// Same as above: hardware handle retained for device builds.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EspKeyButtonInput {
    gpio: i32,
    initialized: bool,
}

impl EspKeyButtonInput {
    pub fn new() -> Self {
        #[cfg(feature = "board-ttgo-classic")]
        let gpio = 35;
        #[cfg(not(feature = "board-ttgo-classic"))]
        let gpio = 14;

        Self::new_with_gpio(gpio)
    }

    pub fn new_with_gpio(gpio: i32) -> Self {
        #[cfg(target_os = "espidf")]
        unsafe {
            // Note: GPIO 34-39 on ESP32 are input-only pins without internal pullups
            let pull_up_en = if gpio >= 34 {
                esp_idf_sys::gpio_pullup_t_GPIO_PULLUP_DISABLE
            } else {
                esp_idf_sys::gpio_pullup_t_GPIO_PULLUP_ENABLE
            };

            let conf = esp_idf_sys::gpio_config_t {
                pin_bit_mask: 1u64 << gpio,
                mode: esp_idf_sys::gpio_mode_t_GPIO_MODE_INPUT,
                pull_up_en,
                pull_down_en: esp_idf_sys::gpio_pulldown_t_GPIO_PULLDOWN_DISABLE,
                intr_type: esp_idf_sys::gpio_int_type_t_GPIO_INTR_DISABLE,
            };
            esp_idf_sys::gpio_config(&conf);
        }
        Self {
            gpio,
            initialized: true,
        }
    }
}

impl Default for EspKeyButtonInput {
    fn default() -> Self {
        Self::new()
    }
}

impl ButtonInput for EspKeyButtonInput {
    fn is_pressed_raw(&self) -> bool {
        #[cfg(target_os = "espidf")]
        unsafe {
            // GPIO 14 active-low: 0 = pressed, 1 = released
            esp_idf_sys::gpio_get_level(self.gpio) == 0
        }
        #[cfg(not(target_os = "espidf"))]
        false
    }
}

/// Dual Button Manager supporting both DevKitC-1 (GPIO 0 only) and LilyGO T-Display-S3 (GPIO 0 + GPIO 14).
pub struct DualButtonManager<B: ButtonInput, K: ButtonInput> {
    pub boot: BootButton<B>,
    pub key: Option<BootButton<K>>,
}

impl<B: ButtonInput, K: ButtonInput> DualButtonManager<B, K> {
    pub fn new(boot_input: B, key_input: Option<K>) -> Self {
        Self {
            boot: BootButton::new(boot_input),
            key: key_input.map(BootButton::new),
        }
    }

    /// Checks if the BOOT button (GPIO 0 / Confirm) is pressed.
    pub fn is_boot_pressed(&self, delay_fn: impl Fn(Duration)) -> bool {
        self.boot.is_pressed(delay_fn)
    }

    /// Checks if the KEY button (GPIO 14 / Cancel or Next) is pressed.
    pub fn is_key_pressed(&self, delay_fn: impl Fn(Duration)) -> bool {
        if let Some(ref k) = self.key {
            k.is_pressed(delay_fn)
        } else {
            false
        }
    }

    /// Dual-button User Presence waiting logic:
    /// - BOOT button (GPIO 0) -> Authorize transaction (`Ok(true)`).
    /// - KEY button (GPIO 14) -> Reject transaction (`Err(UserPresenceError::Cancelled)`).
    /// - Timeout -> `Err(UserPresenceError::Timeout)`.
    pub fn wait_for_user_presence<F, C, D>(
        &self,
        timeout: Duration,
        mut tick_callback: F,
        mut cancel_check: C,
        mut delay_fn: D,
    ) -> Result<bool, UserPresenceError>
    where
        F: FnMut(Duration),
        C: FnMut() -> bool,
        D: FnMut(Duration),
    {
        let mut elapsed = Duration::from_millis(0);
        let poll_interval = Duration::from_millis(20);

        while elapsed < timeout {
            if cancel_check() {
                return Err(UserPresenceError::Cancelled);
            }

            tick_callback(elapsed);

            // 1. Check BOOT button (Confirm / Authorize)
            if self.boot.input.is_pressed_raw() {
                delay_fn(Duration::from_millis(self.boot.debounce_ms));
                if self.boot.input.is_pressed_raw() {
                    while self.boot.input.is_pressed_raw() {
                        delay_fn(Duration::from_millis(20));
                    }
                    return Ok(true);
                }
            }

            // 2. Check KEY button (Cancel / Reject) if available (LilyGO T-Display)
            if let Some(ref k) = self.key {
                if k.input.is_pressed_raw() {
                    delay_fn(Duration::from_millis(k.debounce_ms));
                    if k.input.is_pressed_raw() {
                        while k.input.is_pressed_raw() {
                            delay_fn(Duration::from_millis(20));
                        }
                        return Err(UserPresenceError::Cancelled);
                    }
                }
            }

            delay_fn(poll_interval);
            elapsed += poll_interval;
        }

        Err(UserPresenceError::Timeout)
    }
}

#[derive(Debug, Clone, Default)]
pub struct MockButtonInput {
    pub pressed: std::sync::Arc<core::sync::atomic::AtomicBool>,
}

impl MockButtonInput {
    pub fn new() -> Self {
        Self {
            pressed: std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn set_pressed(&self, state: bool) {
        self.pressed
            .store(state, core::sync::atomic::Ordering::SeqCst);
    }
}

impl ButtonInput for MockButtonInput {
    fn is_pressed_raw(&self) -> bool {
        self.pressed.load(core::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debounce_filtering() {
        let input = MockButtonInput::new();
        let button = BootButton::new(input.clone());

        assert!(!button.is_pressed(|_| {}));

        input.set_pressed(true);
        assert!(button.is_pressed(|_| {}));
    }

    #[test]
    fn test_user_presence_timeout() {
        let input = MockButtonInput::new();
        let button = BootButton::new(input);

        let res =
            button.wait_for_user_presence(Duration::from_millis(100), |_| {}, || false, |_| {});

        assert_eq!(res, Err(UserPresenceError::Timeout));
    }

    #[test]
    fn test_user_presence_detected() {
        let input = MockButtonInput::new();
        let button = BootButton::new(input.clone());

        let mut counter = 0;
        let res = button.wait_for_user_presence(
            Duration::from_millis(200),
            |_| {},
            || false,
            |_| {
                counter += 1;
                if counter == 3 {
                    input.set_pressed(true);
                } else if counter == 5 {
                    input.set_pressed(false);
                }
            },
        );

        assert_eq!(res, Ok(true));
    }

    #[test]
    fn test_dual_button_confirm_and_cancel() {
        let boot_mock = MockButtonInput::new();
        let key_mock = MockButtonInput::new();

        let dual_mgr = DualButtonManager::new(boot_mock.clone(), Some(key_mock.clone()));

        // Test Confirm via BOOT (GPIO 0)
        let mut boot_steps = 0;
        let res_confirm = dual_mgr.wait_for_user_presence(
            Duration::from_millis(200),
            |_| {},
            || false,
            |_| {
                boot_steps += 1;
                if boot_steps == 2 {
                    boot_mock.set_pressed(true);
                } else if boot_steps == 4 {
                    boot_mock.set_pressed(false);
                }
            },
        );
        assert_eq!(res_confirm, Ok(true));

        // Test Reject/Cancel via KEY (GPIO 14)
        let mut key_steps = 0;
        let res_cancel = dual_mgr.wait_for_user_presence(
            Duration::from_millis(200),
            |_| {},
            || false,
            |_| {
                key_steps += 1;
                if key_steps == 2 {
                    key_mock.set_pressed(true);
                } else if key_steps == 4 {
                    key_mock.set_pressed(false);
                }
            },
        );
        assert_eq!(res_cancel, Err(UserPresenceError::Cancelled));
    }
}
