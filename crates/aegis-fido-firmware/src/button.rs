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
            delay_fn(Duration::from_millis(self.debounce_ms));
            self.input.is_pressed_raw()
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

/// Simulated button input for unit tests and host-side execution.
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

        let res = button.wait_for_user_presence(
            Duration::from_millis(100),
            |_| {},
            || false,
            |_| {},
        );

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
}
