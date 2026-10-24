#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceError {
    Timeout,
    Cancelled,
    HardwareFault,
}

/// Trait defining User Presence (UP) verification (e.g. GPIO 0 physical button touch)
pub trait PresenceVerifier {
    /// Check if user presence is currently confirmed without blocking
    fn check_presence(&mut self) -> Result<bool, PresenceError>;

    /// Block and wait for physical touch confirmation with a timeout
    fn wait_for_presence(&mut self, timeout_ms: u32) -> Result<bool, PresenceError>;
}

/// TEST-ONLY: always returns present without touching hardware.
/// Never construct outside `#[cfg(test)]`. Production uses
/// `Gpio0TouchVerifier` (HW) or the `bool presence_confirmed` gate
/// (`UpOnly`/`UpAndPin`); see `oath/applet.rs device_*`.
pub struct AlwaysPresentVerifier;

impl PresenceVerifier for AlwaysPresentVerifier {
    fn check_presence(&mut self) -> Result<bool, PresenceError> {
        Ok(true)
    }

    fn wait_for_presence(&mut self, _timeout_ms: u32) -> Result<bool, PresenceError> {
        Ok(true)
    }
}

/// TEST-ONLY: simulates no touch / timeout.
/// Never construct outside `#[cfg(test)]`.
pub struct NeverPresentVerifier;

impl PresenceVerifier for NeverPresentVerifier {
    fn check_presence(&mut self) -> Result<bool, PresenceError> {
        Ok(false)
    }

    fn wait_for_presence(&mut self, _timeout_ms: u32) -> Result<bool, PresenceError> {
        Err(PresenceError::Timeout)
    }
}

/// Configurable mock verifier for unit tests.
/// Ausente no device (`target_os = "espidf"` sem `cfg(test)`): prod usa
/// `Gpio0TouchVerifier` (HW) ou os verifiers fixos acima.
#[cfg(any(test, not(target_os = "espidf")))]
pub struct MockPresenceVerifier {
    pub is_present: bool,
    pub return_timeout: bool,
}

#[cfg(any(test, not(target_os = "espidf")))]
impl MockPresenceVerifier {
    pub fn new(is_present: bool) -> Self {
        Self {
            is_present,
            return_timeout: false,
        }
    }

    pub fn with_timeout() -> Self {
        Self {
            is_present: false,
            return_timeout: true,
        }
    }
}

#[cfg(any(test, not(target_os = "espidf")))]
impl PresenceVerifier for MockPresenceVerifier {
    fn check_presence(&mut self) -> Result<bool, PresenceError> {
        Ok(self.is_present)
    }

    fn wait_for_presence(&mut self, _timeout_ms: u32) -> Result<bool, PresenceError> {
        if self.return_timeout {
            Err(PresenceError::Timeout)
        } else {
            Ok(self.is_present)
        }
    }
}

/// GPIO 0 Touch Verifier for ESP32-S3 hardware
/// Uses function pointer or closure to read the active-low BOOT button (GPIO 0).
pub struct Gpio0TouchVerifier<F>
where
    F: FnMut() -> bool,
{
    read_gpio0_pressed: F,
}

impl<F> Gpio0TouchVerifier<F>
where
    F: FnMut() -> bool,
{
    pub fn new(read_gpio0_pressed: F) -> Self {
        Self { read_gpio0_pressed }
    }
}

impl<F> PresenceVerifier for Gpio0TouchVerifier<F>
where
    F: FnMut() -> bool,
{
    fn check_presence(&mut self) -> Result<bool, PresenceError> {
        Ok((self.read_gpio0_pressed)())
    }

    fn wait_for_presence(&mut self, _timeout_ms: u32) -> Result<bool, PresenceError> {
        Ok((self.read_gpio0_pressed)())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_verifiers_bypass_hardware_stay_out_of_release() {
        let mut always = AlwaysPresentVerifier;
        assert_eq!(always.check_presence(), Ok(true));
        assert_eq!(always.wait_for_presence(3000), Ok(true));
        let mut never = NeverPresentVerifier;
        assert_eq!(never.check_presence(), Ok(false));
        assert_eq!(never.wait_for_presence(3000), Err(PresenceError::Timeout));
        // Invariant: both types bypass real UP, so they must stay
        // inside #[cfg(test)] call-sites only (audit 2026-10-24:
        // zero production constructors in core/firmware/usb/sdk).
    }
}
