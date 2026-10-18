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

/// Always present verifier (e.g., for automated test runs or test mode)
pub struct AlwaysPresentVerifier;

impl PresenceVerifier for AlwaysPresentVerifier {
    fn check_presence(&mut self) -> Result<bool, PresenceError> {
        Ok(true)
    }

    fn wait_for_presence(&mut self, _timeout_ms: u32) -> Result<bool, PresenceError> {
        Ok(true)
    }
}

/// Never present verifier (e.g., simulates user failing to touch within timeout)
pub struct NeverPresentVerifier;

impl PresenceVerifier for NeverPresentVerifier {
    fn check_presence(&mut self) -> Result<bool, PresenceError> {
        Ok(false)
    }

    fn wait_for_presence(&mut self, _timeout_ms: u32) -> Result<bool, PresenceError> {
        Err(PresenceError::Timeout)
    }
}

/// Configurable mock verifier for unit tests
pub struct MockPresenceVerifier {
    pub is_present: bool,
    pub return_timeout: bool,
}

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
        Self {
            read_gpio0_pressed,
        }
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
