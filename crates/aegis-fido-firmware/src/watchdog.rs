//! Watchdog feed and static log buffer for the hot loop.
//!
//! MAX-ESP: no `alloc`/`format!` in the hot path; `feed` performs no sleep
//! and preserves USB timing. On `espidf` it resets the task WDT; on host
//! it only records the tick (saturating, no panics).

/// Hot-loop watchdog: records last feed tick, no timing change.
#[derive(Debug, Clone, Copy, Default)]
pub struct Watchdog {
    last_feed_tick: u64,
    timeout_ticks: u64,
}

impl Watchdog {
    /// Creates a watchdog with a tick timeout (ticks are 10ms in `main`).
    /// On `espidf` subscribes the calling task to the TWDT once so `feed`
    /// never logs `task not found` (subscribe-then-reset is the IDF contract).
    pub fn new(timeout_ticks: u64) -> Self {
        #[cfg(target_os = "espidf")]
        unsafe {
            // Already-subscribed tasks return an error which we ignore.
            let _ = esp_idf_sys::esp_task_wdt_add(core::ptr::null_mut());
        }
        Self {
            last_feed_tick: 0,
            timeout_ticks,
        }
    }

    /// Feeds the watchdog at `tick`. No sleep, no USB timing change.
    pub fn feed(&mut self, tick: u64) {
        self.last_feed_tick = tick;
        #[cfg(target_os = "espidf")]
        unsafe {
            esp_idf_sys::esp_task_wdt_reset();
        }
    }

    /// Last tick fed.
    pub fn last_feed(&self) -> u64 {
        self.last_feed_tick
    }

    /// Timeout in ticks.
    pub fn timeout(&self) -> u64 {
        self.timeout_ticks
    }

    /// Whether `tick` exceeded the timeout since last feed (saturating).
    pub fn is_expired(&self, tick: u64) -> bool {
        tick.saturating_sub(self.last_feed_tick) > self.timeout_ticks
    }
}

/// Stack-backed `core::fmt::Write` without `alloc`/`format!`.
///
/// Truncates on overflow (MAX-ESP: static 256B buffer, no heap).
pub struct StaticBuf<CHAR> {
    buf: CHAR,
    len: usize,
}

impl<CHAR> StaticBuf<CHAR>
where
    CHAR: AsMut<[u8]> + AsRef<[u8]>,
{
    /// Wraps a stack buffer.
    pub fn new(buf: CHAR) -> Self {
        Self { buf, len: 0 }
    }

    /// Returns written bytes as `&str` (lossy-safe: writer only copies `&str`).
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf.as_ref()[..self.len]).unwrap_or("")
    }

    /// Number of bytes written (saturating, capped by buffer len).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no bytes were written.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<CHAR> core::fmt::Write for StaticBuf<CHAR>
where
    CHAR: AsMut<[u8]> + AsRef<[u8]>,
{
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let cap = self.buf.as_ref().len();
        let remain = cap.saturating_sub(self.len);
        let take = remain.min(s.len());
        self.buf.as_mut()[self.len..self.len + take]
            .copy_from_slice(&s.as_bytes()[..take]);
        self.len = self.len.saturating_add(take);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;

    #[test]
    fn feed_does_not_change_timing() {
        let mut w = Watchdog::new(300);
        w.feed(10);
        assert_eq!(w.last_feed(), 10);
        assert!(!w.is_expired(20));
        assert!(w.is_expired(400));
        w.feed(u64::MAX);
        assert_eq!(w.last_feed(), u64::MAX);
    }

    #[test]
    fn static_buf_truncates_without_alloc() {
        let mut raw = [0u8; 16];
        let mut b = StaticBuf::new(&mut raw);
        let _ = write!(b, "hello world {:08X}", 0x1234ABCD);
        assert!(!b.is_empty());
        assert!(b.len() <= 16);
        assert!(b.as_str().len() <= 16);
    }
}
