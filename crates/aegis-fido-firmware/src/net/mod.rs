//! Net: WiFi AP + station + mDNS + politica de senha (ver cascas finas
//! `wifi_ap` / `wifi_station` / `mdns` para compat de paths externos).
pub mod ap_core;
pub mod http_front;
pub mod mdns;
pub mod password_policy;
pub mod station;
