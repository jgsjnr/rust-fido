//! Log de eventos da firmware para o app (op vendor `0x38`).
//!
//! Ring buffer em RAM com os eventos reais do device (boot, janela de
//! pareamento, bond, ops recebidas + status respondido). Sem PII nem
//! segredos: só códigos de evento, opcodes, status e tamanhos — nunca
//! payloads, labels, chaves, PIN ou dados de usuário.
//!
//! Leitura: BLE exige vínculo (`authorize_fw_log_op`, status `0x05` sem
//! ele); serial/USB físico é livre (posse do cabo). Sem UP, sem PIN
//! (diagnóstico, nada sensível). Resposta wire: `0x00 + ASCII`.

extern crate alloc;

use alloc::vec::Vec;

/// Op vendor do log da firmware (primeiro livre após wallet `0x35-0x37`).
pub const OP_FW_LOG: u8 = 0x38;

/// `true` só para `0x38`.
pub fn is_fw_log_op(op: u8) -> bool {
    op == OP_FW_LOG
}

/// Teto do corpo ASCII por resposta (cabe no reassemble BLE com folga).
pub const FW_LOG_MAX_BYTES: usize = 512;

/// Códigos de evento (estáveis; o app só exibe, nunca interpreta PII).
pub const EV_BOOT: u8 = 0x01;
pub const EV_ADV_START: u8 = 0x02;
pub const EV_ADV_STOP: u8 = 0x03;
pub const EV_PAIR_OPEN: u8 = 0x04;
pub const EV_PAIR_CLOSE: u8 = 0x05;
pub const EV_BOND_OK: u8 = 0x06;
pub const EV_OP_RX: u8 = 0x09;
pub const EV_OP_RESP: u8 = 0x0A;
pub const EV_UP_NEEDED: u8 = 0x0B;
pub const EV_UP_OK: u8 = 0x0C;
pub const EV_WALLET: u8 = 0x0D;
pub const EV_RESCUE: u8 = 0x0E;
pub const EV_OTA: u8 = 0x0F;
pub const EV_ERR: u8 = 0x10;

/// Capacidade do anel (16 B/entrada -> 1 KiB de RAM).
pub const FW_LOG_CAP: usize = 64;

#[derive(Debug, Clone, Copy, Default)]
struct Entry {
    seq: u16,
    t_ms: u32,
    code: u8,
    arg: u8,
}

/// Anel de eventos (RAM, perde-se no reboot; `EV_BOOT` marca o zero).
#[derive(Debug)]
pub struct FwLog {
    buf: [Entry; FW_LOG_CAP],
    next: usize,
    len: usize,
    seq: u16,
}

impl FwLog {
    /// Anel vazio (sem `EV_BOOT`; o chamador registra no boot real).
    pub fn new() -> Self {
        Self {
            buf: [Entry::default(); FW_LOG_CAP],
            next: 0,
            len: 0,
            seq: 0,
        }
    }

    /// Registra um evento (`code` + `arg` opaco, `now_ms` monotônico).
    pub fn record(&mut self, code: u8, arg: u8, now_ms: u64) {
        self.seq = self.seq.wrapping_add(1);
        self.buf[self.next] = Entry {
            seq: self.seq,
            t_ms: (now_ms & 0xFFFF_FFFF) as u32,
            code,
            arg,
        };
        self.next = (self.next + 1) % FW_LOG_CAP;
        if self.len < FW_LOG_CAP {
            self.len += 1;
        }
    }

    /// Entradas retidas (para testes).
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` quando vazio.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Renderiza do mais antigo ao mais novo, uma linha ASCII por evento:
    /// `SEQ EV=cc ARG=aa T=mmmm\n` (só decimais, sem nomes/PII).
    /// Corta em `max_bytes` sem partir linha no meio.
    pub fn render_ascii(&self, max_bytes: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        if self.len == 0 || max_bytes == 0 {
            return out;
        }
        let start = (self.next + FW_LOG_CAP - self.len) % FW_LOG_CAP;
        for i in 0..self.len {
            let e = self.buf[(start + i) % FW_LOG_CAP];
            let mut line: [u8; 32] = [0; 32];
            let n = fmt_line(e, &mut line);
            if out.len() + n > max_bytes {
                break;
            }
            out.extend_from_slice(&line[..n]);
        }
        out
    }
}

impl Default for FwLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Formata uma linha no buffer; retorna o comprimento usado.
fn fmt_line(e: Entry, out: &mut [u8; 32]) -> usize {
    let mut n = 0;
    n += push_u16(e.seq, out, n);
    n += push_lit(b" EV=", out, n);
    n += push_u8(e.code, out, n);
    n += push_lit(b" ARG=", out, n);
    n += push_u8(e.arg, out, n);
    n += push_lit(b" T=", out, n);
    n += push_u32(e.t_ms, out, n);
    n += push_lit(b"\n", out, n);
    n
}

fn push_lit(lit: &[u8], out: &mut [u8; 32], mut n: usize) -> usize {
    let mut w = 0;
    for b in lit {
        if n >= out.len() {
            break;
        }
        out[n] = *b;
        n += 1;
        w += 1;
    }
    w
}

fn push_u8(mut v: u8, out: &mut [u8; 32], mut n: usize) -> usize {
    let mut w = 0;
    let mut div = 100;
    let mut started = false;
    while div > 0 {
        let d = v / div;
        v %= div;
        div /= 10;
        if d > 0 || started || div == 0 {
            if n >= out.len() {
                break;
            }
            out[n] = b'0' + d;
            n += 1;
            w += 1;
            started = true;
        }
    }
    w
}

fn push_u16(mut v: u16, out: &mut [u8; 32], mut n: usize) -> usize {
    let mut w = 0;
    let mut div = 10000;
    let mut started = false;
    while div > 0 {
        let d = (v / div) as u8;
        v %= div;
        div /= 10;
        if d > 0 || started || div == 0 {
            if n >= out.len() {
                break;
            }
            out[n] = b'0' + d;
            n += 1;
            w += 1;
            started = true;
        }
    }
    w
}

fn push_u32(mut v: u32, out: &mut [u8; 32], mut n: usize) -> usize {
    let mut w = 0;
    let mut div = 1_000_000_000u32;
    let mut started = false;
    while div > 0 {
        let d = (v / div) as u8;
        v %= div;
        div /= 10;
        if d > 0 || started || div == 0 {
            if n >= out.len() {
                break;
            }
            out[n] = b'0' + d;
            n += 1;
            w += 1;
            started = true;
        }
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn op_so_0x38() {
        assert!(is_fw_log_op(0x38));
        assert!(!is_fw_log_op(0x37));
        assert!(!is_fw_log_op(0x2E));
        assert!(!is_fw_log_op(0x20));
    }

    #[test]
    fn render_linha_e_ordem() {
        let mut l = FwLog::new();
        assert!(l.is_empty());
        l.record(EV_BOOT, 0, 1000);
        l.record(EV_OP_RX, 0x38, 1001);
        assert_eq!(l.len(), 2);
        let raw = l.render_ascii(512);
        let s = String::from_utf8(raw).expect("ascii");
        let mut lines = s.lines();
        assert_eq!(lines.next(), Some("1 EV=1 ARG=0 T=1000"));
        assert_eq!(lines.next(), Some("2 EV=9 ARG=56 T=1001"));
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn anel_sobrescreve_antigo() {
        let mut l = FwLog::new();
        for i in 0..(FW_LOG_CAP + 5) {
            l.record(EV_OP_RX, (i & 0xFF) as u8, i as u64);
        }
        assert_eq!(l.len(), FW_LOG_CAP);
        let s = String::from_utf8(l.render_ascii(4096)).expect("ascii");
        // As 5 primeiras (seq 1..=5) caíram; a mais antiga retida é seq 6.
        assert!(s.lines().next().unwrap_or("").starts_with("6 EV="));
        assert_eq!(s.lines().count(), FW_LOG_CAP);
    }

    #[test]
    fn max_bytes_nao_parte_linha() {
        let mut l = FwLog::new();
        l.record(EV_BOOT, 0, 0);
        l.record(EV_BOOT, 0, 0);
        let raw = l.render_ascii(10);
        // 10 B não cabem 1 linha (~19 B): vazio, sem meia-linha.
        assert!(raw.is_empty());
        let raw = l.render_ascii(19);
        assert_eq!(raw.iter().filter(|b| **b == b'\n').count(), 1);
    }
}
