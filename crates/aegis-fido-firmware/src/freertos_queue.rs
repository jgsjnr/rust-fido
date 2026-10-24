//! FreeRTOS queue + event-group em Rust (Fase 2: extraido de `freertos_sched`).
//!
//! Movido verbatim de `freertos_sched.rs` (fila `FreeRtosQueue` + `EventGroup`):
//! FIFO limitada com `send` nao-bloqueante fail-closed e `receive` com timeout,
//! e bits estilo `xEventGroupSetBits/WaitBits`. Semantica identica;
//! `freertos_sched` re-exporta (shim fino) para paridade de caminho.

use core::sync::atomic::{AtomicU32, Ordering};
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// Fila limitada estilo `xQueueCreate` (FIFO, com bloqueio e timeout).
///
/// No host usa `Mutex<VecDeque> + Condvar`; no ESP-IDF o transporte real
/// é a fila nativa (ver [`FreeRtosScheduler`]), mas a semântica — FIFO,
/// capacidade fixa, `send` não-bloqueante com descarte fail-closed e
/// `receive` com timeout — é idêntica e testada aqui.
pub struct FreeRtosQueue<T> {
    inner: Mutex<VecDeque<T>>,
    not_empty: Condvar,
    capacity: usize,
}

impl<T> FreeRtosQueue<T> {
    /// Cria fila com a profundidade dada (mínimo 1).
    pub fn new(depth: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(depth.max(1))),
            not_empty: Condvar::new(),
            capacity: depth.max(1),
        }
    }

    /// Envia sem bloquear; `false` = cheia (descarte fail-closed, sem panic).
    ///
    /// Fail-closed documentado: cheia nunca bloqueia a produtora (o TWDT nao
    /// estoura), nunca faz panic e nunca entrega parcial; o evento e
    /// descartado inteiro e o host retenta (mapeado a `TaskOutcome::Dropped`
    /// no consumo). Latch UP e gates CTAP so mudam no roteamento com
    /// resposta, nunca no descarte. Excecao: `FirmwareEvent::Shutdown` usa
    /// `request_stop`/`drain_for_shutdown` e nunca se perde (despejo + retry).
    pub fn send(&self, item: T) -> bool {
        let mut q = self.inner.lock().expect("queue mutex");
        if q.len() >= self.capacity {
            return false;
        }
        q.push_back(item);
        self.not_empty.notify_one();
        true
    }

    /// Recebe com timeout em ms (`None` = sem espera).
    pub fn receive(&self, timeout_ms: Option<u64>) -> Option<T> {
        let mut q = self.inner.lock().expect("queue mutex");
        if let Some(item) = q.pop_front() {
            return Some(item);
        }
        let ms = timeout_ms?;
        let (guard, _res) = self
            .not_empty
            .wait_timeout(q, Duration::from_millis(ms))
            .expect("queue condvar");
        let mut guard = guard;
        guard.pop_front()
    }

    /// Tamanho atual.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("queue mutex").len()
    }

    /// Capacidade configurada.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Fila vazia?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// EventGroup estilo FreeRTOS (`xEventGroupSetBits/WaitBits`).
///
/// Bits são trwa; `wait_bits` bloqueia até `(current & mask) != 0` ou
/// timeout, opcionalmente limpando os bits na saída (`clear_on_exit`,
/// como `pdTRUE` no `xClearOnExit`).
#[derive(Debug, Default)]
pub struct EventGroup {
    bits: AtomicU32,
    mutex: Mutex<()>,
    cv: Condvar,
}

impl EventGroup {
    /// Cria grupo zerado.
    pub fn new() -> Self {
        Self {
            bits: AtomicU32::new(0),
            mutex: Mutex::new(()),
            cv: Condvar::new(),
        }
    }

    /// Liga bits (OR atômico) e acorda esperas.
    pub fn set_bits(&self, bits: u32) {
        self.bits.fetch_or(bits, Ordering::SeqCst);
        let _g = self.mutex.lock().expect("event mutex");
        self.cv.notify_all();
    }

    /// Desliga bits (AND-NOT atômico).
    pub fn clear_bits(&self, bits: u32) {
        self.bits.fetch_and(!bits, Ordering::SeqCst);
    }

    /// Snapshot atual.
    pub fn get(&self) -> u32 {
        self.bits.load(Ordering::SeqCst)
    }

    /// Espera até algum bit de `mask` ligar, com timeout em ms.
    /// Retorna os bits correntes (podem não conter `mask` se expirou).
    pub fn wait_bits(&self, mask: u32, clear_on_exit: bool, timeout_ms: u64) -> u32 {
        let guard = self.mutex.lock().expect("event mutex");
        let deadline = Duration::from_millis(timeout_ms);
        let mut guard = guard;
        let start = std::time::Instant::now();
        loop {
            let cur = self.bits.load(Ordering::SeqCst);
            if cur & mask != 0 {
                if clear_on_exit {
                    self.bits.fetch_and(!mask, Ordering::SeqCst);
                }
                return cur;
            }
            let elapsed = start.elapsed();
            if elapsed >= deadline {
                return self.bits.load(Ordering::SeqCst);
            }
            let remain = deadline - elapsed;
            let (g, _r) = self.cv.wait_timeout(guard, remain).expect("event condvar");
            guard = g;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::freertos_sched::{EVT_BLE_RX, EVT_TICK_10MS, EVT_USB_RX};
    use std::sync::Arc;

    #[test]
    fn queue_fifo_com_descarte_fail_closed() {
        let q: FreeRtosQueue<u8> = FreeRtosQueue::new(2);
        assert!(q.is_empty());
        assert!(q.send(1));
        assert!(q.send(2));
        assert!(!q.send(3));
        assert_eq!(q.len(), 2);
        assert_eq!(q.receive(None), Some(1));
        assert_eq!(q.receive(None), Some(2));
        assert_eq!(q.receive(None), None);
    }

    #[test]
    fn queue_receive_com_timeout() {
        let q = Arc::new(FreeRtosQueue::new(4));
        let q2 = Arc::clone(&q);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            q2.send(42u8);
        });
        assert_eq!(q.receive(Some(500)), Some(42u8));
        assert_eq!(q.receive(Some(10)), None);
    }

    #[test]
    fn event_group_set_wait_clear() {
        let eg = EventGroup::new();
        assert_eq!(eg.get(), 0);
        eg.set_bits(EVT_USB_RX | EVT_TICK_10MS);
        let got = eg.wait_bits(EVT_USB_RX, false, 100);
        assert_ne!(got & EVT_USB_RX, 0);
        // Sem clear: bit continua.
        assert_ne!(eg.get() & EVT_USB_RX, 0);
        let got2 = eg.wait_bits(EVT_USB_RX, true, 100);
        assert_ne!(got2 & EVT_USB_RX, 0);
        assert_eq!(eg.get() & EVT_USB_RX, 0);
        eg.clear_bits(EVT_TICK_10MS);
        assert_eq!(eg.get() & EVT_TICK_10MS, 0);
    }

    #[test]
    fn event_group_timeout_sem_bit() {
        let eg = EventGroup::new();
        let got = eg.wait_bits(EVT_BLE_RX, false, 20);
        assert_eq!(got & EVT_BLE_RX, 0);
    }

    #[test]
    fn queue_depth_zero_clampa_para_um() {
        let q: FreeRtosQueue<u8> = FreeRtosQueue::new(0);
        assert_eq!(q.capacity(), 1);
        assert!(q.send(7));
        assert!(!q.send(8));
        assert_eq!(q.receive(None), Some(7));
    }
}
