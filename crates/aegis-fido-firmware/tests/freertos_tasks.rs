//! Integração host do escalonador FreeRTOS (sem hardware).
//!
//! Sobe 3 tasks (USB com 2 pacotes, botão com 1 UP, housekeeping com
//! ticks) via `aegis_fido_firmware::freertos::*` e asserta os contratos
//! observáveis: `drained >= 2`, `presses >= 1`, tick visto, `request_stop`
//! triplo (flag + `EVT_SHUTDOWN` + `Shutdown` drenado) e descarte
//! fail-closed em fila cheia (sem panic).

use aegis_fido_firmware::freertos::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Deadline padrão: 2 s (sem sleeps longos, sem flake).
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn scheduler_tres_tasks_drena_usb_button_tick_e_shutdown_triplo() {
    let sched = FreeRtosScheduler::new(32);

    // USB: exatamente 2 pacotes de 64 B, depois `None` (sem wrap do contador).
    let remaining = Arc::new(AtomicUsize::new(2));
    let remaining_clone = Arc::clone(&remaining);
    let usb = sched.spawn_usb_task(move || {
        if remaining_clone.load(Ordering::SeqCst) == 0 {
            return None;
        }
        if remaining_clone.fetch_sub(1, Ordering::SeqCst) > 0 {
            Some([0xA5; CTAPHID_PACKET_SIZE])
        } else {
            None
        }
    });

    // Botão: exatamente 1 UP (BOOT) na segunda amostragem (~10 ms).
    let polls = Arc::new(AtomicUsize::new(0));
    let polls_clone = Arc::clone(&polls);
    let button = sched.spawn_button_task(
        move || polls_clone.fetch_add(1, Ordering::SeqCst) == 1,
        || false,
    );

    // Housekeeping: watchdog + tick periódico (tick 0 emite de imediato).
    let house = sched.spawn_housekeeping_task();

    // Drena a fila compartilhada até ver os 3 observáveis (ou deadline 2 s).
    let end = deadline();
    let mut usb_seen = 0usize;
    let mut button_seen = 0usize;
    let mut tick_seen = false;
    while Instant::now() < end {
        match sched.queue.receive(Some(50)) {
            Some(FirmwareEvent::UsbPacket(_)) => usb_seen += 1,
            Some(FirmwareEvent::ButtonPress { boot: true, .. }) => button_seen += 1,
            Some(FirmwareEvent::Tick10ms(_)) => tick_seen = true,
            Some(_) => {}
            None => {}
        }
        if usb_seen >= 2 && button_seen >= 1 && tick_seen {
            break;
        }
    }
    assert!(usb_seen >= 2, "esperava >=2 pacotes USB, viu {usb_seen}");
    assert!(button_seen >= 1, "esperava >=1 UP de botão");
    assert!(tick_seen, "esperava ao menos 1 tick do housekeeping");

    // Desligamento cooperativo triplo.
    sched.request_stop();
    assert!(
        sched.stop.load(Ordering::SeqCst),
        "request_stop deve armar a flag"
    );
    assert_ne!(
        sched.events.get() & EVT_SHUTDOWN,
        0,
        "request_stop deve setar EVT_SHUTDOWN"
    );

    let drained = usb.join().expect("join usb");
    let presses = button.join().expect("join button");
    let ticks = house.join().expect("join housekeeping");
    assert!(drained >= 2, "esperava drained>=2, obteve {drained}");
    assert!(presses >= 1, "esperava presses>=1, obteve {presses}");
    assert!(ticks >= 1, "esperava ao menos 1 tick, obteve {ticks}");

    // `Shutdown` drenado da fila (pode haver eventos à frente; drena com timeout).
    let end = deadline();
    let mut shutdown_seen = false;
    while Instant::now() < end {
        match sched.queue.receive(Some(50)) {
            Some(FirmwareEvent::Shutdown) => {
                shutdown_seen = true;
                break;
            }
            Some(_) => {}
            None => {}
        }
    }
    assert!(shutdown_seen, "esperava FirmwareEvent::Shutdown na fila");
}

#[test]
fn fila_cheia_descarta_sem_panic() {
    let q: FreeRtosQueue<u8> = FreeRtosQueue::new(2);
    assert!(q.send(1));
    assert!(q.send(2));
    // Cheia: `false`, sem panic, sem crescer além da capacidade.
    assert!(!q.send(3));
    assert_eq!(q.len(), 2);
    assert_eq!(q.capacity(), 2);
    assert_eq!(q.receive(None), Some(1));
    assert_eq!(q.receive(None), Some(2));
    assert_eq!(q.receive(None), None);
}
