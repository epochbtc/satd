//! The HTTP listeners budget the "accept error" warning: the first five a
//! minute per listener are logged and the rest counted. During fd
//! exhaustion every `accept` fails, and unbudgeted the loop logged a line
//! per 50 ms retry.
//!
//! Its own test binary because the log capture needs a process-wide
//! subscriber (see `Logs`), and because the test lowers the process's
//! file-descriptor limit, which would starve any test running beside it.
//! Linux only: it reads `EMFILE` off a real fd table.
#![cfg(target_os = "linux")]

use std::time::Duration;

use node::http_serve::{ListenerLimits, SocketCap, Transport, serve_http_listener};
use tokio::net::TcpListener;
use tokio::sync::watch;

thread_local! {
    static THREAD_LOGS: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

struct ThreadLogs;

impl std::io::Write for ThreadLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        THREAD_LOGS.with(|l| l.borrow_mut().extend_from_slice(buf));
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One process-wide subscriber writing into a per-thread buffer, never a
/// scoped `set_default`: whether a `warn!` is evaluated at all is decided by
/// tracing's process-wide callsite interest, which a scoped subscriber on
/// any thread moves. Each `#[tokio::test]` runs on its own thread with a
/// current-thread runtime, so the buffer is the test's own, and the
/// listener's tasks write into it too.
struct Logs;

impl Logs {
    fn capture() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            use tracing_subscriber::layer::SubscriberExt as _;
            use tracing_subscriber::util::SubscriberInitExt as _;
            let _ = tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(|| ThreadLogs),
                )
                .with(tracing_subscriber::filter::LevelFilter::TRACE)
                .try_init();
        });
        THREAD_LOGS.with(|l| l.borrow_mut().clear());
        Logs
    }

    fn count(&self, needle: &str) -> usize {
        THREAD_LOGS.with(|l| String::from_utf8_lossy(&l.borrow()).matches(needle).count())
    }
}

fn limits() -> ListenerLimits {
    ListenerLimits {
        sockets: SocketCap::new(0),
        idle_timeout: None,
        write_timeout: None,
    }
}

/// fd exhaustion: every `accept` fails with `EMFILE` while a connection
/// waits in the backlog, and the loop retries every 50 ms.
#[tokio::test]
async fn accept_errors_are_budgeted() {
    let logs = Logs::capture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Connected before the fds run out: the kernel completes the handshake
    // and queues it, and the listener cannot take it.
    let _client = std::net::TcpStream::connect(addr).unwrap();

    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: plain libc calls on a valid out-pointer.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) }, 0);
    let saved = limit;
    limit.rlim_cur = limit.rlim_cur.min(1024);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let mut filler = Vec::new();
    while let Ok(f) = std::fs::File::open("/dev/null") {
        filler.push(f);
    }

    let (sd_tx, sd_rx) = watch::channel(false);
    let serve = tokio::spawn(serve_http_listener(
        "test",
        listener,
        Transport::Plain,
        axum::Router::new(),
        limits(),
        sd_rx,
    ));
    // About twenty failed accepts.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = sd_tx.send(true);
    let _ = serve.await;

    drop(filler);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &saved) }, 0);
    assert_eq!(logs.count("accept error"), 5, "the EMFILE retries are budgeted");
}
