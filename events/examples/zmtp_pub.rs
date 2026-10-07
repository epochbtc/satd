//! Publish a fixed, checkable sequence of messages over the in-tree ZMTP PUB
//! server, for interop tests against other ZMQ implementations
//! (`contrib/zmq/interop.sh`).
//!
//! ```text
//! zmtp_pub [ENDPOINT] [SUBSCRIBERS] [PREFIX...]
//! ```
//!
//! Binds `ENDPOINT` (default `tcp://127.0.0.1:0`) and prints
//! `ENDPOINT <bound endpoint>` on its own line. Once `SUBSCRIBERS`
//! (default 1) subscribers are connected and every `PREFIX` has a
//! subscriber, it publishes the sequence below, waits for every subscriber
//! to disconnect, and exits 0. It exits 1 if subscribers do not turn up or
//! do not leave within a minute, or if any message was dropped.
//!
//! The sequence is 46 messages. Message `i` (from 0) has:
//! - topic `TOPICS[i % 5]` for `i < 45`, and `rawblock` for the last;
//! - a body of `LENS[i % 9]` bytes for `i < 45`, and 4 MiB for the last,
//!   whose byte `j` is `(i * 7 + j) % 251`;
//! - the sequence frame `i` as a little-endian `u32`.
//!
//! A subscriber checks the messages whose topic matches its prefixes, in
//! order, and disconnects after the last of them.

use std::io::Write as _;
use std::time::{Duration, Instant};

use bytes::Bytes;
use satd_events::zmtp::ZmtpPub;

const TOPICS: [&str; 5] = ["hashblock", "hashtx", "rawblock", "rawtx", "sequence"];
const LENS: [usize; 9] = [0, 1, 32, 255, 256, 1000, 65_535, 65_536, 300_000];
const COUNT: usize = 46;
const LAST_LEN: usize = 4 << 20;
const WAIT: Duration = Duration::from_secs(60);

fn message(i: usize) -> [Bytes; 3] {
    let (topic, len) = if i + 1 == COUNT {
        ("rawblock", LAST_LEN)
    } else {
        (TOPICS[i % TOPICS.len()], LENS[i % LENS.len()])
    };
    let body: Vec<u8> = (0..len).map(|j| ((i * 7 + j) % 251) as u8).collect();
    [
        Bytes::from_static(topic.as_bytes()),
        Bytes::from(body),
        Bytes::copy_from_slice(&(i as u32).to_le_bytes()),
    ]
}

async fn wait_for(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !cond() {
        if Instant::now() > deadline {
            eprintln!("zmtp_pub: timed out waiting for {what}");
            std::process::exit(1);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or_else(|| "tcp://127.0.0.1:0".to_string());
    let want: usize = match args.next() {
        Some(n) => n.parse().expect("SUBSCRIBERS must be a number"),
        None => 1,
    };
    let prefixes: Vec<String> = args.collect();

    // An unbounded HWM: this is a correctness check, nothing may drop.
    let pubs = ZmtpPub::bind(&endpoint, 0).await?;
    println!("ENDPOINT {}", pubs.local_endpoint());
    std::io::stdout().flush()?;

    wait_for("subscribers", || {
        pubs.subscriber_count() >= want
            && prefixes.iter().all(|p| pubs.has_subscriber(p.as_bytes()))
    })
    .await;
    for i in 0..COUNT {
        pubs.publish(message(i));
    }
    wait_for("subscribers to finish", || pubs.subscriber_count() == 0).await;

    if pubs.dropped_total() != 0 {
        eprintln!("zmtp_pub: {} messages dropped", pubs.dropped_total());
        std::process::exit(1);
    }
    eprintln!("zmtp_pub: published {COUNT} messages to {want} subscriber(s)");
    Ok(())
}
