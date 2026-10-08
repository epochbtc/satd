use super::*;

fn block_of(size: usize) -> NetworkMessage {
    NetworkMessage::Unknown {
        command: bitcoin::p2p::message::CommandString::try_from_static("bigmsg").unwrap(),
        payload: vec![0; size],
    }
}

/// The count is the message's v1 wire size, exactly.
#[test]
fn queued_size_is_the_v1_wire_size() {
    for msg in [NetworkMessage::Verack, NetworkMessage::Ping(9), block_of(123_456)] {
        let wire = bitcoin::consensus::serialize(&bitcoin::p2p::message::RawNetworkMessage::new(
            bitcoin::p2p::Magic::REGTEST,
            msg.clone(),
        ));
        assert_eq!(queued_size(&msg), wire.len(), "{}", msg.cmd());
    }
}

/// What goes in is counted, what the write loop takes off is subtracted,
/// and a send that does not happen leaves no trace.
#[test]
fn bytes_are_counted_in_and_out() {
    let (tx, mut rx) = mpsc::channel(2);
    let sender = PeerSender::from(tx);
    let q = sender.queue().clone();
    let a = block_of(600_000);
    let b = block_of(500_000);
    sender.try_send(a.clone()).unwrap();
    assert_eq!(q.queued_bytes(), queued_size(&a));
    assert!(!q.over_limit(), "600 kB is within the buffer");
    sender.try_send(b.clone()).unwrap();
    assert!(q.over_limit(), "1.1 MB is past it");
    assert!(sender.paused());

    // The channel is full: the refused message is not counted.
    let before = q.queued_bytes();
    assert!(sender.try_send(NetworkMessage::Verack).is_err());
    assert_eq!(q.queued_bytes(), before);

    let first = rx.try_recv().unwrap();
    q.sent(queued_size(&first));
    assert_eq!(q.queued_bytes(), queued_size(&b));
    assert!(!q.over_limit());
    assert!(!sender.paused(), "a free slot and room in the buffer");
}

/// A full channel pauses serving even when the bytes are few.
#[test]
fn a_full_channel_pauses() {
    let (tx, _rx) = mpsc::channel(1);
    let sender = PeerSender::from(tx);
    assert!(!sender.paused());
    sender.try_send(NetworkMessage::Verack).unwrap();
    assert!(!sender.queue().over_limit());
    assert!(sender.paused());
}

/// Reading stops from the moment a `getdata` is handed over until the
/// manager has taken it in and served all of it, and while the buffer is
/// over the limit.
#[test]
fn reading_pauses_for_an_unserved_getdata() {
    let q = SendQueue::new();
    assert!(!q.reading_paused());
    q.note_getdata_forwarded();
    assert!(q.reading_paused(), "forwarded, not yet taken in");
    q.push_getdata(vec![Inventory::Block(bitcoin::BlockHash::from_byte_array([1; 32]))]);
    q.note_getdata_handled();
    assert!(q.reading_paused(), "taken in, one entry unserved");
    assert_eq!(q.getdata_backlog(), 1);
    assert!(q.front_getdata().is_some());
    assert!(q.reading_paused(), "still unserved while it is being worked on");
    q.pop_getdata();
    assert!(!q.reading_paused());

    q.add(MAX_SEND_BUFFER_BYTES + 1);
    assert!(q.reading_paused(), "over the buffer");
    q.sent(2);
    assert!(!q.reading_paused());
}

/// One resume request at a time, and only when there is a backlog and room.
#[test]
fn a_resume_is_requested_once_until_taken() {
    let q = SendQueue::new();
    assert!(!q.take_resume(), "nothing to resume");
    q.push_getdata(vec![Inventory::Block(bitcoin::BlockHash::from_byte_array([1; 32]))]);
    q.add(MAX_SEND_BUFFER_BYTES + 1);
    assert!(!q.take_resume(), "no room yet");
    q.sent(MAX_SEND_BUFFER_BYTES + 1);
    assert!(q.take_resume());
    assert!(!q.take_resume(), "one is already waiting");
    q.resume_taken();
    assert!(q.take_resume());
}

/// A wake sent while nobody waits is kept for the next wait.
#[tokio::test]
async fn a_wake_is_not_lost() {
    let q = SendQueue::new();
    q.wake_reader();
    tokio::time::timeout(Duration::from_secs(1), q.reader_woken())
        .await
        .expect("the stored wake resolves the next wait");
}

use bitcoin::hashes::Hash as _;
