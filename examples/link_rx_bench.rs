//! Receive-path throughput / allocation benchmark for `Link::handle_packet`.
//!
//! Measures the cost of decrypting received link packets. The link is
//! created with a large negotiated MTU (backbone-like) so the receive path
//! must provision a plaintext buffer as large as the link MDU.
//!
//! Run with `--release` for meaningful numbers:
//!
//!   cargo run --release --example link_rx_bench -- <packets> <mtu>
//!
//! The default packet count is 20000 and the default MTU is 1_048_576.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use reticulum_sdk::destination::link::{Link, LinkHandleResult};
use reticulum_sdk::destination::{DestinationName, SingleInputDestination};
use reticulum_sdk::identity::PrivateIdentity;

struct CountingAllocator;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static A: CountingAllocator = CountingAllocator;

fn create_link_pair(mtu: usize) -> (Link, Link) {
    let identity = PrivateIdentity::new_from_name("link bench owner");
    let destination = SingleInputDestination::new(
        identity,
        DestinationName::new("example_utilities", "link.bench"),
    );

    let (out_event_tx, _out_event_rx) = tokio::sync::broadcast::channel(1_000_000);
    let (in_event_tx, _in_event_rx) = tokio::sync::broadcast::channel(1_000_000);

    let mut out_link = Link::new(destination.desc.clone(), out_event_tx);
    let link_request = out_link.request(Some(mtu));
    let mut in_link = Link::new_from_request(
        &link_request,
        destination.sign_key().clone(),
        destination.desc.clone(),
        in_event_tx,
    )
    .expect("input link");
    let proof = in_link.prove();
    match out_link.handle_packet(&proof, true) {
        LinkHandleResult::Activated => {}
        _ => unreachable!("link proof should activate output link"),
    }

    (out_link, in_link)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let packet_count: usize = args
        .get(1)
        .map(|s| s.parse().unwrap())
        .unwrap_or(20_000);
    let mtu: usize = args
        .get(2)
        .map(|s| s.parse().unwrap())
        .unwrap_or(1_048_576);

    let (out_link, mut in_link) = create_link_pair(mtu);
    println!("link MDU = {} (mtu={})", in_link.mdu(), mtu);

    // Fixed modest payload, independent of the negotiated MTU. This
    // isolates the effect being measured: with a large negotiated MTU the
    // OLD receive path allocated a plaintext buffer as large as the link
    // MDU on every packet regardless of the actual payload size, whereas
    // the new path only allocates the payload that was actually sent.
    let payload_len = 1400usize.min(in_link.mdu());
    let payload = vec![0xABu8; payload_len];

    // Pre-generate a batch of encrypted packets so the loop measures the
    // receive (decrypt + allocation) path only, not the sender.
    let batch: Vec<_> = (0..packet_count)
        .map(|i| {
            let mut p = payload.clone();
            p[0] = i as u8;
            p[payload_len - 1] = (i >> 8) as u8;
            out_link.data_packet(&p).expect("data packet")
        })
        .collect();

    // Warm-up: drain lazy one-time allocations (buffer sizing, etc.) so the
    // measured region is steady-state.
    for p in &batch {
        let _ = in_link.handle_packet(p, false);
    }

    ALLOCS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);

    let start = Instant::now();
    let mut received: usize = 0;
    for p in &batch {
        if let LinkHandleResult::MessageReceived(_) = in_link.handle_packet(p, false) {
            received += 1;
        }
    }
    let elapsed = start.elapsed();

    let allocs = ALLOCS.load(Ordering::Relaxed);
    let alloc_bytes = ALLOC_BYTES.load(Ordering::Relaxed);
    let rate = packet_count as f64 / elapsed.as_secs_f64();

    println!("packets           : {}", packet_count);
    println!("received          : {}", received);
    println!("elapsed           : {:.3} s", elapsed.as_secs_f64());
    println!("throughput        : {:.0} pkt/s", rate);
    println!("heap allocations  : {}", allocs);
    println!("heap bytes alloc  : {}", alloc_bytes);
    println!("allocations/pkt   : {:.2}", allocs as f64 / packet_count as f64);
    println!("bytes/pkt         : {:.2}", alloc_bytes as f64 / packet_count as f64);
}
