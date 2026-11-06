//! The PROXY v2 header parser (`sftp::preauth`) over arbitrary bytes. Drives both the
//! buffer form `parse_proxy_v2` and the stream reader `read_proxy_v2` the listener uses,
//! and checks they agree: same header, same error, the same number of bytes consumed, and
//! "needs more bytes" exactly where the reader hits end of stream.
#![no_main]

use std::future::Future;
use std::io;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use libfuzzer_sys::fuzz_target;
use s0::sftp::preauth::{PROXY_V2_SIG, parse_proxy_v2, read_proxy_v2};

fuzz_target!(|input: &[u8]| {
    // libFuzzer rarely guesses a 12-byte magic, so an odd first byte prepends the PROXY
    // v2 signature and the rest of the input exercises the head and address block. An
    // even first byte feeds the input as-is (signature mismatches, v1 text, short reads).
    let Some((&mode, rest)) = input.split_first() else {
        return;
    };
    let owned;
    let data: &[u8] = if mode & 1 == 1 {
        owned = [&PROXY_V2_SIG[..], rest].concat();
        &owned
    } else {
        rest
    };

    let pure = parse_proxy_v2(data);

    // A `&[u8]` reader never returns `Pending`, so one poll completes the future: no
    // runtime, no I/O.
    let mut reader = data;
    let streamed = {
        let mut fut = pin!(read_proxy_v2(&mut reader));
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(r) => r,
            Poll::Pending => panic!("read_proxy_v2 over a byte slice returned Pending"),
        }
    };

    match (pure, streamed) {
        (Ok(Some((header, consumed))), Ok(read)) => {
            assert_eq!(header, read);
            assert_eq!(consumed, data.len() - reader.len());
        }
        (Ok(None), Err(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
        (Err(msg), Err(e)) => {
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            assert_eq!(e.to_string(), msg);
        }
        (p, s) => panic!("parsers disagree: {p:?} vs {s:?}"),
    }
});
