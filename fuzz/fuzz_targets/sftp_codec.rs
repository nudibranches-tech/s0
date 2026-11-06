//! `sftp::codec::parse` over arbitrary packet bodies: every input is a `Request` or a
//! `CodecError`, never a panic, an overflow or an allocation sized by an unchecked length
//! field. The deterministic `codec::tests::arbitrary_bytes_never_panic` runs the same
//! function on every `cargo test`.
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = s0::sftp::codec::parse(Bytes::copy_from_slice(data));
});
