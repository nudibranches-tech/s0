//! What happens on a connection before russh sees a byte: the PROXY v2 header and the
//! strict-KEX requirement (ADR-009 D3, D12).
//!
//! **Strict KEX (Terrapin).** russh 0.63.3 negotiates `kex-strict-*-v00@openssh.com` when
//! both sides offer it, but exposes no way for a server to *require* it: the negotiated
//! flag is private to the session and no `Handler` method runs before authentication. The
//! client's first `SSH_MSG_KEXINIT` is sent in the clear, though, so [`StrictKexGuard`]
//! reads it on its way in and closes the connection unless the client advertises
//! `kex-strict-c-v00@openssh.com`. No byte of the client's stream reaches russh until that
//! verdict is in. This enforces the requirement in-tree rather than as an upstream patch.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// The 12-byte PROXY protocol v2 signature.
pub const PROXY_V2_SIG: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// Upper bound on the address block (TLVs included) of a v2 header. The spec allows
/// 65535; nothing a load balancer sends to s0 needs more than this.
const MAX_PROXY_LEN: usize = 512;

/// The client marker for strict KEX.
pub const STRICT_KEX_CLIENT: &str = "kex-strict-c-v00@openssh.com";

/// What a PROXY v2 header said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyHeader {
    /// `LOCAL`: a load-balancer health check. Closed without an SSH banner.
    Local,
    /// `PROXY` over TCP: the real client.
    Proxied { source: SocketAddr },
}

/// Parse a PROXY v2 header (binary form only) from the front of `stream`.
///
/// Reads exactly the header and nothing more. The v1 text form is refused.
pub async fn read_proxy_v2<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<ProxyHeader> {
    let mut head = [0u8; 16];
    stream.read_exact(&mut head).await?;
    let (cmd, fam, len) =
        parse_proxy_v2_head(&head).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    parse_proxy_v2_body(cmd, fam, &body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// `(command, family, address-block length)` from the 16-byte fixed head.
pub fn parse_proxy_v2_head(head: &[u8; 16]) -> Result<(u8, u8, usize), &'static str> {
    if head[..12] != PROXY_V2_SIG {
        if head.starts_with(b"PROXY ") {
            return Err("PROXY protocol v1 (text) is refused; configure v2");
        }
        return Err("trusted peer did not send a PROXY v2 header");
    }
    let ver_cmd = head[12];
    if ver_cmd >> 4 != 2 {
        return Err("unsupported PROXY protocol version");
    }
    let cmd = ver_cmd & 0x0f;
    if cmd > 1 {
        return Err("unknown PROXY command");
    }
    let len = usize::from(u16::from_be_bytes([head[14], head[15]]));
    if len > MAX_PROXY_LEN {
        return Err("PROXY v2 address block too large");
    }
    Ok((cmd, head[13], len))
}

/// Decode the address block.
pub fn parse_proxy_v2_body(cmd: u8, fam: u8, body: &[u8]) -> Result<ProxyHeader, &'static str> {
    if cmd == 0 {
        return Ok(ProxyHeader::Local);
    }
    match fam {
        // TCP over IPv4
        0x11 => {
            let b = body.get(..12).ok_or("truncated PROXY v2 IPv4 block")?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[8], b[9]]);
            Ok(ProxyHeader::Proxied {
                source: SocketAddr::new(IpAddr::V4(ip), port),
            })
        }
        // TCP over IPv6
        0x21 => {
            let b = body.get(..36).ok_or("truncated PROXY v2 IPv6 block")?;
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[..16]);
            let port = u16::from_be_bytes([b[32], b[33]]);
            Ok(ProxyHeader::Proxied {
                source: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), port),
            })
        }
        _ => Err("unsupported PROXY v2 address family (TCP over IPv4/IPv6 only)"),
    }
}

/// Bound on what the guard buffers before it reaches a verdict: the identification line
/// plus one KEXINIT. A client KEXINIT is a few kilobytes.
const MAX_PREAMBLE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pending,
    Pass,
}

/// Wraps the client stream and withholds every inbound byte from russh until the client's
/// first KEXINIT has been seen to advertise strict KEX (see the module doc). Writes pass
/// straight through, so russh can send its own banner and KEXINIT meanwhile.
pub struct StrictKexGuard<S> {
    inner: S,
    buf: Vec<u8>,
    /// Bytes of `buf` already handed to the reader after a `Pass`.
    released: usize,
    verdict: Verdict,
    /// Where a refusal is reported, so the connection task can audit it after russh has
    /// consumed the stream.
    refusal: Option<std::sync::Arc<std::sync::OnceLock<&'static str>>>,
}

impl<S> StrictKexGuard<S> {
    pub fn new(inner: S) -> Self {
        StrictKexGuard {
            inner,
            buf: Vec::new(),
            released: 0,
            verdict: Verdict::Pending,
            refusal: None,
        }
    }

    #[must_use]
    pub fn with_refusal_slot(
        mut self,
        slot: std::sync::Arc<std::sync::OnceLock<&'static str>>,
    ) -> Self {
        self.refusal = Some(slot);
        self
    }
}

/// Inspect the buffered preamble: `Ok(None)` needs more bytes, `Ok(Some(()))` passes,
/// `Err` refuses.
pub fn inspect_preamble(buf: &[u8]) -> Result<Option<()>, &'static str> {
    if buf.len() >= 4 && PROXY_V2_SIG.starts_with(&buf[..buf.len().min(12)]) {
        return Err("PROXY header from a peer outside frontends.sftp.proxy_protocol.trusted_cidrs");
    }
    if buf.starts_with(b"PROXY ") {
        return Err("PROXY header from a peer outside frontends.sftp.proxy_protocol.trusted_cidrs");
    }
    // RFC 4253 §4.2: the client sends exactly its identification line first.
    let Some(nl) = buf.iter().position(|b| *b == b'\n') else {
        if buf.len() > 255 {
            return Err("identification line too long");
        }
        if !buf.is_empty() && !b"SSH-".starts_with(&buf[..buf.len().min(4)]) {
            return Err("not an SSH client");
        }
        return Ok(None);
    };
    if !buf.starts_with(b"SSH-2.0-") {
        return Err("not an SSH-2.0 client");
    }
    let pkt = &buf[nl + 1..];
    if pkt.len() < 6 {
        return Ok(None);
    }
    let packet_len = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]) as usize;
    if !(2..=MAX_PREAMBLE).contains(&packet_len) {
        return Err("malformed first packet");
    }
    if pkt.len() < 4 + packet_len {
        return Ok(None);
    }
    let padding = usize::from(pkt[4]);
    let payload_len = packet_len
        .checked_sub(1 + padding)
        .ok_or("malformed first packet padding")?;
    let payload = &pkt[5..5 + payload_len];
    // SSH_MSG_KEXINIT = 20, then a 16-byte cookie, then the kex name-list.
    if payload.first() != Some(&20) {
        return Err("first packet is not KEXINIT");
    }
    let rest = payload.get(17..).ok_or("truncated KEXINIT")?;
    let len = rest
        .get(..4)
        .map(|l| u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize)
        .ok_or("truncated KEXINIT")?;
    let names = rest.get(4..4 + len).ok_or("truncated KEXINIT")?;
    let names = std::str::from_utf8(names).map_err(|_| "KEXINIT name-list is not ASCII")?;
    if names.split(',').any(|n| n == STRICT_KEX_CLIENT) {
        Ok(Some(()))
    } else {
        Err(
            "client does not support strict key exchange (kex-strict-c-v00@openssh.com); \
             Terrapin-vulnerable clients are refused",
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StrictKexGuard<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.verdict {
                Verdict::Pass => {
                    if this.released < this.buf.len() {
                        let n = (this.buf.len() - this.released).min(out.remaining());
                        out.put_slice(&this.buf[this.released..this.released + n]);
                        this.released += n;
                        if this.released == this.buf.len() {
                            this.buf = Vec::new();
                            this.released = 0;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut this.inner).poll_read(cx, out);
                }
                Verdict::Pending => {
                    let mut tmp = [0u8; 4096];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let got = rb.filled();
                            if got.is_empty() {
                                // EOF before a verdict.
                                return Poll::Ready(Ok(()));
                            }
                            this.buf.extend_from_slice(got);
                            if this.buf.len() > MAX_PREAMBLE {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "preamble too large",
                                )));
                            }
                            match inspect_preamble(&this.buf) {
                                Ok(None) => continue,
                                Ok(Some(())) => this.verdict = Verdict::Pass,
                                Err(why) => {
                                    if let Some(slot) = &this.refusal {
                                        let _ = slot.set(why);
                                    }
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::PermissionDenied,
                                        why,
                                    )));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StrictKexGuard<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kexinit(names: &str) -> Vec<u8> {
        let mut payload = vec![20u8];
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&(names.len() as u32).to_be_bytes());
        payload.extend_from_slice(names.as_bytes());
        let padding = 4u8;
        let packet_len = (payload.len() + 1 + usize::from(padding)) as u32;
        let mut out = b"SSH-2.0-OpenSSH_9.9\r\n".to_vec();
        out.extend_from_slice(&packet_len.to_be_bytes());
        out.push(padding);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&[0u8; 4]);
        out
    }

    #[test]
    fn strict_kex_is_required() {
        let ok = kexinit("curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com");
        assert_eq!(inspect_preamble(&ok), Ok(Some(())));
        let bad = kexinit("curve25519-sha256,ext-info-c");
        assert!(inspect_preamble(&bad).unwrap_err().contains("strict"));
        // Partial input waits rather than deciding.
        assert_eq!(inspect_preamble(&ok[..10]), Ok(None));
        assert_eq!(inspect_preamble(&ok[..ok.len() - 3]), Ok(None));
    }

    #[test]
    fn non_ssh_and_proxy_headers_are_refused() {
        assert!(inspect_preamble(b"GET / HTTP/1.1\r\n").is_err());
        assert!(inspect_preamble(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n").is_err());
        let mut v2 = PROXY_V2_SIG.to_vec();
        v2.extend_from_slice(&[0x21, 0x11, 0, 12]);
        assert!(inspect_preamble(&v2).is_err());
    }

    #[test]
    fn proxy_v2_parses_v4_v6_and_local() {
        let mut h = [0u8; 16];
        h[..12].copy_from_slice(&PROXY_V2_SIG);
        h[12] = 0x21;
        h[13] = 0x11;
        h[14..16].copy_from_slice(&12u16.to_be_bytes());
        let (cmd, fam, len) = parse_proxy_v2_head(&h).unwrap();
        let body = [203, 0, 113, 10, 10, 0, 0, 1, 0x30, 0x39, 0, 22];
        assert_eq!(len, 12);
        assert_eq!(
            parse_proxy_v2_body(cmd, fam, &body).unwrap(),
            ProxyHeader::Proxied {
                source: "203.0.113.10:12345".parse().unwrap()
            }
        );
        h[12] = 0x20;
        let (cmd, fam, _) = parse_proxy_v2_head(&h).unwrap();
        assert_eq!(
            parse_proxy_v2_body(cmd, fam, &[]).unwrap(),
            ProxyHeader::Local
        );
        let mut v1 = [0u8; 16];
        v1[..6].copy_from_slice(b"PROXY ");
        assert!(parse_proxy_v2_head(&v1).unwrap_err().contains("v1"));
        h[14..16].copy_from_slice(&4000u16.to_be_bytes());
        assert!(
            parse_proxy_v2_head(&h).is_err(),
            "oversized block refused before allocation"
        );
    }

    #[tokio::test]
    async fn the_guard_withholds_bytes_until_the_verdict() {
        use tokio::io::AsyncWriteExt;
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let mut guard = StrictKexGuard::new(server);
        let ok = kexinit("kex-strict-c-v00@openssh.com");
        client.write_all(&ok[..20]).await.unwrap();
        let read = tokio::time::timeout(std::time::Duration::from_millis(50), async {
            let mut b = [0u8; 8];
            guard.read(&mut b).await
        })
        .await;
        assert!(
            read.is_err(),
            "no byte may reach russh before the KEXINIT is inspected"
        );
        client.write_all(&ok[20..]).await.unwrap();
        let mut got = vec![0u8; ok.len()];
        guard.read_exact(&mut got).await.unwrap();
        assert_eq!(got, ok);

        let (mut client, server) = tokio::io::duplex(1 << 16);
        let mut guard = StrictKexGuard::new(server);
        client
            .write_all(&kexinit("curve25519-sha256"))
            .await
            .unwrap();
        let mut b = [0u8; 8];
        assert!(guard.read(&mut b).await.is_err());
    }
}
