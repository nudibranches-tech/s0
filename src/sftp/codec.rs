//! The SFTP version 3 wire format (draft-ietf-secsh-filexfer-02), in-tree (ADR-009 D4).
//!
//! Pure functions over bytes: [`parse`] turns one packet body into a [`Request`], and
//! [`Response::encode`] turns a reply into a framed packet. Nothing here allocates on the
//! strength of a length field before checking it against the bytes actually present, and
//! nothing here decodes a path: paths stay `Vec<u8>` until `sftp::paths` validates them, so
//! two byte strings can never collapse onto one key (E7).
//!
//! Every malformed input is an error, never a partial parse: a string longer than the
//! bytes remaining, trailing bytes after the last field, a truncated integer. The caller
//! answers `SSH_FX_BAD_MESSAGE` when the request id could be read and then closes the
//! channel — the stream is never resynchronized.

use bytes::{BufMut, Bytes, BytesMut};

// ── packet types ──────────────────────────────────────────────────────────────
pub const SSH_FXP_INIT: u8 = 1;
pub const SSH_FXP_VERSION: u8 = 2;
pub const SSH_FXP_OPEN: u8 = 3;
pub const SSH_FXP_CLOSE: u8 = 4;
pub const SSH_FXP_READ: u8 = 5;
pub const SSH_FXP_WRITE: u8 = 6;
pub const SSH_FXP_LSTAT: u8 = 7;
pub const SSH_FXP_FSTAT: u8 = 8;
pub const SSH_FXP_SETSTAT: u8 = 9;
pub const SSH_FXP_FSETSTAT: u8 = 10;
pub const SSH_FXP_OPENDIR: u8 = 11;
pub const SSH_FXP_READDIR: u8 = 12;
pub const SSH_FXP_REMOVE: u8 = 13;
pub const SSH_FXP_MKDIR: u8 = 14;
pub const SSH_FXP_RMDIR: u8 = 15;
pub const SSH_FXP_REALPATH: u8 = 16;
pub const SSH_FXP_STAT: u8 = 17;
pub const SSH_FXP_RENAME: u8 = 18;
pub const SSH_FXP_READLINK: u8 = 19;
pub const SSH_FXP_SYMLINK: u8 = 20;
pub const SSH_FXP_STATUS: u8 = 101;
pub const SSH_FXP_HANDLE: u8 = 102;
pub const SSH_FXP_DATA: u8 = 103;
pub const SSH_FXP_NAME: u8 = 104;
pub const SSH_FXP_ATTRS: u8 = 105;
pub const SSH_FXP_EXTENDED: u8 = 200;
pub const SSH_FXP_EXTENDED_REPLY: u8 = 201;

// ── open flags ───────────────────────────────────────────────────────────────
pub const SSH_FXF_READ: u32 = 0x01;
pub const SSH_FXF_WRITE: u32 = 0x02;
pub const SSH_FXF_APPEND: u32 = 0x04;
pub const SSH_FXF_CREAT: u32 = 0x08;
pub const SSH_FXF_TRUNC: u32 = 0x10;
pub const SSH_FXF_EXCL: u32 = 0x20;

// ── attribute flags ──────────────────────────────────────────────────────────
pub const SSH_FILEXFER_ATTR_SIZE: u32 = 0x01;
pub const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x02;
pub const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x04;
pub const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x08;
pub const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x8000_0000;

/// The protocol version this server speaks, whatever the client offers above it.
pub const SFTP_VERSION: u32 = 3;

/// Upper bound on the extended-attribute pairs one ATTRS may carry. Clients send none;
/// the bound exists so a count field cannot drive a loop.
const MAX_EXTENDED_ATTRS: u32 = 64;

/// `SSH_FX_*` status codes (v3 defines 0–8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StatusCode {
    Ok = 0,
    Eof = 1,
    NoSuchFile = 2,
    PermissionDenied = 3,
    Failure = 4,
    BadMessage = 5,
    NoConnection = 6,
    ConnectionLost = 7,
    OpUnsupported = 8,
}

/// File attributes, as far as v3 can express them. Every field is optional on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attrs {
    pub size: Option<u64>,
    pub uid_gid: Option<(u32, u32)>,
    pub permissions: Option<u32>,
    pub atime_mtime: Option<(u32, u32)>,
    pub extended: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Attrs {
    /// True when no attribute was requested at all — the one SETSTAT that is answered OK
    /// (ADR-009 D11).
    pub fn is_empty(&self) -> bool {
        self.size.is_none()
            && self.uid_gid.is_none()
            && self.permissions.is_none()
            && self.atime_mtime.is_none()
            && self.extended.is_empty()
    }

    fn encode(&self, out: &mut BytesMut) {
        let mut flags = 0u32;
        if self.size.is_some() {
            flags |= SSH_FILEXFER_ATTR_SIZE;
        }
        if self.uid_gid.is_some() {
            flags |= SSH_FILEXFER_ATTR_UIDGID;
        }
        if self.permissions.is_some() {
            flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        }
        if self.atime_mtime.is_some() {
            flags |= SSH_FILEXFER_ATTR_ACMODTIME;
        }
        if !self.extended.is_empty() {
            flags |= SSH_FILEXFER_ATTR_EXTENDED;
        }
        out.put_u32(flags);
        if let Some(s) = self.size {
            out.put_u64(s);
        }
        if let Some((u, g)) = self.uid_gid {
            out.put_u32(u);
            out.put_u32(g);
        }
        if let Some(p) = self.permissions {
            out.put_u32(p);
        }
        if let Some((a, m)) = self.atime_mtime {
            out.put_u32(a);
            out.put_u32(m);
        }
        if !self.extended.is_empty() {
            out.put_u32(self.extended.len() as u32);
            for (k, v) in &self.extended {
                put_string(out, k);
                put_string(out, v);
            }
        }
    }
}

/// One parsed client request. Paths and handles are raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Init {
        version: u32,
    },
    Open {
        id: u32,
        path: Vec<u8>,
        pflags: u32,
        attrs: Attrs,
    },
    Close {
        id: u32,
        handle: Vec<u8>,
    },
    Read {
        id: u32,
        handle: Vec<u8>,
        offset: u64,
        len: u32,
    },
    Write {
        id: u32,
        handle: Vec<u8>,
        offset: u64,
        data: Bytes,
    },
    Lstat {
        id: u32,
        path: Vec<u8>,
    },
    Fstat {
        id: u32,
        handle: Vec<u8>,
    },
    Setstat {
        id: u32,
        path: Vec<u8>,
        attrs: Attrs,
    },
    Fsetstat {
        id: u32,
        handle: Vec<u8>,
        attrs: Attrs,
    },
    Opendir {
        id: u32,
        path: Vec<u8>,
    },
    Readdir {
        id: u32,
        handle: Vec<u8>,
    },
    Remove {
        id: u32,
        path: Vec<u8>,
    },
    Mkdir {
        id: u32,
        path: Vec<u8>,
        attrs: Attrs,
    },
    Rmdir {
        id: u32,
        path: Vec<u8>,
    },
    Realpath {
        id: u32,
        path: Vec<u8>,
    },
    Stat {
        id: u32,
        path: Vec<u8>,
    },
    Rename {
        id: u32,
        old: Vec<u8>,
        new: Vec<u8>,
    },
    Readlink {
        id: u32,
        path: Vec<u8>,
    },
    Symlink {
        id: u32,
        link: Vec<u8>,
        target: Vec<u8>,
    },
    /// `posix-rename@openssh.com`.
    PosixRename {
        id: u32,
        old: Vec<u8>,
        new: Vec<u8>,
    },
    /// `limits@openssh.com`.
    Limits {
        id: u32,
    },
    /// Any other `SSH_FXP_EXTENDED`. The payload is not parsed.
    Extended {
        id: u32,
        name: Vec<u8>,
    },
    /// A packet type outside the v3 request set. The id is the first four bytes when
    /// present, so the client still gets a status.
    Unknown {
        kind: u8,
        id: Option<u32>,
    },
}

impl Request {
    /// The request id, for the reply. `INIT` has none.
    pub fn id(&self) -> Option<u32> {
        use Request::*;
        match self {
            Init { .. } => None,
            Open { id, .. }
            | Close { id, .. }
            | Read { id, .. }
            | Write { id, .. }
            | Lstat { id, .. }
            | Fstat { id, .. }
            | Setstat { id, .. }
            | Fsetstat { id, .. }
            | Opendir { id, .. }
            | Readdir { id, .. }
            | Remove { id, .. }
            | Mkdir { id, .. }
            | Rmdir { id, .. }
            | Realpath { id, .. }
            | Stat { id, .. }
            | Rename { id, .. }
            | Readlink { id, .. }
            | Symlink { id, .. }
            | PosixRename { id, .. }
            | Limits { id }
            | Extended { id, .. } => Some(*id),
            Unknown { id, .. } => *id,
        }
    }

    /// The SFTP request name, as it rides in `input.request.method` and on the audit
    /// record.
    pub fn name(&self) -> &'static str {
        use Request::*;
        match self {
            Init { .. } => "INIT",
            Open { .. } => "OPEN",
            Close { .. } => "CLOSE",
            Read { .. } => "READ",
            Write { .. } => "WRITE",
            Lstat { .. } => "LSTAT",
            Fstat { .. } => "FSTAT",
            Setstat { .. } => "SETSTAT",
            Fsetstat { .. } => "FSETSTAT",
            Opendir { .. } => "OPENDIR",
            Readdir { .. } => "READDIR",
            Remove { .. } => "REMOVE",
            Mkdir { .. } => "MKDIR",
            Rmdir { .. } => "RMDIR",
            Realpath { .. } => "REALPATH",
            Stat { .. } => "STAT",
            Rename { .. } => "RENAME",
            Readlink { .. } => "READLINK",
            Symlink { .. } => "SYMLINK",
            PosixRename { .. } => "posix-rename@openssh.com",
            Limits { .. } => "limits@openssh.com",
            Extended { .. } => "EXTENDED",
            Unknown { .. } => "UNKNOWN",
        }
    }
}

/// Why a packet could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError {
    /// The request id, when the first four bytes after the type could be read — so the
    /// client gets `SSH_FX_BAD_MESSAGE` before the channel closes.
    pub id: Option<u32>,
    pub reason: &'static str,
}

/// A cursor over one packet body that refuses to read past the end.
struct Reader {
    buf: Bytes,
    pos: usize,
}

impl Reader {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        let b = *self.buf.get(self.pos).ok_or("truncated byte")?;
        self.pos += 1;
        Ok(b)
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        let s = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or("truncated uint32")?;
        self.pos += 4;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        let hi = u64::from(self.u32()?);
        let lo = u64::from(self.u32()?);
        Ok((hi << 32) | lo)
    }

    /// A length-prefixed string, bounded by the bytes actually remaining **before** any
    /// allocation.
    fn bytes(&mut self) -> Result<Bytes, &'static str> {
        let len = self.u32()? as usize;
        if len > self.remaining() {
            return Err("string length exceeds packet");
        }
        let b = self.buf.slice(self.pos..self.pos + len);
        self.pos += len;
        Ok(b)
    }

    fn vec(&mut self) -> Result<Vec<u8>, &'static str> {
        Ok(self.bytes()?.to_vec())
    }

    fn attrs(&mut self) -> Result<Attrs, &'static str> {
        let flags = self.u32()?;
        let known = SSH_FILEXFER_ATTR_SIZE
            | SSH_FILEXFER_ATTR_UIDGID
            | SSH_FILEXFER_ATTR_PERMISSIONS
            | SSH_FILEXFER_ATTR_ACMODTIME
            | SSH_FILEXFER_ATTR_EXTENDED;
        if flags & !known != 0 {
            return Err("unknown attribute flag");
        }
        let mut a = Attrs::default();
        if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
            a.size = Some(self.u64()?);
        }
        if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
            a.uid_gid = Some((self.u32()?, self.u32()?));
        }
        if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            a.permissions = Some(self.u32()?);
        }
        if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            a.atime_mtime = Some((self.u32()?, self.u32()?));
        }
        if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
            let count = self.u32()?;
            if count > MAX_EXTENDED_ATTRS {
                return Err("too many extended attributes");
            }
            for _ in 0..count {
                a.extended.push((self.vec()?, self.vec()?));
            }
        }
        Ok(a)
    }

    fn end(&self) -> Result<(), &'static str> {
        if self.remaining() != 0 {
            return Err("trailing bytes after the last field");
        }
        Ok(())
    }
}

/// Parse one packet body (the bytes after the 4-byte length: type, then fields).
///
/// The caller has already bounded the body by `max_sftp_packet_len`.
pub fn parse(body: Bytes) -> Result<Request, CodecError> {
    let mut r = Reader { buf: body, pos: 0 };
    let kind = r.u8().map_err(|reason| CodecError { id: None, reason })?;
    if kind == SSH_FXP_INIT {
        let version = r.u32().map_err(|reason| CodecError { id: None, reason })?;
        // Extension pairs may follow INIT; v3 servers ignore them. They are still parsed,
        // so a malformed tail is an error rather than an unread blob.
        while r.remaining() > 0 {
            r.bytes()
                .and_then(|_| r.bytes())
                .map_err(|reason| CodecError { id: None, reason })?;
        }
        return Ok(Request::Init { version });
    }
    let id = match r.u32() {
        Ok(id) => id,
        Err(reason) => return Err(CodecError { id: None, reason }),
    };
    let fail = |reason| CodecError {
        id: Some(id),
        reason,
    };
    let req = (|| -> Result<Request, &'static str> {
        let req = match kind {
            SSH_FXP_OPEN => Request::Open {
                id,
                path: r.vec()?,
                pflags: r.u32()?,
                attrs: r.attrs()?,
            },
            SSH_FXP_CLOSE => Request::Close {
                id,
                handle: r.vec()?,
            },
            SSH_FXP_READ => Request::Read {
                id,
                handle: r.vec()?,
                offset: r.u64()?,
                len: r.u32()?,
            },
            SSH_FXP_WRITE => Request::Write {
                id,
                handle: r.vec()?,
                offset: r.u64()?,
                data: r.bytes()?,
            },
            SSH_FXP_LSTAT => Request::Lstat { id, path: r.vec()? },
            SSH_FXP_FSTAT => Request::Fstat {
                id,
                handle: r.vec()?,
            },
            SSH_FXP_SETSTAT => Request::Setstat {
                id,
                path: r.vec()?,
                attrs: r.attrs()?,
            },
            SSH_FXP_FSETSTAT => Request::Fsetstat {
                id,
                handle: r.vec()?,
                attrs: r.attrs()?,
            },
            SSH_FXP_OPENDIR => Request::Opendir { id, path: r.vec()? },
            SSH_FXP_READDIR => Request::Readdir {
                id,
                handle: r.vec()?,
            },
            SSH_FXP_REMOVE => Request::Remove { id, path: r.vec()? },
            SSH_FXP_MKDIR => Request::Mkdir {
                id,
                path: r.vec()?,
                attrs: r.attrs()?,
            },
            SSH_FXP_RMDIR => Request::Rmdir { id, path: r.vec()? },
            SSH_FXP_REALPATH => Request::Realpath { id, path: r.vec()? },
            SSH_FXP_STAT => Request::Stat { id, path: r.vec()? },
            SSH_FXP_RENAME => Request::Rename {
                id,
                old: r.vec()?,
                new: r.vec()?,
            },
            SSH_FXP_READLINK => Request::Readlink { id, path: r.vec()? },
            SSH_FXP_SYMLINK => Request::Symlink {
                id,
                link: r.vec()?,
                target: r.vec()?,
            },
            SSH_FXP_EXTENDED => {
                let name = r.vec()?;
                match name.as_slice() {
                    b"posix-rename@openssh.com" => Request::PosixRename {
                        id,
                        old: r.vec()?,
                        new: r.vec()?,
                    },
                    b"limits@openssh.com" => Request::Limits { id },
                    _ => {
                        // Unparsed payload: consumed, not interpreted.
                        r.pos = r.buf.len();
                        Request::Extended { id, name }
                    }
                }
            }
            other => {
                r.pos = r.buf.len();
                Request::Unknown {
                    kind: other,
                    id: Some(id),
                }
            }
        };
        r.end()?;
        Ok(req)
    })()
    .map_err(fail)?;
    Ok(req)
}

/// One directory entry in a NAME reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameEntry {
    pub filename: Vec<u8>,
    pub longname: Vec<u8>,
    pub attrs: Attrs,
}

/// A server reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Version {
        extensions: Vec<(&'static str, &'static str)>,
    },
    Status {
        id: u32,
        code: StatusCode,
        message: String,
    },
    Handle {
        id: u32,
        handle: Vec<u8>,
    },
    Data {
        id: u32,
        data: Bytes,
    },
    Name {
        id: u32,
        entries: Vec<NameEntry>,
    },
    Attrs {
        id: u32,
        attrs: Attrs,
    },
    ExtendedReply {
        id: u32,
        data: Vec<u8>,
    },
}

impl Response {
    pub fn status(id: u32, code: StatusCode, message: impl Into<String>) -> Self {
        Response::Status {
            id,
            code,
            message: message.into(),
        }
    }

    pub fn ok(id: u32) -> Self {
        Response::status(id, StatusCode::Ok, "")
    }

    /// The framed packet: `uint32 length || type || fields`.
    pub fn encode(&self) -> Bytes {
        let mut body = BytesMut::new();
        match self {
            Response::Version { extensions } => {
                body.put_u8(SSH_FXP_VERSION);
                body.put_u32(SFTP_VERSION);
                for (name, data) in extensions {
                    put_string(&mut body, name.as_bytes());
                    put_string(&mut body, data.as_bytes());
                }
            }
            Response::Status { id, code, message } => {
                body.put_u8(SSH_FXP_STATUS);
                body.put_u32(*id);
                body.put_u32(*code as u32);
                put_string(&mut body, message.as_bytes());
                put_string(&mut body, b"en");
            }
            Response::Handle { id, handle } => {
                body.put_u8(SSH_FXP_HANDLE);
                body.put_u32(*id);
                put_string(&mut body, handle);
            }
            Response::Data { id, data } => {
                body.put_u8(SSH_FXP_DATA);
                body.put_u32(*id);
                put_string(&mut body, data);
            }
            Response::Name { id, entries } => {
                body.put_u8(SSH_FXP_NAME);
                body.put_u32(*id);
                body.put_u32(entries.len() as u32);
                for e in entries {
                    put_string(&mut body, &e.filename);
                    put_string(&mut body, &e.longname);
                    e.attrs.encode(&mut body);
                }
            }
            Response::Attrs { id, attrs } => {
                body.put_u8(SSH_FXP_ATTRS);
                body.put_u32(*id);
                attrs.encode(&mut body);
            }
            Response::ExtendedReply { id, data } => {
                body.put_u8(SSH_FXP_EXTENDED_REPLY);
                body.put_u32(*id);
                body.put_slice(data);
            }
        }
        let mut out = BytesMut::with_capacity(4 + body.len());
        out.put_u32(body.len() as u32);
        out.put_slice(&body);
        out.freeze()
    }
}

fn put_string(out: &mut BytesMut, s: &[u8]) {
    out.put_u32(s.len() as u32);
    out.put_slice(s);
}

/// The `limits@openssh.com` reply body: max packet, max read, max write, max open handles.
pub fn limits_reply(max_packet: u64, max_read: u64, max_write: u64, max_handles: u64) -> Vec<u8> {
    let mut b = BytesMut::new();
    b.put_u64(max_packet);
    b.put_u64(max_read);
    b.put_u64(max_write);
    b.put_u64(max_handles);
    b.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(kind: u8, f: impl FnOnce(&mut BytesMut)) -> Bytes {
        let mut b = BytesMut::new();
        b.put_u8(kind);
        f(&mut b);
        b.freeze()
    }

    #[test]
    fn open_parses_path_as_raw_bytes() {
        let body = pkt(SSH_FXP_OPEN, |b| {
            b.put_u32(7);
            put_string(b, b"/a/\xff");
            b.put_u32(SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC);
            b.put_u32(SSH_FILEXFER_ATTR_PERMISSIONS);
            b.put_u32(0o644);
        });
        let r = parse(body).unwrap();
        assert_eq!(
            r,
            Request::Open {
                id: 7,
                path: b"/a/\xff".to_vec(),
                pflags: SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC,
                attrs: Attrs {
                    permissions: Some(0o644),
                    ..Attrs::default()
                }
            },
            "a non-UTF-8 path must survive as bytes, never lossily decoded"
        );
    }

    #[test]
    fn a_string_longer_than_the_packet_is_an_error_with_the_id() {
        let body = pkt(SSH_FXP_STAT, |b| {
            b.put_u32(9);
            b.put_u32(1_000_000);
            b.put_slice(b"abc");
        });
        let e = parse(body).unwrap_err();
        assert_eq!(e.id, Some(9));
        assert_eq!(e.reason, "string length exceeds packet");
    }

    #[test]
    fn trailing_bytes_are_an_error() {
        let body = pkt(SSH_FXP_STAT, |b| {
            b.put_u32(1);
            put_string(b, b"/x");
            b.put_u8(0);
        });
        assert_eq!(
            parse(body).unwrap_err().reason,
            "trailing bytes after the last field"
        );
    }

    #[test]
    fn a_truncated_id_has_no_id() {
        let body = pkt(SSH_FXP_STAT, |b| b.put_u16(1));
        assert_eq!(parse(body).unwrap_err().id, None);
    }

    #[test]
    fn unknown_attribute_flags_are_refused() {
        let body = pkt(SSH_FXP_SETSTAT, |b| {
            b.put_u32(3);
            put_string(b, b"/x");
            b.put_u32(0x40);
        });
        assert_eq!(parse(body).unwrap_err().reason, "unknown attribute flag");
    }

    #[test]
    fn an_extended_attribute_count_cannot_drive_a_loop() {
        let body = pkt(SSH_FXP_SETSTAT, |b| {
            b.put_u32(3);
            put_string(b, b"/x");
            b.put_u32(SSH_FILEXFER_ATTR_EXTENDED);
            b.put_u32(u32::MAX);
        });
        assert_eq!(
            parse(body).unwrap_err().reason,
            "too many extended attributes"
        );
    }

    #[test]
    fn extended_requests_are_recognized_by_exact_name() {
        let body = pkt(SSH_FXP_EXTENDED, |b| {
            b.put_u32(4);
            put_string(b, b"posix-rename@openssh.com");
            put_string(b, b"/a");
            put_string(b, b"/b");
        });
        assert!(matches!(
            parse(body).unwrap(),
            Request::PosixRename { id: 4, .. }
        ));
        let body = pkt(SSH_FXP_EXTENDED, |b| {
            b.put_u32(5);
            put_string(b, b"statvfs@openssh.com");
            put_string(b, b"/");
        });
        assert_eq!(
            parse(body).unwrap(),
            Request::Extended {
                id: 5,
                name: b"statvfs@openssh.com".to_vec()
            }
        );
    }

    #[test]
    fn an_unknown_packet_type_keeps_its_id() {
        let body = pkt(42, |b| b.put_u32(77));
        assert_eq!(
            parse(body).unwrap(),
            Request::Unknown {
                kind: 42,
                id: Some(77)
            }
        );
    }

    #[test]
    fn write_data_is_a_zero_copy_slice() {
        let body = pkt(SSH_FXP_WRITE, |b| {
            b.put_u32(1);
            put_string(b, b"h1");
            b.put_u64(1 << 33);
            put_string(b, b"payload");
        });
        let Request::Write { offset, data, .. } = parse(body).unwrap() else {
            panic!()
        };
        assert_eq!(offset, 1 << 33);
        assert_eq!(&data[..], b"payload");
    }

    #[test]
    fn status_encodes_with_language_tag() {
        let p = Response::status(3, StatusCode::PermissionDenied, "no").encode();
        assert_eq!(
            u32::from_be_bytes(p[0..4].try_into().unwrap()) as usize,
            p.len() - 4
        );
        assert_eq!(p[4], SSH_FXP_STATUS);
        assert_eq!(&p[p.len() - 2..], b"en");
    }

    #[test]
    fn attrs_round_trip_through_name() {
        let a = Attrs {
            size: Some(10),
            permissions: Some(0o100640),
            atime_mtime: Some((1, 2)),
            ..Attrs::default()
        };
        let mut b = BytesMut::new();
        a.encode(&mut b);
        let mut r = Reader {
            buf: b.freeze(),
            pos: 0,
        };
        assert_eq!(r.attrs().unwrap(), a);
        assert!(r.end().is_ok());
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // A tiny deterministic fuzz pass; the cargo-fuzz target `sftp_codec`
        // (fuzz/fuzz_targets/sftp_codec.rs) runs the same function, unbiased, in CI.
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..20_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 64) as usize;
            let mut v = Vec::with_capacity(len);
            let mut s = seed;
            for _ in 0..len {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                v.push((s >> 56) as u8);
            }
            if let Some(first) = v.first_mut() {
                *first %= 21;
            }
            let _ = parse(Bytes::from(v));
        }
    }
}
