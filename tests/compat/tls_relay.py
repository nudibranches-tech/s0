"""A TLS terminator for the Garage compat leg: accepts TLS on LISTEN and relays the bytes,
unchanged, to Garage's plain-HTTP S3 port. Garage terminates no TLS itself, and a real
deployment puts a proxy in front of it; this is that proxy, in the standard library.

It matters for more than realism: an SDK signs aws-chunked trailers only over plain HTTP,
and Garage v2.4.1 verifies such a signed trailer against a non-standard string to sign, so
over HTTP every trailer upload fails at Garage whoever sends it. Over TLS the SDK sends the
unsigned trailer form, which Garage reads correctly.

Usage: tls_relay.py <listen-port> <upstream-port> <cert.pem> <key.pem>"""

import socket
import ssl
import sys
import threading

LISTEN_PORT, UPSTREAM_PORT, CERT, KEY = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def serve(raw):
    try:
        client = ctx.wrap_socket(raw, server_side=True)
    except (ssl.SSLError, OSError):
        raw.close()
        return
    try:
        upstream = socket.create_connection(("127.0.0.1", UPSTREAM_PORT), timeout=10)
        upstream.settimeout(None)
    except OSError:
        client.close()
        return
    threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
    pipe(upstream, client)


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", LISTEN_PORT))
listener.listen(64)
while True:
    raw, _ = listener.accept()
    threading.Thread(target=serve, args=(raw,), daemon=True).start()
