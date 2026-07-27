# syntax=docker/dockerfile:1

# ---- Build stage -------------------------------------------------------------
FROM rust:1.94-bookworm AS builder

WORKDIR /build

# Copy the full tree and build a release binary with a locked dependency graph.
# The cache mounts keep the registry and target dir warm across rebuilds.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked --bin s0 && \
    cp target/release/s0 /usr/local/bin/s0

# ---- Runtime stage -----------------------------------------------------------
# distroless "cc" carries glibc + libgcc for the dynamically linked gnu binary.
# The `:nonroot` tag runs as uid/gid 65532 by default.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /usr/local/bin/s0 /usr/local/bin/s0

# S3 data-plane listener (and the STS mint listener, when configured).
EXPOSE 8014
EXPOSE 8015

# The gateway reads its JSON config from $GATEWAY_CONFIG; mount it at runtime,
# e.g. `-v /etc/s0-gas:/etc/s0-gas -e GATEWAY_CONFIG=/etc/s0-gas/gateway.json`.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/s0"]
