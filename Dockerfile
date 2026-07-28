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
# Admin: /healthz, /readyz, /metrics. This image is distroless — there is no shell, so
# an `exec` probe is impossible and these endpoints are the only way to health-check a
# pod. Keep the port off the ingress: it is unauthenticated by design (a probe cannot
# sign SigV4).
EXPOSE 8016

# The gateway reads its JSON config from $GATEWAY_CONFIG; mount it at runtime,
# e.g. `-v /etc/s0-gas:/etc/s0-gas -e GATEWAY_CONFIG=/etc/s0-gas/gateway.json`.
# The config may reference ${VAR} / ${VAR:-default} from the environment. The audit
# spill path MUST be pod-unique (`audit-spill-${POD_NAME}.ndjson`, POD_NAME from the
# downward API) on node-local scratch: a spill volume shared between replicas is
# unsupported and loses records. Allow >45s of termination grace for the drain.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/s0"]
