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

# Four listeners with three different authentication postures. Which posture applies is a
# property of the socket, never of the path, so they are four ports on purpose and
# `GatewayConfig::validate` refuses a config where any two collide. EXPOSE is
# documentation only — it neither publishes nor firewalls anything.

# S3 data plane: SigV4, per-request authorization. Ingress-fronted.
EXPOSE 8014

# STS mint: AssumeRoleWithWebIdentity. Unauthenticated by design — a valid web identity
# token IS the credential, as at sts.amazonaws.com. Absent unless configured; give it its
# own hostname when it is.
EXPOSE 8015

# Admin: /healthz, /readyz, /metrics. Unauthenticated by construction — a kubelet probe
# cannot present a secret. This image is distroless, so there is no shell and an `exec`
# probe is impossible: these endpoints are the only way to health-check a pod. Keep the
# port off the ingress.
EXPOSE 8016

# Internal control-plane surface: POST /internal/v1/sts/sessions and
# /internal/v1/derived-keys, guarded by a constant-time X-Shared-Secret. Absent unless
# `internal` is configured, and an empty secret refuses every request. Never the ingress,
# never the data plane — fence it with a NetworkPolicy; the secret is the second line.
EXPOSE 8017

# The gateway reads its JSON config from $GATEWAY_CONFIG; mount it at runtime,
# e.g. `-v /etc/s0:/etc/s0 -e GATEWAY_CONFIG=/etc/s0/gateway.json`.
# The config may reference ${VAR} / ${VAR:-default} from the environment. The audit
# spill path MUST be pod-unique (`audit-spill-${POD_NAME}.ndjson`, POD_NAME from the
# downward API) on node-local scratch: a spill volume shared between replicas is
# unsupported and loses records. Allow >45s of termination grace for the drain.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/s0"]
