# OPNsense MCP server container image
#
# Multi-stage build producing a distroless image with no shell and no external
# binaries. The runtime has no package manager, no shell, and no GNU userland —
# only libc and the statically-linked server binary.
#
# Builder glibc generation must be <= runtime generation: Debian 13 (trixie) on
# both sides satisfies this. Building on a newer base (Debian 14+) would link
# against a newer glibc that the Debian 13 runtime does not carry.

# Builder stage: Debian 13 slim with Rust 1.98.1, matching rust-toolchain.toml.
#
# Not yet digest-pinned (sibling servers pin `FROM ... @sha256:...`): this
# environment has no registry access to resolve the current amd64 digest.
# Pin it in a follow-up before this ships.
FROM rust:1.98.1-slim-trixie AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy workspace manifests first for better layer caching.
COPY Cargo.toml Cargo.lock ./
COPY rustopnsmcp/Cargo.toml rustopnsmcp/
COPY rustopnsmcp-core/Cargo.toml rustopnsmcp-core/

# Create stub sources to cache dependencies.
RUN mkdir -p rustopnsmcp/src rustopnsmcp-core/src && \
    echo 'fn main() {}' > rustopnsmcp/src/main.rs && \
    echo '' > rustopnsmcp-core/src/lib.rs && \
    cargo build --release && \
    rm -rf rustopnsmcp/src rustopnsmcp-core/src

# Copy source and build the real binary.
COPY rustopnsmcp/ rustopnsmcp/
COPY rustopnsmcp-core/ rustopnsmcp-core/
RUN touch rustopnsmcp/src/main.rs rustopnsmcp-core/src/lib.rs && \
    cargo build --release --locked

# Runtime stage: distroless Debian 13 with nonroot user. Not yet
# digest-pinned; see the note on the builder stage above.
FROM gcr.io/distroless/cc-debian13:nonroot

USER 65532:65532

# No HEALTHCHECK: distroless has no shell and no utilities, so there is
# nothing for a healthcheck command to run. Orchestrators supervise the
# process via the container runtime.

COPY --from=builder /build/target/release/rustopnsmcp /usr/local/bin/rustopnsmcp

LABEL org.opencontainers.image.title="rustopnsmcp"
LABEL org.opencontainers.image.description="OPNsense MCP server"
LABEL org.opencontainers.image.source="https://github.com/fastrevmd-lab/rustopnsmcp"
LABEL org.opencontainers.image.licenses="MIT"

# ENTRYPOINT carries what must always hold: config paths and anything
# security-relevant. CMD carries only what an operator is expected to
# replace: bind address, port, and mode flags. Docker replaces CMD when the
# caller supplies arguments, so security-relevant defaults must stay in
# ENTRYPOINT.
ENTRYPOINT ["/usr/local/bin/rustopnsmcp", \
    "--device-mapping", "/etc/rustopnsmcp/devices.json", \
    "--tokens-file", "/var/lib/rustopnsmcp/tokens.json"]
CMD ["--transport", "streamable-http", \
    "--host", "127.0.0.1", \
    "--port", "30037"]
