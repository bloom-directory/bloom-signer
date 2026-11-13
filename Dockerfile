# Bloom Signer container image.
#
# Build:  docker build -t bloom-signer .
# Run:    the process is a Unix-socket service; mount its config, identity and
#         durable state (see the paths documented near the runtime stage).

# --- build ------------------------------------------------------------------
FROM rust:1.96.0-bookworm AS builder

# rust-toolchain.toml pins the `stable` channel, which would make rustup pull
# whatever stable is current at build time. RUSTUP_TOOLCHAIN overrides the file
# so the image's pinned 1.96.0 is what actually compiles the binary.
ENV RUSTUP_TOOLCHAIN=1.96.0 \
    CARGO_TERM_COLOR=never \
    CARGO_INCREMENTAL=0

WORKDIR /src

# Dependency layer: manifests plus placeholder targets are enough for cargo to
# resolve and download the registry and git dependencies (the git deps on
# bloom-service-runtime need the `git` that this base image already carries).
# This layer is reused until a Cargo.toml or Cargo.lock actually changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/bloom-signer-api/Cargo.toml crates/bloom-signer-api/Cargo.toml
COPY crates/bloom-signer-backend-api/Cargo.toml crates/bloom-signer-backend-api/Cargo.toml
COPY crates/bloom-signer-backend-local/Cargo.toml crates/bloom-signer-backend-local/Cargo.toml
COPY crates/bloom-signer-backend-aws-kms/Cargo.toml crates/bloom-signer-backend-aws-kms/Cargo.toml
COPY crates/bloom-signer/Cargo.toml crates/bloom-signer/Cargo.toml
RUN set -eux; \
    for crate in bloom-signer-api bloom-signer-backend-api bloom-signer-backend-local \
                 bloom-signer-backend-aws-kms bloom-signer; do \
        mkdir -p "crates/$crate/src"; \
        : > "crates/$crate/src/lib.rs"; \
    done; \
    : > crates/bloom-signer/src/main.rs; \
    cargo fetch --locked

# Real sources. The placeholder tree is dropped first so no stub file can
# survive into the compiled artifact.
RUN rm -rf crates
COPY crates crates

# Default features (`local`); the aws-kms backend is deliberately not built, so
# the artifact carries no AWS SDK and no aws-lc/OpenSSL native code. --offline
# proves the build consumed only what the cached fetch layer resolved.
RUN cargo build --release --locked --offline --package bloom-signer

# --- runtime ----------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# `ldd` on the release binary resolves only ld-linux, libc, libm and libgcc_s,
# all of which ship in debian:bookworm-slim: SQLite is statically linked via
# rusqlite's `bundled` feature and the default feature set opens no outbound
# TLS. No apt packages are therefore installed — not even ca-certificates.

# The Signer's audit checkpoint store and legacy-migration store are opened
# against the effective uid declared in the edge manifest, so this uid/gid must
# match `signer.effective_uid` in the manifest you mount. Override at build
# time when your deployment allocates a different id.
ARG SIGNER_UID=10001
ARG SIGNER_GID=10001

# /etc/bloom stays root-owned: authority-edge-history.json is only trusted when
# root owns it, while signer.json must be a mode 0600-or-stricter regular file
# owned by the service uid.
RUN set -eux; \
    groupadd --system --gid "${SIGNER_GID}" bloom; \
    useradd --system --uid "${SIGNER_UID}" --gid "${SIGNER_GID}" \
        --home-dir /var/lib/bloom --shell /usr/sbin/nologin bloom; \
    install -d -o root -g root -m 0755 /etc/bloom; \
    install -d -o bloom -g bloom -m 0700 \
        /var/lib/bloom \
        /var/db/bloom \
        /var/db/bloom/signer \
        /var/run/bloom

COPY --from=builder /src/target/release/bloom-signer /usr/local/bin/bloom-signer
COPY --from=builder /src/target/release/bloom-signer-migrate /usr/local/bin/bloom-signer-migrate

# Socket paths have no built-in default and are required at startup; the rest
# of the service paths default to the values created above. /var/run is tmpfs
# on many hosts, so mount or recreate /var/run/bloom owned by this uid.
ENV BLOOM_SIGNER_SOCKET=/var/run/bloom/signer.sock \
    BLOOM_SIGNER_CONTROL_SOCKET=/var/run/bloom/signer-control.sock

USER bloom:bloom
WORKDIR /var/lib/bloom

ENTRYPOINT ["/usr/local/bin/bloom-signer"]
