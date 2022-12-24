# syntax = docker/dockerfile:1.4

FROM rust:1.66.0-slim-bullseye AS builder

WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/app/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/rustup \
    set -eux; \
    rustup install stable; \
    cargo build --release; \
    objcopy --compress-debug-sections target/release/fedito ./fedito

FROM debian:bullseye-slim
RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt update; \
    apt clean autoclean; \
    apt autoremove --yes; \
    rm -rf /var/lib/{apt,dpkg,cache,log}/
WORKDIR app
RUN set -eux; \
    mkdir -p dist assets
COPY --from=builder /app/fedito ./fedito
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/assets ./assets
CMD ["./fedito"]
