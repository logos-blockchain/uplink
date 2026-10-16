# syntax=docker/dockerfile:1
#
# The `uplink` command line, which the devnet runs as its oracle. Build context: the repository.

FROM rust:1-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang libclang-dev libssl-dev libpcsclite-dev pkg-config cmake ninja-build git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# The referral guest is committed under artifacts/, so nothing here builds it.
RUN --mount=type=cache,id=uplink-devnet-uplink-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=uplink-devnet-uplink-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=uplink-devnet-uplink-target,target=/src/target \
    cargo build --release -p uplink --bin uplink \
    && cp target/release/uplink /usr/local/bin/

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3t64 libstdc++6 libpcsclite1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/uplink /usr/local/bin/

ENV RISC0_DEV_MODE=1
ENTRYPOINT ["uplink"]
