# syntax=docker/dockerfile:1
#
# The LEZ sequencer and indexer at the release uplink pins, built with in-process guest execution
# so neither needs r0vm. They run with RISC0_DEV_MODE=1, executing guests without proving.

FROM rust:1-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang libclang-dev libssl-dev pkg-config cmake ninja-build git \
    && rm -rf /var/lib/apt/lists/*

ARG LEZ_TAG=v0.3.1
WORKDIR /src
RUN git clone -q --depth 1 --branch "$LEZ_TAG" \
    https://github.com/logos-blockchain/logos-execution-zone.git .

RUN --mount=type=cache,id=uplink-devnet-lez-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=uplink-devnet-lez-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=uplink-devnet-lez-target,target=/src/target \
    cargo build --release \
        -p sequencer_service --bin sequencer_service \
        -p indexer_service --bin indexer_service \
        --features sequencer_service/prove,indexer_service/prove \
    && cp target/release/sequencer_service target/release/indexer_service /usr/local/bin/

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3t64 libstdc++6 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/sequencer_service /usr/local/bin/indexer_service /usr/local/bin/

ENV RISC0_DEV_MODE=1 RUST_LOG=info
