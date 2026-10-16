# syntax=docker/dockerfile:1
#
# The Logos blockchain node at the revision LEZ v0.3.1 pins, with the devnet's config generator
# built alongside it in the node's own workspace. Build context: devnet/.

FROM rust:1-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang libclang-dev libssl-dev pkg-config cmake git \
    && rm -rf /var/lib/apt/lists/*

ARG LOGOS_BLOCKCHAIN_REV=3926a532b9d96d62747da064161a115a7c0c5a3e
WORKDIR /src
RUN git init -q . \
    && git remote add origin https://github.com/logos-blockchain/logos-blockchain.git \
    && git fetch -q --depth 1 origin "$LOGOS_BLOCKCHAIN_REV" \
    && git checkout -q FETCH_HEAD

COPY genesis/devnet_config.rs tools/blockchain-tools/src/bin/devnet_config.rs

# `testing` lets the node and the generator serialize KMS keys into configs.
RUN --mount=type=cache,id=uplink-devnet-blockchain-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=uplink-devnet-blockchain-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=uplink-devnet-blockchain-target,target=/src/target \
    cargo build --release \
        -p logos-blockchain-node --bin logos-blockchain-node \
        -p logos-blockchain-tools --bin devnet_config \
        --features logos-blockchain-node/testing \
    && cp target/release/logos-blockchain-node target/release/devnet_config /usr/local/bin/

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3t64 libstdc++6 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/logos-blockchain-node /usr/local/bin/devnet_config /usr/local/bin/

WORKDIR /data
ENV POL_PROOF_DEV_MODE=true
ENTRYPOINT ["logos-blockchain-node"]
