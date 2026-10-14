# Same container LEZ builds its guests with, so the referral binary is reproducible.
RISC0_DOCKER_CONTAINER_TAG := "r0.1.91.1"

# Build the referral guest in Docker and commit the result under artifacts/.
build-artifacts:
    @echo "Building the referral guest"
    @rm -rf target/programs/referral/methods/riscv32im-risc0-zkvm-elf/docker/*.bin
    RISC0_DOCKER_CONTAINER_TAG={{RISC0_DOCKER_CONTAINER_TAG}} CARGO_TARGET_DIR=target/programs/referral/methods cargo risczero build --no-default-features --features guest --manifest-path programs/referral/methods/Cargo.toml
    @mkdir -p artifacts/programs/referral
    @cp target/programs/referral/methods/riscv32im-risc0-zkvm-elf/docker/*.bin artifacts/programs/referral/

# Print where Cargo checked out the pinned LEZ release.
lez-checkout:
    @cargo metadata --format-version 1 | python3 -c 'import json, os, sys; print(next(os.path.dirname(os.path.dirname(p["manifest_path"])) for p in json.load(sys.stdin)["packages"] if p["name"] == "test_fixtures"))'

# LEZ's test harness runs a Bedrock node it expects inside its own checkout, so resolve it there.
resolve-bedrock-node:
    bash "$(just lez-checkout)/bedrock/tools/resolve_bedrock_node_in_docker.sh"

# Clippy cannot build the guest, so it skips it and uses the committed artifact.
clippy:
    RISC0_SKIP_BUILD=1 cargo clippy --workspace --all-targets

# Unit tests only.
test-unit:
    RISC0_DEV_MODE=1 cargo test --workspace --exclude uplink_integration_tests

# Everything, including the end-to-end tests, which need Docker and `just resolve-bedrock-node`.
test:
    RISC0_DEV_MODE=1 cargo test --workspace

# Format with the same nightly rustfmt LEZ uses; rustfmt.toml needs unstable options.
fmt:
    cargo +nightly-2026-10-08 fmt --all
