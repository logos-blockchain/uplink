# Uplink

The node referral program for the Logos Execution Zone (LEZ).

Nodes register under the node that referred them. Each epoch an oracle publishes which nodes were
active, and every participant earns a point for each active node it referred directly. Points earned
lower in the tree are forwarded upward as credits. A participant can cash its points out into a
public receipt that only it can link to its node.

## Layout

| Path | Crate | What it holds |
|---|---|---|
| `programs/referral/core` | `referral_core` | Contract types and reward logic, shared by the program and the wallet |
| `programs/referral` | `referral_program` | The program's `plan` and `apply`, and their unit tests |
| `programs/referral/methods` | `referral_methods` | The guest entry point, and the built binary packed as a `Program` |
| `artifacts/programs/referral` | | The reproducibly built guest binary |
| `wallet` | `uplink_wallet` | Building and submitting referral operations through the LEZ wallet |
| `integration_tests` | `uplink_integration_tests` | End-to-end tests through real wallets |

LEZ crates are pinned to one release (`v0.3.1`) in the workspace `Cargo.toml`. Every LEZ crate must
come from the same tag.

## Building

The guest binary is committed, so a normal build does not need Docker. After changing the program or
its dependencies, rebuild it:

```sh
just build-artifacts
```

## Testing

```sh
just test-unit             # program, core and wallet unit tests
just resolve-bedrock-node  # once per LEZ version: the end-to-end tests run a Bedrock node in Docker
just test                  # everything, including the end-to-end tests
```

Tests always run with `RISC0_DEV_MODE=1`, so they execute the guest without proving.

## Wallet state

`uplink_wallet` uses the user's LEZ wallet for keys, accounts and sync, and keeps its own state in
`referral.json` next to the wallet's storage: pending registrations, invitations, submitted operations
and the past publications it has read from the indexer.
