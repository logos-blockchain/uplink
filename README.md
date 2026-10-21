# Uplink

The node referral program for the Logos Execution Zone (LEZ).

Nodes register under the node that referred them. Each epoch an oracle publishes which nodes were
active, and every participant earns a point for each active node it referred directly. Points earned
lower in the tree are forwarded upward as credits. A participant can cash its points out into a
public receipt that only it can link to its node.

## Epochs and claims

Each publication is archived when it is published: the epoch's active-set digest is written once to
its own account, `epoch_account(uplink_account, epoch)`, and never changes. That account's id is
predictable, so the archive overwrites anything a caller created in it first. Epochs are numbered
consecutively from 1: each publication must be of the epoch after the last, so no epoch is skipped
and none is published twice, and the oracle cannot correct a publication.

A claim settles one or more published epochs in increasing order, each against its archived
publication, so a participant that claims late is still paid for every epoch it was active in. In
each epoch it earns the credits earned in it, and settles the epoch for every child not yet settled
for it, earning a point for each of those active in it. The total is forwarded to its referrer if
the referrer was active in that epoch. A participant keeps, per child, the epochs settled for it as
merged ranges, so epochs can be claimed in any order and none pays a child twice.

A node registers under its referrer with the referrer's invitation: the referrer's node, and the keys
its children address their notes to, signed by the referrer's node key. Registration checks that
signature, so an invitation cannot be altered or forged to send a node's notes to keys it does not
hold.

Registration records the registry's current epoch, and a child counts from the epoch it registered
in: the epochs before it count as settled. Since every child registers after its referrer, nobody
earns anything for an epoch before they registered. The wallet adopts an announced child in the
first epoch it claims that the child is active in: until then the child pays nothing, and adopting it
later still pays every epoch it was active in. The wallet reads past active sets from the
indexer and checks each against its archived digest, claims epochs oldest first, and batches a
catch-up into claims of at most 16 epochs and 2,048 active-set entries, about 2,200 guest cycles
each.

## The oracle

The oracle publishes the blend network's membership. `uplink oracle --node <URL>` runs alongside a
Logos blockchain node, reads its SDP snapshot, the Blend declarations active in the current chain
epoch, and publishes their providers as the next epoch's active nodes. Each node is named by its
Ed25519 provider key, the same key that signs its registration. Uplink's epochs are its own and need
not match the chain's: each chain epoch the oracle publishes becomes the next Uplink epoch.

A chain epoch is published only once the node's last irreversible block is inside it: the ledger
fixes an epoch's snapshot when the epoch begins, so from then on no reorg can change it. The oracle
checks the node every few seconds and publishes each chain epoch once, recording it before sending
so a restart does not publish it again; a publication that is not included is sent again after a
minute, and the chain rejects any publication but the next epoch. A chain epoch the oracle misses
is not published, but no Uplink epoch is skipped. `--once` checks a single time and exits.

```sh
uplink --program <ID> oracle --node http://localhost:8080
```

## Devnet

`devnet/` runs the whole flow locally: four blockchain nodes with no blend nodes at genesis, a LEZ
sequencer and indexer, the oracle, recipes for each operator action, and a terminal dashboard. See
[devnet/README.md](devnet/README.md).

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

Tests always run with `RISC0_DEV_MODE=1`, so they execute the guest without proving. Each end-to-end
test runs its own Bedrock node, sequencer and indexer; run them with `-- --test-threads=1` on a
machine that cannot run all of them at once, or the tests that read history back from the indexer
can time out waiting for it.

## Wallet state

`uplink_wallet` uses the user's LEZ wallet for keys, accounts and sync, and keeps its own state in
`referral.json` next to the wallet's storage: pending registrations, invitations, submitted operations
and the past publications it has read from the indexer. It never stores a receipt secret.

## Cash-out receipts

A cash-out burns the participant's whole balance into a public receipt account that only the node's
operator can link to the node. The link is a blinding factor derived from a receipt secret, which the
operator derives once from the node's Ed25519 secret key (its 32-byte seed) and hands to the
participant's wallet:

```text
receipt_secret     = SHA256("Uplink/ReceiptSecret/v1\0"  || node_secret)
blinding_factor(i) = SHA256("Uplink/BlindingFactor/v1\0" || receipt_secret
                            || uplink_account || participant || i as 8 little-endian bytes)
receipt(i)         = public PDA of uplink_account with seed
                     SHA256("Uplink/CashOut/v1\0" || node || blinding_factor(i))
```

The tags end in a zero byte, and every account and node is its 32 raw bytes. The program sees only
the blinding factor; neither secret leaves the operator and the wallet. To be paid, a holder reveals a
receipt's opening: the node and its blinding factor. After losing a device, the operator derives the
receipt secret again from the node key, and the wallet finds every receipt from it and the chain.

```sh
uplink derive-receipt-secret --node-key-file node.key --out receipt.secret
uplink --program <ID> cash-out --participant <ID> --receipt-secret-file receipt.secret
```

`referral_core::blinding_factor` and `uplink_wallet::receipt_secret` pin both derivations with test
vectors.
