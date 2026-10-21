# Uplink devnet

A local network to try the whole uplink flow on: four Logos blockchain nodes, a LEZ sequencer and
indexer on node-0, and the uplink oracle, all in Docker. Each node's operator acts through
`just devnet` recipes from the host, and `just devnet dashboard` shows what the chains hold.

| Service | What it is | Host port |
|---|---|---|
| `node-0` … `node-3` | Logos blockchain nodes, at the revision LEZ v0.3.1 pins | 18080 … 18083 (HTTP API) |
| `sequencer` | LEZ sequencer; creates the LEZ channel on node-0 | 3040 |
| `indexer` | LEZ indexer, reading the channel from node-0 | 8779 |
| `oracle` | `uplink oracle`, publishing node-0's blend membership each epoch | |

## Chain parameters

- Security parameter `k = 2`, with a slot activation coefficient of 1/2 and 1 s slots, so an epoch
  is 40 slots, 40 seconds, and a block is final two blocks deep.
- **Node 0 holds 99% of the stake** (`devnet_config --node-0-stake-percent`), so it proposes almost
  every block and the chain rarely forks. The other 1% is the other nodes' leader notes and every
  service and wallet note.
- Blend: one layer, and a release delay of one round. The delay cannot be zero: the deployment
  requires a non-zero `maximum_release_delay_in_rounds`, so one round is the least there is.
- Blend's minimum network size is 2, the least the deployment accepts. With fewer members, nodes
  broadcast instead of blending.
- **No blend nodes at genesis.** The stock genesis ceremony refuses an empty provider list, but the
  protocol allows one, so `devnet/genesis/devnet_config.rs` builds the genesis with the node's own
  config generator (the one its multi-node tests use) and no providers. Every node has a staked
  service note to join with.
- Every key is derived from the node's index, so the identities are the same on every run; only
  the genesis time changes.

## Running it

You need Docker and `just`. The first build takes a while (each image compiles its project in
Rust); later builds reuse the cargo caches.

```sh
just devnet build   # build the node, LEZ and oracle images
just devnet up      # write a genesis, start everything, deploy the program, start the oracle
just devnet dashboard
```

`up` writes everything it generates under `devnet/state/`: the genesis and node configs, each
node's key and blend service note, the chain data, and a LEZ wallet per actor (`deployer`, `oracle`,
`node-0` … `node-3`). `just devnet down` stops the network and keeps it; `just devnet reset` deletes
it, and the next `up` starts a new chain.

## The flow

Node N's operator acts through its own wallet, `devnet/state/wallets/node-N`, and signs its
registration and the invitations it hands out with its node's key,
`devnet/state/config/node-N/node.key`, which is also its blend provider key: the oracle publishes
nodes by that key, so it is the key a node registers under.

```sh
# Blend: declare nodes as blend nodes. Each joins the membership two epochs after its
# declaration lands, and the oracle publishes the membership of every finalized epoch.
just devnet blend-join 0
just devnet blend-join 1

# Register: node 0 at the root, node 1 referred by node 0, node 2 referred by node 1.
just devnet register 0
just devnet register 1 0
just devnet register 2 1

# Claim: once epochs in which a node and its referrals were active are published.
just devnet claimable 0
just devnet claim 1
just devnet claim 0
just devnet show 0

# Cash out ("capture") a node's points into a public receipt only its operator can link to it.
just devnet cash-out 0
just devnet receipts 0
just devnet opening 0 0
```

A node earns a point for each referral active in an epoch it was active in itself, so a node that
has not joined blend earns nothing, and its referrals' points stop at it. Credits move up one level
per claim: claim the children before their referrer.

Other recipes: `just devnet logs <service>`, `just devnet ps`, `just devnet blend-status [n]`, `just devnet blend-withdraw <n>`, and
`just devnet wallet <actor> <command>` for any LEZ wallet command (for instance
`just devnet wallet deployer account list`).

## The dashboard

`just devnet dashboard` reads the chains every two seconds:

- **Blockchain nodes**: each node's state, height, tip and last irreversible slot, and peers.
- **Blend declarations**: every SDP declaration, with the epochs it was created and became active
  in, and whether it is in the current epoch's membership.
- **Blend membership by epoch**: the live membership, and each epoch the oracle published on LEZ.
- **Uplink registry**: the registry account: registered nodes, the last published epoch and its
  active nodes, and the oracle's balance.
- **Participants**: each operator's participant, read from its wallet as of that wallet's last sync.
  Participant state is private, so this is the one panel the chains cannot show.
- **Uplink activity**: publications, registrations, claims and cash-outs, from LEZ blocks.

It assumes nothing about the devnet beyond its flags: node URLs, the indexer, the program, a
directory naming the nodes, and the wallets to show (see `uplink-dashboard --help`).
`--print 180x45` reads once and prints the dashboard as text instead.

## Known quirks

- **The sequencer's fee reserve is 300%.** The blockchain re-prices storage gas at every epoch
  boundary, and at the genesis price of 1 a rise rounds up to a doubling. With LEZ's default 12%
  reserve, the inscription in flight at the first boundary could no longer pay its fee, the
  sequencer did not re-fund it, and every LEZ block after it stalled. `lez/sequencer_config.json`
  sets `priority_fee_percent: 300` to ride that out.
- `Failed to reconstruct block from proposal` in a node's log is a sibling block: when two leaders
  win the same slot, the later proposal's transactions may already be out of the mempool, and the
  node falls back to chain sync. With node 0 holding nearly all the stake this is rare; with
  equal stake it was about half of all proposals.
- The gossip mesh is sized for four nodes (`mesh_n: 3`); the node's default of six assumes a
  larger network.
- `SEQUENCER_LOG=info,logos_blockchain::zone_sdk=debug just devnet up` turns up the sequencer's
  logging.
