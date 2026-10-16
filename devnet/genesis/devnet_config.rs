//! Generates the uplink devnet: a genesis with no Blend providers, a deployment, and one node
//! config per node.
//!
//! Built inside the Logos blockchain workspace (see `devnet/docker/blockchain.Dockerfile`), where
//! it drives the same config generation the node's own multi-node tests use. Every key is derived
//! from the node's index, so the network's identities are the same on every run; only the genesis
//! time changes.

use std::{fs, path::PathBuf};

use anyhow::{Context as _, Result};
use clap::Parser;
use lb_config::{
    consensus::{
        SHORT_PROLONGED_BOOTSTRAP_PERIOD, SdpFundingConfig, create_genesis_block_with_declarations,
    },
    create_general_configs_from_prepared_network,
    funding::refresh_service_note,
    deployment::e2e_deployment_settings_with_genesis_block,
    network::NetworkParams,
    node::create_node_user_config,
    preparation::{PreparedNetwork, prepare_network},
};
use lb_core::mantle::GenesisTime;
use lb_key_management_system_keys::keys::{Ed25519Key, Key, ZkKey};
use lb_node::config::deployment::DeploymentSettings;
use lb_utils::yaml::{OnUnknownKeys, deserialize_value_from_reader};
use logos_blockchain_tools::set_at_path;
use serde_yaml::Value;
use time::OffsetDateTime;

#[derive(Parser)]
struct Args {
    /// Directory the deployment and node configs are written to.
    #[arg(long)]
    out: PathBuf,
    /// Number of nodes.
    #[arg(long, default_value_t = 4)]
    nodes: usize,
    /// Address of node `i` is this prefix followed by `10 + i`.
    #[arg(long, default_value = "172.28.0.")]
    ip_prefix: String,
    /// Notes of the key the LEZ sequencer pays its inscriptions from, held by every node.
    #[arg(long, default_value_t = 32)]
    sequencer_funding_notes: usize,
    /// Percentage of all genesis stake given to node 0's leader note.
    #[arg(long, default_value_t = 99)]
    node_0_stake_percent: u64,
}

const NETWORK_PORT: u16 = 3000;
const BLEND_PORT: u16 = 3400;
const API_PORT: u16 = 18080;
const SEQUENCER_FUNDING_NOTE_VALUE: u64 = 1_000_000_000;

/// Era-zero parameters the devnet sets on top of the generator's end-to-end deployment.
const DEPLOYMENT_OVERRIDES: &[(&str, &str)] = &[
    ("eras.0.cryptarchia.security_param", "2"),
    ("eras.0.cryptarchia.slot_activation_coeff.numerator", "1"),
    ("eras.0.cryptarchia.slot_activation_coeff.denominator", "2"),
    ("eras.0.blend.common.num_blend_layers", "1"),
    // The smallest Blend network that blends: with fewer members the nodes broadcast instead.
    ("eras.0.blend.common.minimum_network_size", "2"),
    // The release delay cannot be zero; one round is the least there is.
    ("eras.0.blend.core.scheduler.delayer.maximum_release_delay_in_rounds", "1"),
];

/// Node `index`'s id, the seed of all its keys. The generator derives the stake, blend-note and
/// SDP keys from the id's first 16 bytes, so the index leads.
fn node_id(index: usize) -> [u8; 32] {
    let mut id = [0; 32];
    id[0] = u8::try_from(index).expect("node index fits in a byte").strict_add(1);
    id[1..8].copy_from_slice(b"uplink-");
    id
}

fn sequencer_funding_key() -> ZkKey {
    ZkKey::new(lb_groth16::Fr::from(0x5e9_u64))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let ids: Vec<[u8; 32]> = (0..args.nodes).map(node_id).collect();
    let blend_ports = vec![BLEND_PORT; args.nodes];
    let funding = sequencer_funding_key();
    let wallets = vec![(funding.clone(), SEQUENCER_FUNDING_NOTE_VALUE); args.sequencer_funding_notes];

    let genesis_time = GenesisTime::try_from(OffsetDateTime::now_utc().replace_nanosecond(0)?)
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let mut prepared = prepare_network(
        &ids,
        &blend_ports,
        0,
        wallets.len(),
        &wallets,
        SdpFundingConfig::default(),
        Some("uplink-devnet"),
        genesis_time,
    );
    give_node_0_stake(&mut prepared, args.node_0_stake_percent, genesis_time)?;
    let configs = create_general_configs_from_prepared_network(
        &prepared,
        &NetworkParams::default(),
        SHORT_PROLONGED_BOOTSTRAP_PERIOD,
        &[Key::Zk(funding.clone())],
    );

    fs::create_dir_all(&args.out)?;
    let mut deployment = yaml(&e2e_deployment_settings_with_genesis_block(&prepared.genesis))?;
    for (path, value) in DEPLOYMENT_OVERRIDES {
        set_at_path(&mut deployment, path, serde_yaml::from_str(value)?)
            .map_err(|error| anyhow::anyhow!(error))?;
    }
    let deployment_yaml = serde_yaml::to_string(&deployment)?;
    deserialize_value_from_reader::<DeploymentSettings, _>(
        deployment_yaml.as_bytes(),
        OnUnknownKeys::Fail,
    )
    .context("the devnet deployment is not a valid deployment")?;
    fs::write(args.out.join("deployment.yaml"), deployment_yaml)?;

    let address = |index: usize| format!("{}{}", args.ip_prefix, 10 + index);
    for (index, config) in configs.into_iter().enumerate() {
        let blend_note = config.consensus_config.blend_note.note_id;
        let mut user = yaml(&create_node_user_config(config))?;
        let peers: Vec<Value> = (0..index)
            .map(|peer| Value::from(format!("/ip4/{}/udp/{NETWORK_PORT}/quic-v1", address(peer))))
            .collect();
        for (path, value) in [
            ("network.backend.swarm.host", Value::from("0.0.0.0")),
            ("network.backend.swarm.port", Value::from(NETWORK_PORT)),
            ("network.backend.initial_peers", Value::Sequence(peers)),
            (
                "blend.core.backend.listening_address",
                Value::from(format!("/ip4/0.0.0.0/udp/{BLEND_PORT}/quic-v1")),
            ),
            ("api.backend.listen_address", Value::from(format!("0.0.0.0:{API_PORT}"))),
            // A gossip mesh sized for this network, where each node has `nodes - 1` peers, rather
            // than the default's six.
            ("network.backend.swarm.gossipsub.mesh_n", Value::from(3)),
            ("network.backend.swarm.gossipsub.mesh_n_low", Value::from(2)),
            ("network.backend.swarm.gossipsub.mesh_n_high", Value::from(4)),
            ("network.backend.swarm.gossipsub.mesh_outbound_min", Value::from(1)),
            ("storage.backend.folder_name", Value::from("/data/db")),
            ("state.base_folder", Value::from("/data/state")),
        ] {
            set_at_path(&mut user, path, value).map_err(|error| anyhow::anyhow!(error))?;
        }

        let dir = args.out.join(format!("node-{index}"));
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("config.yaml"), serde_yaml::to_string(&user)?)?;

        // What the devnet's scripts need to act as this node's operator.
        let provider = Ed25519Key::from_bytes(&ids[index]);
        fs::write(dir.join("node.key"), hex(&ids[index]))?;
        fs::write(dir.join("provider_id"), hex(provider.public_key().as_bytes()))?;
        fs::write(dir.join("blend_note_id"), scalar(&blend_note)?)?;
        fs::write(
            dir.join("locator"),
            format!("/ip4/{}/udp/{BLEND_PORT}/quic-v1", address(index)),
        )?;
    }
    fs::write(
        args.out.join("sequencer_funding_key"),
        scalar(&funding.to_public_key())?,
    )?;
    println!(
        "Wrote the {}-node devnet to {} (genesis at {genesis_time:?})",
        args.nodes,
        args.out.display()
    );
    Ok(())
}

/// Raises node 0's leader note so it holds `percent` of all genesis stake. The ledger's initial
/// total stake is the sum of every genesis note, so the rest is shared by the other nodes' leader
/// notes and every service and wallet note, the sequencer's funding included.
fn give_node_0_stake(
    prepared: &mut PreparedNetwork,
    percent: u64,
    genesis_time: GenesisTime,
) -> Result<()> {
    anyhow::ensure!((1..100).contains(&percent), "node 0's stake must be 1 to 99 percent");
    let leader = prepared.consensus.regular_note_keys[0].to_public_key();
    let mut transfer = prepared.genesis.genesis_tx().transfer().operation().clone();
    let rest: u64 = transfer
        .outputs
        .iter()
        .filter(|note| note.pk != leader)
        .map(|note| note.value)
        .sum();
    let stake = rest
        .checked_mul(percent)
        .map(|scaled| scaled / (100 - percent))
        .context("node 0's stake overflows")?;
    let mut outputs = (&mut transfer.outputs).into_iter().filter(|note| note.pk == leader);
    outputs.next().context("node 0 has no leader note")?.value = stake;
    anyhow::ensure!(outputs.next().is_none(), "node 0 has more than one leader note");

    for note in prepared
        .consensus
        .blend_notes
        .iter_mut()
        .chain(&mut prepared.consensus.sdp_notes)
    {
        refresh_service_note(note, &transfer);
    }
    prepared.consensus.utxos = transfer.utxos().collect();
    // The devnet genesis declares no providers, so rebuilding it without any changes nothing else.
    prepared.genesis = create_genesis_block_with_declarations(
        transfer,
        Vec::new(),
        Some("uplink-devnet"),
        genesis_time,
    );
    Ok(())
}

/// A value as human-readable YAML, the form the node reads its configs in.
fn yaml<T: serde::Serialize>(value: &T) -> Result<Value> {
    Ok(serde_yaml::from_str(&serde_yaml::to_string(value)?)?)
}

/// A value that serializes as a single string, such as a key or note id, as that string.
fn scalar<T: serde::Serialize>(value: &T) -> Result<String> {
    match yaml(value)? {
        Value::String(text) => Ok(text),
        other => anyhow::bail!("expected a string, got {other:?}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
