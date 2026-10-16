#![expect(
    clippy::print_stdout,
    reason = "This is a CLI application, printing to stdout is expected and convenient"
)]

//! `uplink-devnet`: sets up the devnet's LEZ side and acts for its operators.
//!
//! Each actor of the devnet (the deployer, the oracle and each node's operator) has its own LEZ
//! wallet under `<state>/wallets/<actor>`. `bootstrap` creates them, deploys the referral program
//! and funds the oracle; the rest is the LEZ wallet's own command line and the node-key signing the
//! `uplink` registration flow asks for.

use core::time::Duration;
use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use lee::{AccountId, PrivateKey};
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use referral_core::{
    ORACLE_ACCOUNT_ID,
    ed25519_dalek::{Signer as _, SigningKey},
};
use referral_methods::referral;
use testnet_initial_state::initial_pub_accounts_private_keys;
use url::Url;
use wallet::{
    WalletCore,
    cli::{
        CliAccountMention, execute_subcommand,
        programs::native_token_transfer::AuthTransferSubcommand,
    },
    config::{SequencerConnectionData, WalletConfig},
    program_facades::program_loader::ProgramLoader,
};

/// The key behind `ORACLE_ACCOUNT_ID` in this prototype, the one the integration tests use too.
const PROTOTYPE_ORACLE_SIGNING_KEY: [u8; 32] = [11; 32];

/// What the oracle is funded with, for the fees of its publications.
const ORACLE_FUNDING: u128 = 100_000_000_000;

const SEQUENCER_ATTEMPTS: u32 = 120;

#[derive(Parser)]
#[command(about = "Sets up the uplink devnet's LEZ side and acts for its operators")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the actors' wallets, deploy the referral program and fund the oracle. Skips whatever
    /// is already done, so it can be run again.
    Bootstrap {
        /// The devnet's state directory.
        #[arg(long)]
        state: PathBuf,
        /// Number of node operators to make wallets for.
        #[arg(long, default_value_t = 4)]
        nodes: usize,
        /// The sequencer, as the host reaches it.
        #[arg(long, default_value = "http://127.0.0.1:3040")]
        sequencer: Url,
        /// The sequencer, as the oracle's container reaches it.
        #[arg(long, default_value = "http://sequencer:3040")]
        oracle_sequencer: Url,
    },
    /// Run a LEZ wallet command against the wallet in `LEE_WALLET_HOME_DIR`.
    Wallet {
        #[command(subcommand)]
        command: wallet::cli::Command,
    },
    /// Sign a hex message with a node's Ed25519 key, as a node operator signs its registration.
    Sign {
        /// File holding the node's 32-byte Ed25519 secret key, as hex.
        #[arg(long)]
        key_file: PathBuf,
        /// The message, as hex.
        message: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Bootstrap {
            state,
            nodes,
            sequencer,
            oracle_sequencer,
        } => bootstrap(&state, nodes, &sequencer, &oracle_sequencer).await,
        Command::Wallet { command } => {
            let mut wallet = WalletCore::from_env().context("Failed to load the wallet")?;
            let output = execute_subcommand(&mut wallet, command).await?;
            wallet.store_persistent_data()?;
            println!("{output:?}");
            Ok(())
        }
        Command::Sign { key_file, message } => {
            let key = SigningKey::from_bytes(&read_hex::<32>(&key_file)?);
            let message = hex::decode(message.trim()).context("The message is not hex")?;
            println!("{}", hex::encode(key.sign(&message).to_bytes()));
            Ok(())
        }
    }
}

async fn bootstrap(
    state: &Path,
    nodes: usize,
    sequencer: &Url,
    oracle_sequencer: &Url,
) -> Result<()> {
    let wallets = state.join("wallets");

    let mut deployer = open_wallet(&wallets.join("deployer"), sequencer)?;
    wait_for_sequencer(&deployer).await?;
    let payer = initial_pub_accounts_private_keys().swap_remove(0);
    deployer
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(payer.pub_sign_key.clone());
    deployer.store_persistent_data()?;

    let program_file = state.join("program");
    let program = if program_file.exists() {
        fs::read_to_string(&program_file)?.trim().parse()?
    } else {
        let program = deploy(&mut deployer, payer.account_id).await?;
        fs::write(&program_file, program.to_string())?;
        println!("Deployed the referral program at {program}");
        program
    };

    if deployer.get_account_balance(ORACLE_ACCOUNT_ID).await? < ORACLE_FUNDING {
        let send = AuthTransferSubcommand::Send {
            from: mention(payer.account_id),
            to: Some(mention(ORACLE_ACCOUNT_ID)),
            to_npk: None,
            to_vpk: None,
            to_keys: None,
            to_identifier: Some(lee_core::Identifier::ZERO),
            amount: ORACLE_FUNDING,
        };
        execute_subcommand(&mut deployer, wallet::cli::Command::AuthTransfer(send)).await?;
        println!("Funded the oracle account {ORACLE_ACCOUNT_ID}");
    }

    // The oracle's wallet is used from its container, which reaches the sequencer by name.
    let mut oracle = open_wallet(&wallets.join("oracle"), oracle_sequencer)?;
    oracle
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(PrivateKey::try_new(PROTOTYPE_ORACLE_SIGNING_KEY)?);
    oracle.store_persistent_data()?;

    for node in 0..nodes {
        open_wallet(&wallets.join(format!("node-{node}")), sequencer)?;
    }
    println!("The devnet's referral program is {program}");
    Ok(())
}

/// Deploys the referral program, paid by `payer`, and returns its account.
async fn deploy(wallet: &mut WalletCore, payer: AccountId) -> Result<AccountId> {
    let program = referral();
    let byte_len = program
        .user_elf()
        .context("The referral program does not decode")?
        .len();
    let segments: Vec<AccountId> =
        core::iter::repeat_with(|| wallet.create_new_account_public(None).0)
            .take(byte_len.div_ceil(MAX_SEGMENT_DATA_LEN))
            .collect();
    let (header, _) = wallet.create_new_account_public(None);
    wallet.store_persistent_data()?;

    ProgramLoader(wallet)
        .deploy(header, &segments, program.elf().to_vec(), true, Some(payer))
        .await
}

/// The wallet at `home`, created with a fresh seed if there is none yet.
fn open_wallet(home: &Path, sequencer: &Url) -> Result<WalletCore> {
    fs::create_dir_all(home)?;
    let config_path = home.join("wallet_config.json");
    let storage_path = home.join("storage.json");
    if !config_path.exists() {
        let config = WalletConfig {
            sequencer: SequencerConnectionData {
                sequencer_addr: sequencer.clone(),
                basic_auth: None,
            },
            ..WalletConfig::default()
        };
        fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
    }
    if storage_path.exists() {
        return WalletCore::new_update_chain(config_path, storage_path, None);
    }
    let (wallet, _mnemonic) = WalletCore::new_init_storage(config_path, storage_path, None, "")?;
    wallet.store_persistent_data()?;
    Ok(wallet)
}

async fn wait_for_sequencer(wallet: &WalletCore) -> Result<()> {
    for _ in 0..SEQUENCER_ATTEMPTS {
        if wallet.get_last_block_id().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("The sequencer at {} never answered", wallet.client_url())
}

const fn mention(account: AccountId) -> CliAccountMention {
    CliAccountMention::Id(wallet::account::AccountIdWithPrivacy::Public(account))
}

fn read_hex<const N: usize>(path: &Path) -> Result<[u8; N]> {
    let text =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    hex::decode(text.trim())
        .context("Not hex")?
        .try_into()
        .map_err(|_bytes| anyhow::anyhow!("{} does not hold {N} bytes", path.display()))
}
