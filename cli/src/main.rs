#![expect(
    clippy::print_stdout,
    reason = "This is a CLI application, printing to stdout is expected and convenient"
)]

//! `uplink`: the referral program's command line, over the user's LEZ wallet.
//!
//! The wallet is loaded the way the LEZ `wallet` binary loads it, and must already be set up. The
//! referral store is kept next to the wallet's storage.

use std::{collections::BTreeSet, fs, path::PathBuf};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use lee::AccountId;
use rand::RngCore as _;
use referral_core::{Invitation, NodeId, State};
use referral_methods::referral;
use uplink_wallet::{Referral, store::OperationKind};
use url::Url;
use wallet::WalletCore;

#[derive(Parser)]
#[command(about = "Node referral program on the Logos Execution Zone")]
struct Args {
    /// Account the referral program is deployed at.
    #[arg(long, env = "UPLINK_PROGRAM")]
    program: AccountId,
    /// Indexer endpoint, needed to collect credits earned in past epochs.
    #[arg(long, env = "UPLINK_INDEXER")]
    indexer: Option<Url>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a private participant account.
    NewParticipant,
    /// Show a participant's referral state.
    Show {
        #[arg(long)]
        participant: AccountId,
    },
    /// Write an invitation for a node joining under this participant's node.
    Invite {
        #[arg(long)]
        participant: AccountId,
        /// This participant's node, as hex.
        #[arg(long, value_parser = parse_node)]
        node: NodeId,
        /// File to write the invitation to; printed if omitted.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import the invitation of the node this participant will register under.
    AcceptInvite {
        #[arg(long)]
        participant: AccountId,
        invitation: PathBuf,
    },
    /// Start a registration, and print the message the node key must sign.
    PrepareRegistration {
        #[arg(long)]
        participant: AccountId,
        /// The node being registered, as hex.
        #[arg(long, value_parser = parse_node)]
        node: NodeId,
        /// The referrer's node, as hex. Its invitation must be imported first.
        #[arg(long, value_parser = parse_node)]
        referrer: Option<NodeId>,
    },
    /// Attach the node key's signature over the prepared registration.
    AttachSignature {
        #[arg(long)]
        participant: AccountId,
        /// Ed25519 signature, as hex.
        #[arg(long, value_parser = parse_signature)]
        signature: [u8; 64],
    },
    /// Submit a signed registration.
    Register {
        #[arg(long)]
        participant: AccountId,
        /// Resume an earlier attempt under its reference.
        #[arg(long, value_parser = parse_reference)]
        reference: Option<[u8; 32]>,
    },
    /// Claim everything claimable: this epoch's rewards and credits from past epochs.
    Claim {
        #[arg(long)]
        participant: AccountId,
    },
    /// Cash the whole reward balance out into a new receipt.
    CashOut {
        #[arg(long)]
        participant: AccountId,
        /// Resume an earlier attempt under its reference.
        #[arg(long, value_parser = parse_reference)]
        reference: Option<[u8; 32]>,
    },
    /// List the participant's cash-out receipts.
    Receipts {
        #[arg(long)]
        participant: AccountId,
    },
    /// Print the opening that links a receipt to the participant's node.
    Opening {
        #[arg(long)]
        participant: AccountId,
        #[arg(long)]
        index: u64,
    },
    /// Reconcile and print the status of a submitted operation.
    Status {
        #[arg(value_parser = parse_reference)]
        reference: [u8; 32],
    },
    /// Publish an epoch's active nodes. Signed by the oracle account, which this wallet must hold.
    Publish {
        #[arg(long)]
        epoch: u32,
        /// Active nodes, as hex.
        #[arg(long = "active", value_parser = parse_node)]
        active: Vec<NodeId>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let Args {
        program,
        indexer,
        command,
    } = Args::parse();

    let mut wallet =
        WalletCore::from_env().context("Failed to load the LEZ wallet; set it up with `wallet`")?;
    wallet
        .sync_to_latest_block()
        .await
        .context("Failed to sync the wallet")?;
    let mut facade = Referral::new(&mut wallet, referral(), program)?;
    if let Some(indexer) = indexer {
        facade = facade.with_indexer(indexer);
    }

    run(&mut facade, command).await
}

async fn run(facade: &mut Referral<'_>, command: Command) -> Result<()> {
    match command {
        Command::NewParticipant => println!("{}", facade.create_participant()?),
        Command::Show { participant } => show(facade, participant)?,
        Command::Invite {
            participant,
            node,
            out,
        } => {
            let invitation = serde_json::to_string_pretty(&facade.invitation(participant, node)?)?;
            match out {
                Some(path) => fs::write(&path, invitation)
                    .with_context(|| format!("Failed to write {}", path.display()))?,
                None => println!("{invitation}"),
            }
        }
        Command::AcceptInvite {
            participant,
            invitation,
        } => {
            let invitation: Invitation = serde_json::from_slice(
                &fs::read(&invitation)
                    .with_context(|| format!("Failed to read {}", invitation.display()))?,
            )
            .context("Not an invitation")?;
            facade.import_invitation(participant, invitation)?;
        }
        Command::PrepareRegistration {
            participant,
            node,
            referrer,
        } => {
            let authorization = facade.prepare_registration(participant, node, referrer)?;
            println!("{}", hex::encode(authorization.message()));
        }
        Command::AttachSignature {
            participant,
            signature,
        } => facade.attach_node_signature(participant, signature)?,
        Command::Register {
            participant,
            reference,
        } => submit(facade, reference, OperationKind::Register { participant }).await?,
        Command::Claim { participant } => {
            let operations = facade.claim_operations(participant).await?;
            if operations.is_empty() {
                println!("Nothing to claim");
            }
            for operation in operations {
                submit(facade, None, operation).await?;
            }
        }
        Command::CashOut {
            participant,
            reference,
        } => {
            let reference = reference.unwrap_or_else(new_reference);
            let (hash, status) = facade.cash_out(reference, participant).await?;
            print_submission(reference, &hash.to_string(), status);
        }
        Command::Receipts { participant } => {
            for receipt in facade.receipts(participant).await? {
                println!(
                    "{}\t{}\t{} points",
                    receipt.index, receipt.account_id, receipt.points
                );
            }
        }
        Command::Opening { participant, index } => {
            let opening = facade.opening(participant, index)?;
            println!("program\t{}", opening.program_account);
            println!("node\t{}", hex::encode(opening.node.to_bytes()));
            println!("blinding_factor\t{}", hex::encode(opening.blinding_factor));
            println!("receipt\t{}", opening.account_id);
        }
        Command::Status { reference } => {
            println!("{:?}", facade.reconcile(reference).await?);
        }
        Command::Publish { epoch, active } => {
            let hash = facade
                .publish(epoch, active.into_iter().collect::<BTreeSet<_>>())
                .await?;
            println!("{hash}");
        }
    }
    Ok(())
}

fn show(facade: &Referral<'_>, participant: AccountId) -> Result<()> {
    match facade.state(participant)? {
        State::Participant(state) => {
            println!("node\t{}", hex::encode(state.node.to_bytes()));
            println!(
                "referrer\t{}",
                state
                    .referrer
                    .map_or_else(|| "none".to_owned(), |node| hex::encode(node.to_bytes()))
            );
            println!("children\t{}", state.children.len());
            println!("reward_balance\t{}", state.reward_balance);
        }
        State::Registry(_) | State::Child { .. } | State::Credit { .. } | State::CashOut { .. } => {
            bail!("{participant} does not hold a participant")
        }
    }
    if let Some(pending) = facade.pending_registration(participant) {
        println!(
            "pending_registration\t{}{}",
            hex::encode(pending.node.to_bytes()),
            if pending.signature.is_some() {
                ""
            } else {
                " (unsigned)"
            }
        );
    }
    Ok(())
}

async fn submit(
    facade: &mut Referral<'_>,
    reference: Option<[u8; 32]>,
    operation: OperationKind,
) -> Result<()> {
    let reference = reference.unwrap_or_else(new_reference);
    let (hash, status) = facade.submit(reference, operation).await?;
    print_submission(reference, &hash.to_string(), status);
    Ok(())
}

fn print_submission(
    reference: [u8; 32],
    hash: &str,
    status: uplink_wallet::store::SubmissionStatus,
) {
    println!(
        "reference {}\ttransaction {hash}\t{status:?}",
        hex::encode(reference)
    );
}

fn new_reference() -> [u8; 32] {
    let mut reference = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut reference);
    reference
}

fn parse_node(text: &str) -> Result<NodeId> {
    Ok(NodeId::new(parse_array(text)?))
}

fn parse_signature(text: &str) -> Result<[u8; 64]> {
    parse_array(text)
}

fn parse_reference(text: &str) -> Result<[u8; 32]> {
    parse_array(text)
}

fn parse_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(text).context("Not hex")?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("Expected {N} bytes, got {}", bytes.len()))
}
