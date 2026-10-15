#![expect(
    clippy::print_stdout,
    reason = "This is a CLI application, printing to stdout is expected and convenient"
)]

//! `uplink`: the referral program's command line, over the user's LEZ wallet.
//!
//! The wallet is loaded the way the LEZ `wallet` binary loads it, and must already be set up. The
//! referral store is kept next to the wallet's storage.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use lee::AccountId;
use rand::RngCore as _;
use referral_core::{Epoch, Invitation, NodeId, State};
use referral_methods::referral;
use uplink_wallet::{Referral, store::OperationKind};
use url::Url;
use wallet::WalletCore;

#[derive(Parser)]
#[command(about = "Node referral program on the Logos Execution Zone")]
struct Args {
    /// Account the referral program is deployed at. Needed by every command but
    /// `derive-receipt-secret`.
    #[arg(long, env = "UPLINK_PROGRAM")]
    program: Option<AccountId>,
    /// Indexer endpoint, needed to claim any epoch but the current one.
    #[arg(long, env = "UPLINK_INDEXER")]
    indexer: Option<Url>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Derive a node's receipt secret from its Ed25519 secret key, for its participant's wallet.
    /// Run by the node's operator; needs neither a wallet nor a deployment.
    DeriveReceiptSecret {
        /// File holding the node's 32-byte Ed25519 secret key, as hex.
        #[arg(long)]
        node_key_file: PathBuf,
        /// File to write the receipt secret to, readable by its owner only.
        #[arg(long)]
        out: PathBuf,
    },
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
    /// Print what claiming now would pay, without claiming.
    Claimable {
        #[arg(long)]
        participant: AccountId,
    },
    /// Claim every epoch not yet settled, oldest first, in as many claims as the batch caps need.
    Claim {
        #[arg(long)]
        participant: AccountId,
    },
    /// Cash the whole reward balance out into a new receipt.
    CashOut {
        #[arg(long)]
        participant: AccountId,
        #[command(flatten)]
        receipt_secret: ReceiptSecretFile,
        /// Resume an earlier attempt under its reference.
        #[arg(long, value_parser = parse_reference)]
        reference: Option<[u8; 32]>,
    },
    /// List the participant's cash-out receipts.
    Receipts {
        #[arg(long)]
        participant: AccountId,
        #[command(flatten)]
        receipt_secret: ReceiptSecretFile,
    },
    /// Print the opening that links a receipt to the participant's node.
    Opening {
        #[arg(long)]
        participant: AccountId,
        #[arg(long)]
        index: u64,
        #[command(flatten)]
        receipt_secret: ReceiptSecretFile,
    },
    /// Reconcile and print the status of a submitted operation.
    Status {
        #[arg(value_parser = parse_reference)]
        reference: [u8; 32],
    },
    /// Publish an epoch's active nodes. Signed by the oracle account, which this wallet must hold.
    Publish {
        #[arg(long)]
        epoch: Epoch,
        /// Active nodes, as hex.
        #[arg(long = "active", value_parser = parse_node)]
        active: Vec<NodeId>,
    },
}

/// The node's receipt secret, written by `derive-receipt-secret`.
#[derive(clap::Args)]
struct ReceiptSecretFile {
    /// File holding the node's receipt secret, as hex.
    #[arg(long = "receipt-secret-file", env = "UPLINK_RECEIPT_SECRET_FILE")]
    path: PathBuf,
}

impl ReceiptSecretFile {
    fn read(&self) -> Result<[u8; 32]> {
        read_hex_file(&self.path)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let Args {
        program,
        indexer,
        command,
    } = Args::parse();

    if let Command::DeriveReceiptSecret { node_key_file, out } = &command {
        let secret = uplink_wallet::receipt_secret(&read_hex_file(node_key_file)?);
        return write_secret_file(out, &hex::encode(secret));
    }
    let program = program.context("--program or UPLINK_PROGRAM is required")?;

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
        Command::DeriveReceiptSecret { .. } => unreachable!("handled before the wallet is loaded"),
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
        Command::Claimable { participant } => {
            println!("{}", facade.claimable(participant).await?);
        }
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
            receipt_secret,
            reference,
        } => {
            let reference = reference.unwrap_or_else(new_reference);
            let (hash, status) = facade
                .cash_out(reference, participant, &receipt_secret.read()?)
                .await?;
            print_submission(reference, &hash.to_string(), status);
        }
        Command::Receipts {
            participant,
            receipt_secret,
        } => {
            for receipt in facade
                .receipts(participant, &receipt_secret.read()?)
                .await?
            {
                println!(
                    "{}\t{}\t{} points",
                    receipt.index, receipt.account_id, receipt.points
                );
            }
        }
        Command::Opening {
            participant,
            index,
            receipt_secret,
        } => {
            let opening = facade.opening(participant, index, &receipt_secret.read()?)?;
            println!("program\t{}", opening.uplink_account);
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
                    .referrer_node()
                    .map_or_else(|| "none".to_owned(), |node| hex::encode(node.to_bytes()))
            );
            println!("children\t{}", state.children.len());
            for (child, settled) in &state.children {
                println!(
                    "child\t{}\tsettled {}",
                    hex::encode(child.to_bytes()),
                    settled_epochs(settled)
                );
            }
            println!("reward_balance\t{}", state.reward_balance);

            let mut announced = 0_usize;
            let mut credit_epochs = BTreeSet::new();
            let mut credits = 0_usize;
            for (_id, note) in facade.notes(participant)? {
                match note {
                    State::Child { .. } => announced = announced.saturating_add(1),
                    State::Credit { epoch, .. } => {
                        credits = credits.saturating_add(1);
                        credit_epochs.insert(epoch);
                    }
                    State::Registry(_)
                    | State::Participant(_)
                    | State::CashOut { .. }
                    | State::Publication { .. } => {}
                }
            }
            let epochs: Vec<String> = credit_epochs.iter().map(ToString::to_string).collect();
            println!(
                "pending_notes\t{announced} child announced, {credits} credits{}",
                if epochs.is_empty() {
                    String::new()
                } else {
                    format!(" (epochs {})", epochs.join(", "))
                }
            );
        }
        State::Registry(_)
        | State::Child { .. }
        | State::Credit { .. }
        | State::CashOut { .. }
        | State::Publication { .. } => {
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

/// Settled epoch ranges as `1-3,5`, or `none`.
fn settled_epochs(settled: &[(Epoch, Epoch)]) -> String {
    if settled.is_empty() {
        return "none".to_owned();
    }
    settled
        .iter()
        .map(|&(first, last)| {
            if first == last {
                first.to_string()
            } else {
                format!("{first}-{last}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn read_hex_file(path: &Path) -> Result<[u8; 32]> {
    let text =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    parse_array(text.trim())
        .with_context(|| format!("{} does not hold 32 hex bytes", path.display()))
}

/// Writes `contents` to `path`, readable and writable by its owner only.
fn write_secret_file(path: &Path, contents: &str) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("Failed to create {}", path.display()))?;
    std::io::Write::write_all(&mut file, contents.as_bytes())
        .with_context(|| format!("Failed to write {}", path.display()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settled_epochs_print_as_ranges() {
        assert_eq!(settled_epochs(&[]), "none");
        assert_eq!(settled_epochs(&[(0, 2)]), "0-2");
        assert_eq!(settled_epochs(&[(1, 3), (5, 5), (7, 9)]), "1-3,5,7-9");
    }
}
