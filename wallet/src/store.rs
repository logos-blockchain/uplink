use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::ErrorKind,
    path::Path,
};

use anyhow::{Context as _, Result};
use common::HashType;
use lee::AccountId;
use lee_core::{BlockId, Commitment, Identifier};
use rand::{RngCore as _, rngs::OsRng};
use referral_core::{Epoch, Invitation, NodeId, active_digest, ed25519_dalek::Signature};
use serde::{Deserialize, Serialize};

use crate::blend::ChainEpoch;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferralStore {
    pub intents: BTreeMap<AccountId, ReferralIntent>,
    pub operations: BTreeMap<String, PendingOperation>,
    pub publications: Vec<Publication>,
    pub history_offsets: BTreeMap<AccountId, u64>,
    /// The last chain epoch the oracle published from this wallet, per uplink account.
    #[serde(default)]
    pub oracle_publications: BTreeMap<AccountId, OraclePublication>,
}

/// A chain epoch's membership the oracle published, and the epoch it published it as. Recorded
/// before the publication is sent, so the oracle publishes each chain epoch at most once, even
/// across restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OraclePublication {
    pub chain_epoch: ChainEpoch,
    pub epoch: Epoch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Publication {
    pub uplink_account: AccountId,
    pub epoch: Epoch,
    pub active: BTreeSet<NodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferralIntent {
    pub uplink_account: AccountId,
    pub registration: Option<PendingRegistration>,
    pub invitation: Option<Invitation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRegistration {
    pub node: NodeId,
    pub referrer: Option<NodeId>,
    pub signature: Option<Signature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationKind {
    Register {
        participant: AccountId,
    },
    Claim {
        participant: AccountId,
        /// The claimed epochs, in strictly increasing order.
        epochs: Vec<ClaimedEpoch>,
    },
    CashOut {
        participant: AccountId,
        index: u64,
        /// The receipt this cash-out creates, so it reconciles without the receipt secret.
        receipt: AccountId,
    },
}

/// One epoch of a claim: its publication and the notes it consumes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimedEpoch {
    pub epoch: Epoch,
    pub active_digest: [u8; 32],
    pub notes: Vec<AccountId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmissionStatus {
    Pending,
    Settled,
    Rejected,
}

/// What a submitted operation asserts about the public registry when it is included.
///
/// The registry can move on while the operation waits, which supersedes it. Claims check only
/// immutable publications, so nothing supersedes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryGuard {
    /// A registration, which fails once its node is registered or the registry has published
    /// another epoch than the one it records.
    Registers { node: NodeId, epoch: Epoch },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOperation {
    pub reference: [u8; 32],
    pub uplink_account: AccountId,
    pub operation: OperationKind,
    /// The hash the sequencer returned for the transaction this attempt sent.
    pub hash: HashType,
    /// The last block when the attempt was sent, from which an attempt still not included counts
    /// as lost.
    pub sent_at_block: BlockId,
    pub registry_guard: Option<RegistryGuard>,
    pub input_commitments: Vec<(AccountId, Commitment)>,
    pub status: SubmissionStatus,
}

impl ReferralStore {
    /// Reads the store at `path`, or an empty one if nothing was written there yet.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| {
                format!("Failed to decode the referral store at {}", path.display())
            }),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| {
                format!("Failed to read the referral store at {}", path.display())
            }),
        }
    }

    /// Writes the store to `path` through a temporary file, so a crash never leaves it half
    /// written.
    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes =
            serde_json::to_vec_pretty(self).context("Failed to encode the referral store")?;
        let staged = path.with_extension("json.tmp");
        fs::write(&staged, bytes)
            .with_context(|| format!("Failed to write {}", staged.display()))?;
        fs::rename(&staged, path)
            .with_context(|| format!("Failed to replace the referral store at {}", path.display()))
    }

    #[must_use]
    pub fn operation(&self, reference: [u8; 32]) -> Option<&PendingOperation> {
        self.operations.get(&operation_key(reference))
    }

    pub fn operation_mut(&mut self, reference: [u8; 32]) -> Option<&mut PendingOperation> {
        self.operations.get_mut(&operation_key(reference))
    }

    pub fn record_operation(&mut self, operation: PendingOperation) {
        self.operations
            .insert(operation_key(operation.reference), operation);
    }

    #[must_use]
    pub fn publication(
        &self,
        uplink_account: AccountId,
        epoch: Epoch,
        digest: [u8; 32],
    ) -> Option<&BTreeSet<NodeId>> {
        self.publications
            .iter()
            .find(|publication| {
                publication.uplink_account == uplink_account
                    && publication.epoch == epoch
                    && active_digest(&publication.active) == digest
            })
            .map(|publication| &publication.active)
    }
}

impl ReferralIntent {
    #[must_use]
    pub const fn new(uplink_account: AccountId) -> Self {
        Self {
            uplink_account,
            registration: None,
            invitation: None,
        }
    }
}

impl PendingRegistration {
    #[must_use]
    pub fn signed(&self) -> Option<[u8; 64]> {
        Some(self.signature?.to_bytes())
    }
}

impl OperationKind {
    #[must_use]
    pub const fn participant(&self) -> AccountId {
        match self {
            Self::Register { participant }
            | Self::Claim { participant, .. }
            | Self::CashOut { participant, .. } => *participant,
        }
    }
}

impl SubmissionStatus {
    #[must_use]
    pub const fn is_conclusive(self) -> bool {
        matches!(self, Self::Settled | Self::Rejected)
    }
}

#[must_use]
pub fn random_identifier() -> Identifier {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    Identifier::new(bytes)
}

fn operation_key(reference: [u8; 32]) -> String {
    hex::encode(reference)
}

#[cfg(test)]
mod tests {
    use lee_core::{NullifierPublicKey, encryption::ViewingPublicKey};

    use super::*;

    fn register_operation(
        reference: [u8; 32],
        uplink_account: AccountId,
        participant: AccountId,
    ) -> PendingOperation {
        PendingOperation {
            reference,
            uplink_account,
            operation: OperationKind::Register { participant },
            hash: HashType([1; 32]),
            sent_at_block: 12,
            registry_guard: Some(RegistryGuard::Registers {
                node: NodeId::new([7; 32]),
                epoch: 2,
            }),
            input_commitments: Vec::new(),
            status: SubmissionStatus::Pending,
        }
    }

    #[test]
    fn the_store_round_trips_through_its_file() {
        let uplink_account = AccountId::new([9; 32]);
        let participant = AccountId::new([5; 32]);
        let mut store = ReferralStore::default();

        let mut intent = ReferralIntent::new(uplink_account);
        intent.registration = Some(PendingRegistration {
            node: NodeId::new([7; 32]),
            referrer: Some(NodeId::new([8; 32])),
            signature: Some(Signature::from_bytes(&[3; 64])),
        });
        intent.invitation = Some(Invitation::new(
            NodeId::new([8; 32]),
            NullifierPublicKey([1; 32]),
            ViewingPublicKey::from_seed(&[2; 32], &[3; 32]),
            Signature::from_bytes(&[4; 64]),
        ));
        store.intents.insert(participant, intent);
        store.record_operation(register_operation([7; 32], uplink_account, participant));
        store.record_operation(PendingOperation {
            operation: OperationKind::CashOut {
                participant,
                index: 3,
                receipt: AccountId::new([4; 32]),
            },
            registry_guard: None,
            ..register_operation([8; 32], uplink_account, participant)
        });
        store.record_operation(PendingOperation {
            operation: OperationKind::Claim {
                participant,
                epochs: vec![ClaimedEpoch {
                    epoch: 4,
                    active_digest: [5; 32],
                    notes: vec![AccountId::new([6; 32])],
                }],
            },
            registry_guard: None,
            ..register_operation([9; 32], uplink_account, participant)
        });
        store.publications.push(Publication {
            uplink_account,
            epoch: 4,
            active: BTreeSet::from([NodeId::new([7; 32])]),
        });
        store.history_offsets.insert(uplink_account, 11);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("referral.json");
        store.save(&path).unwrap();

        assert_eq!(ReferralStore::load(&path).unwrap(), store);
    }

    #[test]
    fn a_missing_store_loads_empty() {
        let directory = tempfile::tempdir().unwrap();

        assert_eq!(
            ReferralStore::load(&directory.path().join("referral.json")).unwrap(),
            ReferralStore::default()
        );
    }
}
