use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
pub use ed25519_dalek;
use lee_core::{
    NullifierPublicKey,
    account::{AccountId, ShardData},
    encryption::ViewingPublicKey,
    program::PdaSeed,
};
use serde::{Deserialize, Serialize};

pub const ORACLE_ACCOUNT_ID: AccountId = AccountId::new([
    0x52, 0x5c, 0xc5, 0x6b, 0x7f, 0x8e, 0x28, 0x49, 0xec, 0x9d, 0xa8, 0x66, 0x1c, 0x7a, 0xde, 0x0c,
    0x91, 0x8f, 0x7a, 0x0a, 0xb2, 0x3a, 0x3f, 0xa7, 0x59, 0x61, 0xd5, 0xa1, 0x99, 0xa5, 0x6e, 0xf3,
]);

const AUTHORIZATION_DOMAIN: &[u8; 31] = b"Uplink/AuthorizeParticipant/v1\0";

const CASH_OUT_DOMAIN: &[u8; 18] = b"Uplink/CashOut/v1\0";

const BLINDING_FACTOR_DOMAIN: &[u8; 25] = b"Uplink/BlindingFactor/v1\0";

const EPOCH_DOMAIN: &[u8; 16] = b"Uplink/Epoch/v1\0";

/// An epoch, numbered by the oracle's publications.
pub type Epoch = u32;
pub type Points = u128;

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct NodeId([u8; 32]);

impl NodeId {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    #[must_use]
    pub fn verifying_key(self) -> Option<ed25519_dalek::VerifyingKey> {
        ed25519_dalek::VerifyingKey::from_bytes(&self.0).ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    pub parent_node: NodeId,
    pub npk: NullifierPublicKey,
    pub vpk: ViewingPublicKey,
}

impl Invitation {
    #[must_use]
    pub const fn new(parent_node: NodeId, npk: NullifierPublicKey, vpk: ViewingPublicKey) -> Self {
        Self {
            parent_node,
            npk,
            vpk,
        }
    }
}

/// A participant's referrer, as its `Participant` state keeps it.
///
/// Holds the referrer's node and the keys the participant addresses its notes to, which a wallet
/// restored from its mnemonic finds there. They are as the referrer's invitation gave them; the
/// program does not authenticate them.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Referrer {
    pub node: NodeId,
    pub npk: NullifierPublicKey,
    pub vpk: ViewingPublicKey,
}

impl From<Invitation> for Referrer {
    fn from(invitation: Invitation) -> Self {
        Self {
            node: invitation.parent_node,
            npk: invitation.npk,
            vpk: invitation.vpk,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Registry {
    pub registered_nodes: BTreeSet<NodeId>,
    pub epoch: Epoch,
    pub active_nodes: BTreeSet<NodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Participant {
    pub node: NodeId,
    pub referrer: Option<Referrer>,
    /// Each child and the epochs already settled for it, as sorted, disjoint inclusive ranges.
    /// Epochs before it registered count as settled.
    pub children: BTreeMap<NodeId, Vec<(Epoch, Epoch)>>,
    pub reward_balance: Points,
}

impl Participant {
    #[must_use]
    pub const fn new(node: NodeId, referrer: Option<Referrer>) -> Self {
        Self {
            node,
            referrer,
            children: BTreeMap::new(),
            reward_balance: 0,
        }
    }

    /// Adopts `node` as a child that registered in epoch `since`, unless already adopted. The
    /// epochs before `since` count as settled for it.
    pub fn adopt(&mut self, node: NodeId, since: Epoch) {
        self.children.entry(node).or_insert_with(|| {
            since
                .checked_sub(1)
                .map(|before| vec![(0, before)])
                .unwrap_or_default()
        });
    }

    /// The referrer's node, if this participant has a referrer.
    #[must_use]
    pub fn referrer_node(&self) -> Option<NodeId> {
        self.referrer.as_ref().map(|referrer| referrer.node)
    }

    /// Settles one epoch: adopts the announced children, adds the credits earned in the epoch, and
    /// settles the epoch for every child not yet settled for it, paying one point for each of those
    /// active in it. Returns what it earned.
    ///
    /// A child counts from the epoch it registered in, so it never pays for activity before it
    /// joined; and each epoch settles a child once, so epochs may be claimed in any order and
    /// never pay twice.
    #[must_use]
    pub fn claim(&mut self, claim: &EpochClaim) -> Points {
        assert!(
            claim.active.contains(&self.node),
            "claimant did not participate in the published epoch"
        );
        let mut total: Points = 0;
        for note in &claim.notes {
            match *note {
                State::Child {
                    node,
                    referrer,
                    since,
                } => {
                    assert_eq!(referrer, self.node, "child is announced to another node");
                    self.adopt(node, since);
                }
                State::Credit { .. } => {
                    total = total
                        .checked_add(self.credit(note))
                        .expect("credit total fits in u128");
                }
                State::Registry(_)
                | State::Participant(_)
                | State::CashOut { .. }
                | State::Publication { .. } => {
                    panic!("note does not hold a child or a credit")
                }
            }
        }
        for (child, settled) in &mut self.children {
            if settle(settled, claim.epoch) && claim.active.contains(child) {
                total = total.checked_add(1).expect("claim total fits in u128");
            }
        }
        self.add_reward(total)
    }

    fn credit(&self, note: &State) -> Points {
        let State::Credit {
            recipient_node,
            amount,
            ..
        } = *note
        else {
            panic!("note does not hold a credit")
        };
        assert_eq!(
            recipient_node, self.node,
            "credit is addressed to another node"
        );
        amount
    }

    const fn add_reward(&mut self, total: Points) -> Points {
        self.reward_balance = self
            .reward_balance
            .checked_add(total)
            .expect("reward balance fits in u128");
        total
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum State {
    Registry(Registry),
    Participant(Participant),
    Child {
        node: NodeId,
        referrer: NodeId,
        /// The epoch the child registered in, from which it counts.
        since: Epoch,
    },
    Credit {
        recipient_node: NodeId,
        amount: Points,
        epoch: Epoch,
        active_digest: [u8; 32],
    },
    CashOut {
        points: Points,
    },
    /// The digest of an epoch's active set, archived when the epoch is published and never changed.
    Publication {
        epoch: Epoch,
        active_digest: [u8; 32],
    },
}

impl State {
    #[must_use]
    pub fn to_data(&self) -> ShardData {
        borsh::to_vec(self)
            .expect("borsh serialization is infallible")
            .try_into()
            .expect("referral state fits in account data")
    }

    #[must_use]
    pub fn decode(data: &ShardData) -> Option<Self> {
        (!data.is_empty())
            .then(|| borsh::from_slice(data.as_ref()).ok())
            .flatten()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ParticipantAuthorizationV1 {
    pub uplink_account: AccountId,
    pub node: NodeId,
    pub participant_account: AccountId,
    pub referrer: Option<NodeId>,
}

impl ParticipantAuthorizationV1 {
    #[must_use]
    pub const fn new(
        uplink_account: AccountId,
        node: NodeId,
        participant_account: AccountId,
        referrer: Option<NodeId>,
    ) -> Self {
        Self {
            uplink_account,
            node,
            participant_account,
            referrer,
        }
    }

    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        let mut message = AUTHORIZATION_DOMAIN.to_vec();
        message.extend_from_slice(&borsh::to_vec(self).expect("borsh serialization is infallible"));
        message
    }

    #[must_use]
    pub fn verify(&self, signature: &[u8; 64]) -> bool {
        self.node.verifying_key().is_some_and(|key| {
            key.verify_strict(
                &self.message(),
                &ed25519_dalek::Signature::from_bytes(signature),
            )
            .is_ok()
        })
    }
}

/// What a claim asserts about one epoch.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EpochClaim {
    pub epoch: Epoch,
    pub active: BTreeSet<NodeId>,
    /// The notes this epoch consumes: announced children, and credits earned in this epoch.
    pub notes: Vec<State>,
    /// What the participant earns in this epoch, forwarded to its referrer if active in it.
    pub total: Points,
}

impl EpochClaim {
    /// The referrer this epoch's total is forwarded to: `referrer`, if active in this epoch.
    #[must_use]
    pub fn forward_to(&self, referrer: Option<NodeId>) -> Option<NodeId> {
        referrer.filter(|node| self.active.contains(node))
    }
}

/// A claim over one or more published epochs, in strictly increasing order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Claim {
    pub epochs: Vec<EpochClaim>,
    pub referrer: Option<NodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    Register {
        node: NodeId,
        referrer: Option<Referrer>,
        node_signature: [u8; 64],
        pool: BTreeSet<NodeId>,
        /// The registry's current epoch, which the participant and its child note record.
        epoch: Epoch,
    },
    Publish {
        epoch: Epoch,
        active: BTreeSet<NodeId>,
    },
    Claim(Claim),
    CashOut {
        node: NodeId,
        points: Points,
        blinding_factor: [u8; 32],
    },
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    Publish {
        epoch: Epoch,
        active: BTreeSet<NodeId>,
    },
    Register {
        node: NodeId,
        pool: BTreeSet<NodeId>,
        epoch: Epoch,
    },
    /// Applied to an epoch's publication account.
    CheckEpoch {
        epoch: Epoch,
        active_digest: [u8; 32],
    },
    Create(State),
    Claim(Claim),
    Consume(State),
    CashOutBurn {
        node: NodeId,
        points: Points,
    },
}

/// Marks `epoch` settled in `settled`, sorted, disjoint inclusive ranges that stay merged.
/// Returns whether it was not settled yet.
fn settle(settled: &mut Vec<(Epoch, Epoch)>, epoch: Epoch) -> bool {
    if settled
        .iter()
        .any(|&(first, last)| first <= epoch && epoch <= last)
    {
        return false;
    }
    settled.push((epoch, epoch));
    settled.sort_unstable();
    let mut merged: Vec<(Epoch, Epoch)> = Vec::with_capacity(settled.len());
    for &(first, last) in settled.iter() {
        match merged.last_mut() {
            Some(previous) if first <= previous.1.saturating_add(1) => {
                previous.1 = previous.1.max(last);
            }
            _ => merged.push((first, last)),
        }
    }
    *settled = merged;
    true
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    Impl::hash_bytes(bytes)
        .as_bytes()
        .try_into()
        .expect("Hash output must be exactly 32 bytes long")
}

#[must_use]
pub fn active_digest(active: &BTreeSet<NodeId>) -> [u8; 32] {
    sha256(&borsh::to_vec(active).expect("borsh serialization is infallible"))
}

/// The blinding factor of a participant's `index`-th cash-out receipt.
///
/// Derived off-chain from the node's receipt secret, so only the node's operator can find the
/// receipts and open them, and can find them again from the node key alone. The program never
/// sees the secret: a cash-out carries only the factor. Computed as
/// `SHA256("Uplink/BlindingFactor/v1\0" || receipt_secret || uplink_account ||
/// participant || index as 8 little-endian bytes)`.
#[must_use]
pub fn blinding_factor(
    receipt_secret: &[u8; 32],
    uplink_account: AccountId,
    participant: AccountId,
    index: u64,
) -> [u8; 32] {
    let mut preimage = [0; 25 + 32 + 32 + 32 + 8];
    preimage[..25].copy_from_slice(BLINDING_FACTOR_DOMAIN);
    preimage[25..57].copy_from_slice(receipt_secret);
    preimage[57..89].copy_from_slice(uplink_account.as_ref());
    preimage[89..121].copy_from_slice(participant.as_ref());
    preimage[121..].copy_from_slice(&index.to_le_bytes());
    sha256(&preimage)
}

/// The account publication `epoch`'s digest is archived at: a public PDA of the program, seeded by
/// `SHA256("Uplink/Epoch/v1\0" || epoch as 4 little-endian bytes)`.
#[must_use]
pub fn epoch_account(uplink_account: AccountId, epoch: Epoch) -> AccountId {
    let mut preimage = [0; 16 + 4];
    preimage[..16].copy_from_slice(EPOCH_DOMAIN);
    preimage[16..].copy_from_slice(&epoch.to_le_bytes());
    AccountId::for_public_pda(&uplink_account, &PdaSeed::new(sha256(&preimage)))
}

#[must_use]
pub fn cash_out_receipt(
    uplink_account: AccountId,
    node: NodeId,
    blinding_factor: [u8; 32],
) -> AccountId {
    let mut preimage = [0; 18 + 32 + 32];
    preimage[..18].copy_from_slice(CASH_OUT_DOMAIN);
    preimage[18..50].copy_from_slice(&node.to_bytes());
    preimage[50..].copy_from_slice(&blinding_factor);
    AccountId::for_public_pda(&uplink_account, &PdaSeed::new(sha256(&preimage)))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    const PROGRAM: AccountId = AccountId::new([9; 32]);
    const NODE: NodeId = NodeId::new([7; 32]);
    const PARTICIPANT: AccountId = AccountId::new([3; 32]);

    #[test]
    fn the_authorization_message_is_the_prefixed_encoding_itself() {
        let authorization = ParticipantAuthorizationV1::new(PROGRAM, NODE, PARTICIPANT, None);
        let message = authorization.message();

        assert_eq!(message.len(), 128);
        assert_eq!(&message[..31], AUTHORIZATION_DOMAIN);
        assert_eq!(&message[31..63], PROGRAM.as_ref());
        assert_eq!(
            sha256(&message),
            [
                0x88, 0xb3, 0x18, 0x95, 0x99, 0xfb, 0x92, 0x44, 0x33, 0x43, 0x44, 0xa9, 0xb8, 0x58,
                0x1e, 0x1f, 0x7e, 0x8f, 0x85, 0xbb, 0xb7, 0x79, 0x35, 0xd0, 0xeb, 0xe5, 0x48, 0xaa,
                0xba, 0xb2, 0x7e, 0xe7,
            ]
        );
    }

    #[test]
    fn a_signature_over_the_bare_digest_is_rejected() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let node = NodeId::new(key.verifying_key().to_bytes());
        let authorization = ParticipantAuthorizationV1::new(PROGRAM, node, PARTICIPANT, None);

        assert!(authorization.verify(&key.sign(&authorization.message()).to_bytes()));
        assert!(!authorization.verify(&key.sign(&sha256(&authorization.message())).to_bytes()));
    }

    #[test]
    fn authorization_rejects_every_tampered_field() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let node = NodeId::new(key.verifying_key().to_bytes());
        let parent = NodeId::new(SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes());
        let authorization =
            ParticipantAuthorizationV1::new(PROGRAM, node, PARTICIPANT, Some(parent));
        let signature = key.sign(&authorization.message()).to_bytes();

        assert!(authorization.verify(&signature));

        let tampered = [
            ParticipantAuthorizationV1 {
                uplink_account: AccountId::new([10; 32]),
                ..authorization
            },
            ParticipantAuthorizationV1 {
                participant_account: AccountId::new([4; 32]),
                ..authorization
            },
            ParticipantAuthorizationV1 {
                referrer: None,
                ..authorization
            },
            ParticipantAuthorizationV1 {
                referrer: Some(node),
                ..authorization
            },
        ];
        for candidate in tampered {
            assert!(!candidate.verify(&signature));
        }

        let other = SigningKey::from_bytes(&[2; 32]);
        assert!(!authorization.verify(&other.sign(&authorization.message()).to_bytes()));
    }

    #[test]
    fn state_decoding_rejects_empty_and_trailing_bytes() {
        let state = State::Child {
            node: NODE,
            referrer: NodeId::new([8; 32]),
            since: 3,
        };
        let data = state.to_data();
        assert_eq!(State::decode(&data), Some(state));
        assert_eq!(State::decode(&ShardData::empty()), None);

        let mut trailing = data.to_vec();
        trailing.push(0);
        assert_eq!(State::decode(&trailing.try_into().unwrap()), None);
    }

    const fn child(node: NodeId) -> State {
        State::Child {
            node,
            referrer: NODE,
            since: 0,
        }
    }

    fn epoch(epoch: Epoch, active: &[NodeId], notes: Vec<State>) -> EpochClaim {
        EpochClaim {
            epoch,
            active: active.iter().copied().collect(),
            notes,
            total: 0,
        }
    }

    const fn credit(amount: u128) -> State {
        State::Credit {
            recipient_node: NODE,
            amount,
            epoch: 1,
            active_digest: [0; 32],
        }
    }

    #[test]
    fn claim_pays_each_active_child_once_per_publication_plus_its_credits() {
        let (a, b) = (NodeId::new([1; 32]), NodeId::new([2; 32]));
        let mut participant = Participant::new(NODE, None);
        let first_active = [a, NODE];
        let credit = State::Credit {
            recipient_node: NODE,
            amount: 4,
            epoch: 1,
            active_digest: active_digest(&first_active.into_iter().collect()),
        };

        assert_eq!(
            participant.claim(&epoch(1, &first_active, vec![child(a), child(b), credit])),
            5
        );
        // Epoch 1 is settled for both children, though only the active one was paid for it.
        assert_eq!(
            participant.children,
            BTreeMap::from([(a, vec![(1, 1)]), (b, vec![(1, 1)])])
        );
        assert_eq!(
            participant.claim(&epoch(1, &first_active, vec![child(a)])),
            0
        );
        assert_eq!(participant.claim(&epoch(2, &[a, b, NODE], vec![])), 2);
        assert_eq!(participant.claim(&epoch(1, &first_active, vec![])), 0);
        assert_eq!(participant.reward_balance, 7);
    }

    #[test]
    fn a_child_counts_from_the_epoch_it_registered_in() {
        let a = NodeId::new([1; 32]);
        let mut participant = Participant::new(NODE, None);
        let late = State::Child {
            node: a,
            referrer: NODE,
            since: 3,
        };

        // Active since epoch 1, but it registered in epoch 3: epochs 1 and 2 pay nothing for it.
        assert_eq!(participant.claim(&epoch(1, &[a, NODE], vec![late])), 0);
        assert_eq!(participant.claim(&epoch(2, &[a, NODE], vec![])), 0);
        assert_eq!(participant.claim(&epoch(3, &[a, NODE], vec![])), 1);
        assert_eq!(participant.reward_balance, 1);
    }

    #[test]
    fn epochs_claimed_out_of_order_pay_each_child_once_per_epoch() {
        let a = NodeId::new([1; 32]);
        let mut participant = Participant::new(NODE, None);

        assert_eq!(participant.claim(&epoch(2, &[a, NODE], vec![child(a)])), 1);
        // Epoch 1 is claimed late, and still pays its child point and its credits.
        assert_eq!(participant.claim(&epoch(1, &[a, NODE], vec![credit(4)])), 5);
        assert_eq!(participant.claim(&epoch(2, &[a, NODE], vec![])), 0);
        assert_eq!(participant.claim(&epoch(1, &[a, NODE], vec![])), 0);
        assert_eq!(participant.children, BTreeMap::from([(a, vec![(1, 2)])]));
        assert_eq!(participant.reward_balance, 6);
    }

    #[test]
    fn a_child_adopted_late_is_still_paid_for_epochs_claimed_before() {
        let a = NodeId::new([1; 32]);
        let b = NodeId::new([2; 32]);
        let mut participant = Participant::new(NODE, None);

        // Epoch 2 is claimed for b alone; a's announcement arrives only with epoch 3.
        assert_eq!(
            participant.claim(&epoch(2, &[a, b, NODE], vec![child(b)])),
            1
        );
        assert_eq!(
            participant.claim(&epoch(3, &[a, b, NODE], vec![child(a)])),
            2
        );
        assert_eq!(participant.claim(&epoch(2, &[a, b, NODE], vec![])), 1);
        assert_eq!(participant.reward_balance, 4);
    }

    #[test]
    fn settling_merges_ranges() {
        let mut settled = vec![(0, 2), (5, 6)];

        assert!(!settle(&mut settled, 1));
        assert!(settle(&mut settled, 3));
        assert_eq!(
            settled,
            vec![(0, 3), (5, 6)],
            "extends the range it follows"
        );
        assert!(settle(&mut settled, 8));
        assert_eq!(
            settled,
            vec![(0, 3), (5, 6), (8, 8)],
            "opens a range in a gap"
        );
        assert!(settle(&mut settled, 4));
        assert_eq!(
            settled,
            vec![(0, 6), (8, 8)],
            "joins the ranges it closes the gap between"
        );
        assert!(settle(&mut settled, 7));
        assert_eq!(settled, vec![(0, 8)]);
    }

    #[test]
    #[should_panic(expected = "child is announced to another node")]
    fn claim_rejects_a_child_announced_to_another_node() {
        let other = NodeId::new([1; 32]);
        let mut participant = Participant::new(NODE, None);
        let _total = participant.claim(&epoch(
            1,
            &[NODE],
            vec![State::Child {
                node: other,
                referrer: other,
                since: 0,
            }],
        ));
    }

    #[test]
    fn the_cash_out_receipt_is_the_program_pda_of_the_prefixed_node_and_factor() {
        let factor = [5; 32];
        let receipt = cash_out_receipt(PROGRAM, NODE, factor);

        assert_eq!(
            receipt,
            AccountId::new([
                0x94, 0x30, 0x6d, 0xfc, 0xd2, 0xef, 0x5c, 0x72, 0xb7, 0xe8, 0xf8, 0xd5, 0xb1, 0x5c,
                0x76, 0xa4, 0x78, 0xe7, 0x8e, 0x0f, 0x5c, 0x56, 0xbd, 0xe1, 0x10, 0xeb, 0xda, 0x9b,
                0x2f, 0xf8, 0x63, 0x8d,
            ])
        );
        assert_ne!(
            cash_out_receipt(AccountId::new([10; 32]), NODE, factor),
            receipt
        );
        assert_ne!(
            cash_out_receipt(PROGRAM, NodeId::new([8; 32]), factor),
            receipt
        );
        assert_ne!(cash_out_receipt(PROGRAM, NODE, [6; 32]), receipt);
    }

    #[test]
    fn the_blinding_factor_is_the_prefixed_hash_of_the_secret_deployment_participant_and_index() {
        let secret = [1; 32];
        let (program, participant) = (AccountId::new([2; 32]), AccountId::new([3; 32]));

        assert_eq!(
            blinding_factor(&secret, program, participant, 0),
            [
                0xaa, 0x3c, 0x9d, 0xdb, 0x33, 0xfe, 0x51, 0x1d, 0x9a, 0xb4, 0x13, 0x78, 0x01, 0xce,
                0xe4, 0x1e, 0x83, 0x25, 0xa7, 0xc1, 0xac, 0x73, 0xf7, 0x45, 0xbb, 0xe5, 0x09, 0xe5,
                0x79, 0xd7, 0xd9, 0xf0,
            ]
        );
        assert_eq!(
            blinding_factor(&secret, program, participant, 1),
            [
                0xf0, 0x35, 0x67, 0x1f, 0xba, 0xcf, 0xfc, 0x4d, 0x18, 0x33, 0x5c, 0x28, 0x8c, 0x9b,
                0x7a, 0x4b, 0xaa, 0x38, 0xef, 0x48, 0x3c, 0x64, 0xbc, 0x78, 0x68, 0xed, 0x49, 0x8a,
                0x09, 0xc5, 0x13, 0x66,
            ]
        );
        let factor = blinding_factor(&secret, program, participant, 0);
        assert_ne!(blinding_factor(&[4; 32], program, participant, 0), factor);
        assert_ne!(
            blinding_factor(&secret, AccountId::new([5; 32]), participant, 0),
            factor
        );
        assert_ne!(
            blinding_factor(&secret, program, AccountId::new([6; 32]), 0),
            factor
        );
    }

    #[test]
    #[should_panic(expected = "note does not hold a child or a credit")]
    fn claim_rejects_a_cash_out_receipt_as_a_note() {
        let mut participant = Participant::new(NODE, None);
        let _total = participant.claim(&epoch(1, &[NODE], vec![State::CashOut { points: 3 }]));
    }

    #[test]
    #[should_panic(expected = "credit is addressed to another node")]
    fn claim_rejects_a_credit_for_another_node() {
        let other = NodeId::new([1; 32]);
        let mut participant = Participant::new(NODE, None);
        let _total = participant.claim(&epoch(
            1,
            &[NODE],
            vec![State::Credit {
                recipient_node: other,
                amount: 1,
                epoch: 1,
                active_digest: [0; 32],
            }],
        ));
    }

    #[test]
    #[should_panic(expected = "claimant did not participate in the published epoch")]
    fn claim_rejects_an_inactive_claimant() {
        let a = NodeId::new([1; 32]);
        let mut participant = Participant::new(NODE, None);
        let _total = participant.claim(&epoch(1, &[a], vec![child(a), credit(4)]));
    }

    #[test]
    fn the_epoch_account_is_the_program_pda_of_the_prefixed_epoch() {
        assert_eq!(
            epoch_account(PROGRAM, 1),
            AccountId::new([
                0xc9, 0x62, 0x08, 0x99, 0xc1, 0xb7, 0x6d, 0xac, 0xd7, 0xe5, 0xc7, 0x38, 0x9a, 0x00,
                0x10, 0xcb, 0x22, 0x8d, 0x4e, 0x36, 0x6c, 0x30, 0xc1, 0x0a, 0x90, 0xb2, 0x2a, 0xcf,
                0x24, 0x8b, 0xef, 0xc9,
            ])
        );
        assert_ne!(epoch_account(PROGRAM, 2), epoch_account(PROGRAM, 1));
        assert_ne!(
            epoch_account(AccountId::new([10; 32]), 1),
            epoch_account(PROGRAM, 1)
        );
    }
}
