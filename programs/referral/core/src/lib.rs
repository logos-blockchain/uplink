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

pub const PROTOTYPE_ORACLE_SIGNING_KEY: [u8; 32] = [11; 32];

const AUTHORIZATION_DOMAIN: &[u8; 37] = b"LEZ/Referral/AuthorizeParticipant/v1\0";

const CASH_OUT_DOMAIN: &[u8; 24] = b"LEZ/Referral/CashOut/v1\0";

const BLINDING_FACTOR_DOMAIN: &[u8; 31] = b"LEZ/Referral/BlindingFactor/v1\0";

/// An epoch, numbered by the oracle's publications.
pub type Epoch = u32;

/// Referral reward points. Not a native token amount: points move only inside this program.
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

/// A participant's referrer: its node, and the keys the participant addresses its notes to.
///
/// Kept in the participant's state so that a wallet restored from its mnemonic can still address
/// the referrer, without the invitation it registered with. The keys are as the invitation gave
/// them; the program does not authenticate them.
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
    pub nodes: BTreeSet<NodeId>,
    pub epoch: Epoch,
    pub active: BTreeSet<NodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Participant {
    pub node: NodeId,
    pub referrer: Option<Referrer>,
    pub children: BTreeMap<NodeId, Epoch>,
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

    /// The referrer's node, if this participant has a referrer.
    #[must_use]
    pub fn referrer_node(&self) -> Option<NodeId> {
        self.referrer.as_ref().map(|referrer| referrer.node)
    }

    #[must_use]
    pub fn claim(&mut self, epoch: Epoch, active: &BTreeSet<NodeId>, notes: &[State]) -> Points {
        self.assert_active(active);
        let mut total: Points = 0;
        for note in notes {
            match *note {
                State::Child { node, referrer } => {
                    assert_eq!(referrer, self.node, "child is announced to another node");
                    self.children.entry(node).or_insert(0);
                }
                State::Credit { .. } => {
                    total = total
                        .checked_add(self.credit(note))
                        .expect("credit total fits in u128");
                }
                State::Registry(_) | State::Participant(_) | State::CashOut { .. } => {
                    panic!("note does not hold a child or a credit")
                }
            }
        }
        for (child, last) in &mut self.children {
            if *last < epoch && active.contains(child) {
                *last = epoch;
                total = total.checked_add(1).expect("claim total fits in u128");
            }
        }
        self.add_reward(total)
    }

    #[must_use]
    pub fn collect_credits(&mut self, active: &BTreeSet<NodeId>, notes: &[State]) -> Points {
        self.assert_active(active);
        let total = notes
            .iter()
            .map(|note| self.credit(note))
            .try_fold(0, Points::checked_add)
            .expect("credit total fits in u128");
        self.add_reward(total)
    }

    fn assert_active(&self, active: &BTreeSet<NodeId>) {
        assert!(
            active.contains(&self.node),
            "claimant did not participate in the published epoch"
        );
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
    pub program_account: AccountId,
    pub node: NodeId,
    pub participant_account: AccountId,
    pub referrer: Option<NodeId>,
}

impl ParticipantAuthorizationV1 {
    #[must_use]
    pub const fn new(
        program_account: AccountId,
        node: NodeId,
        participant_account: AccountId,
        referrer: Option<NodeId>,
    ) -> Self {
        Self {
            program_account,
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

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Claim {
    pub epoch: Epoch,
    pub active: BTreeSet<NodeId>,
    pub notes: Vec<State>,
    pub total: Points,
    pub referrer: Option<NodeId>,
}

impl Claim {
    #[must_use]
    pub fn forward_to(&self) -> Option<NodeId> {
        self.referrer.filter(|node| self.active.contains(node))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    Register {
        node: NodeId,
        referrer: Option<Referrer>,
        node_signature: [u8; 64],
        pool: BTreeSet<NodeId>,
    },
    Publish {
        epoch: Epoch,
        active: BTreeSet<NodeId>,
    },
    Claim(Claim),
    CollectCredits(Claim),
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
    },
    CheckEpoch {
        epoch: Epoch,
        active_digest: [u8; 32],
    },
    Create(State),
    Claim(Claim),
    CollectCredits(Claim),
    Consume(State),
    CashOutBurn {
        node: NodeId,
        points: Points,
    },
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
/// `SHA256("LEZ/Referral/BlindingFactor/v1\0" || receipt_secret || program_account ||
/// participant || index as 8 little-endian bytes)`.
#[must_use]
pub fn blinding_factor(
    receipt_secret: &[u8; 32],
    program_account: AccountId,
    participant: AccountId,
    index: u64,
) -> [u8; 32] {
    let mut preimage = [0; 31 + 32 + 32 + 32 + 8];
    preimage[..31].copy_from_slice(BLINDING_FACTOR_DOMAIN);
    preimage[31..63].copy_from_slice(receipt_secret);
    preimage[63..95].copy_from_slice(program_account.as_ref());
    preimage[95..127].copy_from_slice(participant.as_ref());
    preimage[127..].copy_from_slice(&index.to_le_bytes());
    sha256(&preimage)
}

#[must_use]
pub fn cash_out_receipt(
    program_account: AccountId,
    node: NodeId,
    blinding_factor: [u8; 32],
) -> AccountId {
    let mut preimage = [0; 24 + 32 + 32];
    preimage[..24].copy_from_slice(CASH_OUT_DOMAIN);
    preimage[24..56].copy_from_slice(&node.to_bytes());
    preimage[56..].copy_from_slice(&blinding_factor);
    AccountId::for_public_pda(&program_account, &PdaSeed::new(sha256(&preimage)))
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

        assert_eq!(message.len(), 134);
        assert_eq!(&message[..37], AUTHORIZATION_DOMAIN);
        assert_eq!(&message[37..69], PROGRAM.as_ref());
        assert_eq!(
            sha256(&message),
            [
                0x0f, 0x69, 0x7b, 0x3b, 0xaa, 0x83, 0x74, 0x9f, 0xa7, 0x8f, 0x96, 0x17, 0xa9, 0x35,
                0xaa, 0x4c, 0x76, 0x24, 0x08, 0xe8, 0x28, 0xc2, 0x63, 0x21, 0xc5, 0xea, 0xbc, 0x5b,
                0x21, 0x32, 0xed, 0xf1,
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
                program_account: AccountId::new([10; 32]),
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
        let first_active = BTreeSet::from([a, NODE]);
        let credit = State::Credit {
            recipient_node: NODE,
            amount: 4,
            epoch: 1,
            active_digest: active_digest(&first_active),
        };

        assert_eq!(
            participant.claim(1, &first_active, &[child(a), child(b), credit]),
            5
        );
        assert_eq!(participant.children, BTreeMap::from([(a, 1), (b, 0)]));
        assert_eq!(participant.claim(1, &first_active, &[child(a)]), 0);
        assert_eq!(participant.claim(2, &BTreeSet::from([a, b, NODE]), &[]), 2);
        assert_eq!(participant.claim(1, &first_active, &[]), 0);
        assert_eq!(participant.reward_balance, 7);
    }

    #[test]
    #[should_panic(expected = "child is announced to another node")]
    fn claim_rejects_a_child_announced_to_another_node() {
        let other = NodeId::new([1; 32]);
        let mut participant = Participant::new(NODE, None);
        let _total = participant.claim(
            1,
            &BTreeSet::from([NODE]),
            &[State::Child {
                node: other,
                referrer: other,
            }],
        );
    }

    #[test]
    fn the_cash_out_receipt_is_the_program_pda_of_the_prefixed_node_and_factor() {
        let factor = [5; 32];
        let receipt = cash_out_receipt(PROGRAM, NODE, factor);

        assert_eq!(
            receipt,
            AccountId::new([
                0xc7, 0xb1, 0x6c, 0x9d, 0xe5, 0x40, 0xb3, 0x22, 0x17, 0xe2, 0x03, 0xd5, 0x6c, 0xd9,
                0xc7, 0x63, 0x74, 0x63, 0x71, 0x26, 0xcb, 0x8f, 0x66, 0x30, 0x38, 0x11, 0x3f, 0xca,
                0x19, 0x08, 0x01, 0xff,
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
                0x26, 0x61, 0x03, 0x8b, 0x4e, 0xd1, 0x40, 0xac, 0x06, 0x5f, 0x09, 0xda, 0x28, 0x0c,
                0x2e, 0x43, 0xd5, 0x0e, 0xd6, 0x97, 0x9c, 0x0c, 0x93, 0x62, 0x10, 0xd7, 0x14, 0x96,
                0x92, 0x78, 0x1d, 0x2c,
            ]
        );
        assert_eq!(
            blinding_factor(&secret, program, participant, 1),
            [
                0xe5, 0xbf, 0x2b, 0xcf, 0x5d, 0x51, 0xfc, 0x9e, 0xf4, 0x37, 0x50, 0xda, 0xea, 0x75,
                0xf4, 0x1f, 0x90, 0x6d, 0x3b, 0xd9, 0x39, 0x32, 0xd4, 0x3c, 0x48, 0x96, 0xbe, 0xc3,
                0xbb, 0x3c, 0x7c, 0x89,
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
        let _total = participant.claim(1, &BTreeSet::from([NODE]), &[State::CashOut { points: 3 }]);
    }

    #[test]
    #[should_panic(expected = "credit is addressed to another node")]
    fn claim_rejects_a_credit_for_another_node() {
        let other = NodeId::new([1; 32]);
        let mut participant = Participant::new(NODE, None);
        let _total = participant.claim(
            1,
            &BTreeSet::from([NODE]),
            &[State::Credit {
                recipient_node: other,
                amount: 1,
                epoch: 1,
                active_digest: [0; 32],
            }],
        );
    }

    #[test]
    #[should_panic(expected = "claimant did not participate in the published epoch")]
    fn claim_rejects_an_inactive_claimant() {
        let a = NodeId::new([1; 32]);
        let mut participant = Participant::new(NODE, None);
        let _total = participant.claim(1, &BTreeSet::from([a]), &[child(a), credit(4)]);
    }

    #[test]
    #[should_panic(expected = "claimant did not participate in the published epoch")]
    fn collecting_credits_rejects_an_inactive_claimant() {
        let mut participant = Participant::new(NODE, None);
        let _total = participant.collect_credits(&BTreeSet::new(), &[credit(4)]);
    }

    #[test]
    fn collecting_credits_pays_only_the_credits() {
        let a = NodeId::new([1; 32]);
        let mut participant = Participant {
            children: BTreeMap::from([(a, 0)]),
            ..Participant::new(NODE, None)
        };

        assert_eq!(
            participant.collect_credits(&BTreeSet::from([a, NODE]), &[credit(4), credit(3)]),
            7
        );
        assert_eq!(participant.children, BTreeMap::from([(a, 0)]));
        assert_eq!(participant.reward_balance, 7);
    }

    #[test]
    #[should_panic(expected = "note does not hold a credit")]
    fn collecting_credits_rejects_an_announcement() {
        let mut participant = Participant::new(NODE, None);
        let _total = participant.collect_credits(
            &BTreeSet::from([NODE]),
            &[credit(1), child(NodeId::new([1; 32]))],
        );
    }
}
