#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};

use lee_core::{
    NullifierPublicKey,
    account::{AccountId, ShardData},
    encryption::ViewingPublicKey,
    program::{AccountMeta, Plan, PlanInput, ShardEffect},
};
use referral_core::{
    Claim, Effect, Epoch, EpochClaim, Instruction, NodeId, ORACLE_ACCOUNT_ID, Participant,
    ParticipantAuthorizationV1, Referrer, Registry, State, active_digest, cash_out_receipt,
    ed25519_dalek::{Signer as _, SigningKey},
    epoch_account,
};

const PROGRAM: AccountId = AccountId::new([9; 32]);

fn node(seed: u8) -> (SigningKey, NodeId) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id = NodeId::new(key.verifying_key().to_bytes());
    (key, id)
}

/// `node` as a referrer, with keys derived from its id.
fn referrer(node: NodeId) -> Referrer {
    let bytes = node.to_bytes();
    Referrer {
        node,
        npk: NullifierPublicKey(bytes),
        vpk: ViewingPublicKey::from_seed(&bytes, &bytes),
    }
}

fn account(seed: u8) -> AccountId {
    AccountId::new([seed; 32])
}

fn meta(account_id: AccountId, is_authorized: bool) -> AccountMeta {
    AccountMeta::new(account_id, is_authorized, PROGRAM)
}

/// The publication account of `epoch`, as a claim or a publish mentions it.
fn publication(epoch: Epoch) -> AccountMeta {
    meta(epoch_account(PROGRAM, epoch), false)
}

fn published(epoch: Epoch, active: &BTreeSet<NodeId>) -> ShardData {
    State::Publication {
        epoch,
        active_digest: active_digest(active),
    }
    .to_data()
}

fn signature(
    key: &SigningKey,
    node: NodeId,
    participant: AccountId,
    referrer: Option<NodeId>,
) -> [u8; 64] {
    let authorization = ParticipantAuthorizationV1::new(PROGRAM, node, participant, referrer);
    key.sign(&authorization.message()).to_bytes()
}

fn plan_for(accounts: Vec<AccountMeta>, instruction: Instruction) -> Plan {
    crate::plan(
        &PlanInput {
            self_account_id: PROGRAM,
            caller_account_id: None,
            accounts,
            instruction_data: Vec::new(),
        },
        instruction,
    )
}

fn registry_data(registry: Registry) -> ShardData {
    State::Registry(registry).to_data()
}

fn epoch_claim(
    epoch: Epoch,
    active: &BTreeSet<NodeId>,
    notes: Vec<State>,
    total: u128,
) -> EpochClaim {
    EpochClaim {
        epoch,
        active: active.clone(),
        notes,
        total,
    }
}

/// A one-epoch claim of epoch 1 with nothing in it but its total.
fn claim(total: u128, active: &[NodeId], referrer: Option<NodeId>) -> Claim {
    Claim {
        epochs: vec![epoch_claim(
            1,
            &active.iter().copied().collect(),
            vec![],
            total,
        )],
        referrer,
    }
}

// === Publish ===

#[test]
fn publish_archives_the_epoch_and_replaces_the_active_set() {
    let (_, a) = node(1);
    let active = BTreeSet::from([a]);
    let effect = Effect::Publish {
        epoch: 2,
        active: active.clone(),
    };
    let overwrite = Effect::OverwritePublication {
        epoch: 2,
        active_digest: active_digest(&active),
    };

    let plan = plan_for(
        vec![meta(ORACLE_ACCOUNT_ID, true), publication(2)],
        Instruction::Publish {
            epoch: 2,
            active: active.clone(),
        },
    );
    assert_eq!(
        plan.output().effects,
        vec![
            ShardEffect::new(&meta(ORACLE_ACCOUNT_ID, true), &effect),
            ShardEffect::new(&publication(2), &overwrite),
        ]
    );

    let post = crate::apply(
        effect,
        &registry_data(Registry {
            registered_nodes: BTreeSet::from([a]),
            epoch: 1,
            active_nodes: BTreeSet::new(),
        }),
    )
    .expect("Publish writes the registry");
    assert_eq!(
        State::decode(&post),
        Some(State::Registry(Registry {
            registered_nodes: BTreeSet::from([a]),
            epoch: 2,
            active_nodes: active.clone(),
        }))
    );
    assert_eq!(
        crate::apply(overwrite, &ShardData::empty()),
        Some(published(2, &active))
    );
}

#[test]
#[should_panic(expected = "oracle authorization is missing")]
fn publish_rejects_an_unsigned_registry() {
    let _plan = plan_for(
        vec![meta(ORACLE_ACCOUNT_ID, false), publication(1)],
        Instruction::Publish {
            epoch: 1,
            active: BTreeSet::new(),
        },
    );
}

#[test]
#[should_panic(expected = "account must be the epoch's publication account")]
fn publish_archives_into_the_epochs_own_account() {
    let _plan = plan_for(
        vec![meta(ORACLE_ACCOUNT_ID, true), publication(2)],
        Instruction::Publish {
            epoch: 1,
            active: BTreeSet::new(),
        },
    );
}

#[test]
#[should_panic(expected = "a publication must advance the epoch")]
fn a_publication_must_advance_the_epoch() {
    let _written = crate::apply(
        Effect::Publish {
            epoch: 2,
            active: BTreeSet::new(),
        },
        &registry_data(Registry {
            epoch: 2,
            ..Registry::default()
        }),
    );
}

/// Publishes epoch 5 over `squatted`, the note a caller created in its publication account first.
fn publish_over(squatted: &Effect) {
    let squatted = crate::apply(squatted.clone(), &ShardData::empty())
        .expect("the note is created in the publication account");
    let active = BTreeSet::from([node(1).1]);
    assert_eq!(
        crate::apply(
            Effect::OverwritePublication {
                epoch: 5,
                active_digest: active_digest(&active),
            },
            &squatted,
        ),
        Some(published(5, &active))
    );
}

#[test]
fn a_child_note_squatted_in_a_publication_account_is_overwritten() {
    let (node_key, node_id) = node(1);
    let (_, parent) = node(2);
    let participant_account = account(11);

    // Nothing ties a Register's child note to its referrer, so a future epoch's publication
    // account can be named as one.
    let plan = plan_for(
        vec![
            meta(participant_account, true),
            meta(ORACLE_ACCOUNT_ID, false),
            publication(5),
        ],
        Instruction::Register {
            node: node_id,
            referrer: Some(referrer(parent)),
            node_signature: signature(&node_key, node_id, participant_account, Some(parent)),
            pool: BTreeSet::from([parent]),
            epoch: 3,
        },
    );
    let squat = Effect::Create(State::Child {
        node: node_id,
        referrer: parent,
        since: 3,
    });
    assert!(
        plan.output()
            .effects
            .contains(&ShardEffect::new(&publication(5), &squat))
    );

    publish_over(&squat);
}

#[test]
fn an_outgoing_credit_squatted_in_a_publication_account_is_overwritten() {
    let (_, me) = node(1);
    let (_, parent) = node(2);
    let participant_account = account(20);
    let active = BTreeSet::from([me, parent]);
    let claim = Claim {
        epochs: vec![epoch_claim(2, &active, vec![], 1)],
        referrer: Some(parent),
    };

    // Nothing ties a Claim's outgoing credit to the referrer either.
    let plan = plan_for(
        vec![
            meta(participant_account, true),
            publication(2),
            publication(5),
        ],
        Instruction::Claim(claim),
    );
    let squat = Effect::Create(State::Credit {
        recipient_node: parent,
        amount: 1,
        epoch: 2,
        active_digest: active_digest(&active),
    });
    assert!(
        plan.output()
            .effects
            .contains(&ShardEffect::new(&publication(5), &squat))
    );

    publish_over(&squat);
}

// === Register ===

#[test]
fn a_referred_register_announces_the_child_to_its_referrer() {
    let (node_key, node_id) = node(1);
    let (_, parent) = node(2);
    let (_, other) = node(3);
    let participant_account = account(11);
    let child_account = account(41);
    let pool = BTreeSet::from([parent, other]);

    let plan = plan_for(
        vec![
            meta(participant_account, true),
            meta(ORACLE_ACCOUNT_ID, false),
            meta(child_account, false),
        ],
        Instruction::Register {
            node: node_id,
            referrer: Some(referrer(parent)),
            node_signature: signature(&node_key, node_id, participant_account, Some(parent)),
            pool: pool.clone(),
            epoch: 3,
        },
    );

    assert_eq!(
        plan.output().effects,
        vec![
            ShardEffect::new(
                &meta(participant_account, true),
                &Effect::Create(State::Participant(Participant::new(
                    node_id,
                    Some(referrer(parent))
                ))),
            ),
            ShardEffect::new(
                &meta(ORACLE_ACCOUNT_ID, false),
                &Effect::Register {
                    node: node_id,
                    pool,
                    epoch: 3,
                },
            ),
            ShardEffect::new(
                &meta(child_account, false),
                &Effect::Create(State::Child {
                    node: node_id,
                    referrer: parent,
                    since: 3,
                }),
            ),
        ]
    );
}

#[test]
#[should_panic(
    expected = "a Register announces the participant to its referrer exactly when it has one"
)]
fn a_referred_register_requires_a_child_note_account() {
    let (_, parent) = node(2);
    let participant_account = account(11);

    let _plan = plan_for(
        vec![
            meta(participant_account, true),
            meta(ORACLE_ACCOUNT_ID, false),
        ],
        Instruction::Register {
            node: node(1).1,
            referrer: Some(referrer(parent)),
            node_signature: [0; 64],
            pool: BTreeSet::new(),
            epoch: 0,
        },
    );
}

#[test]
#[should_panic(expected = "node authorization signature is invalid")]
fn register_rejects_a_signature_addressed_to_another_participant() {
    let (node_key, node_id) = node(1);
    let signed_for = account(11);
    let submitted_as = account(12);

    let _plan = plan_for(
        vec![meta(submitted_as, true), meta(ORACLE_ACCOUNT_ID, false)],
        Instruction::Register {
            node: node_id,
            referrer: None,
            node_signature: signature(&node_key, node_id, signed_for, None),
            pool: BTreeSet::new(),
            epoch: 0,
        },
    );
}

#[test]
#[should_panic(expected = "the pool must contain the referrer")]
fn register_requires_the_referrer_in_its_pool() {
    let (node_key, node_id) = node(1);
    let (_, parent) = node(2);
    let (_, other) = node(3);
    let participant_account = account(11);
    let child_account = account(41);

    let _plan = plan_for(
        vec![
            meta(participant_account, true),
            meta(ORACLE_ACCOUNT_ID, false),
            meta(child_account, false),
        ],
        Instruction::Register {
            node: node_id,
            referrer: Some(referrer(parent)),
            node_signature: signature(&node_key, node_id, participant_account, Some(parent)),
            pool: BTreeSet::from([other]),
            epoch: 0,
        },
    );
}

#[test]
#[should_panic(expected = "the pool names an unregistered node")]
fn register_checks_the_pool_before_inserting_its_node() {
    let (_, node_id) = node(1);

    let _written = crate::apply(
        Effect::Register {
            node: node_id,
            pool: BTreeSet::from([node_id]),
            epoch: 0,
        },
        &registry_data(Registry::default()),
    );
}

#[test]
#[should_panic(expected = "node is already registered")]
fn register_rejects_an_already_registered_node() {
    let (_, node_id) = node(1);

    let _written = crate::apply(
        Effect::Register {
            node: node_id,
            pool: BTreeSet::new(),
            epoch: 0,
        },
        &registry_data(Registry {
            registered_nodes: BTreeSet::from([node_id]),
            ..Registry::default()
        }),
    );
}

#[test]
#[should_panic(expected = "the registry has moved to another epoch")]
fn register_records_only_the_current_epoch() {
    let (_, node_id) = node(1);

    let _written = crate::apply(
        Effect::Register {
            node: node_id,
            pool: BTreeSet::new(),
            epoch: 1,
        },
        &registry_data(Registry {
            epoch: 2,
            ..Registry::default()
        }),
    );
}

#[test]
#[should_panic(expected = "account already holds referral state")]
fn create_rejects_an_account_that_holds_referral_state() {
    let (_, node_id) = node(1);

    let _written = crate::apply(
        Effect::Create(State::Participant(Participant::new(node_id, None))),
        &State::Child {
            node: node_id,
            referrer: node_id,
            since: 0,
        }
        .to_data(),
    );
}

// === Claim ===

#[test]
fn a_claim_adopts_announced_children_and_forwards_what_it_earns() {
    let (_, me) = node(1);
    let (_, parent) = node(2);
    let (_, c) = node(3);
    let participant_account = account(20);
    let child_note = account(41);
    let credit_note = account(42);
    let outgoing = account(43);
    let active = BTreeSet::from([c, me, parent]);
    let digest = active_digest(&active);
    let child = State::Child {
        node: c,
        referrer: me,
        since: 0,
    };
    let credit = State::Credit {
        recipient_node: me,
        amount: 4,
        epoch: 2,
        active_digest: digest,
    };
    let check_epoch = Effect::CheckEpoch {
        epoch: 2,
        active_digest: digest,
    };
    let claim = Claim {
        epochs: vec![epoch_claim(
            2,
            &active,
            vec![child.clone(), credit.clone()],
            5,
        )],
        referrer: Some(parent),
    };

    let plan = plan_for(
        vec![
            meta(participant_account, true),
            publication(2),
            meta(child_note, false),
            meta(credit_note, false),
            meta(outgoing, false),
        ],
        Instruction::Claim(claim.clone()),
    );
    assert_eq!(
        plan.output().effects,
        vec![
            ShardEffect::new(&publication(2), &check_epoch),
            ShardEffect::new(&meta(child_note, false), &Effect::Consume(child.clone())),
            ShardEffect::new(&meta(credit_note, false), &Effect::Consume(credit.clone())),
            ShardEffect::new(
                &meta(outgoing, false),
                &Effect::Create(State::Credit {
                    recipient_node: parent,
                    amount: 5,
                    epoch: 2,
                    active_digest: digest,
                }),
            ),
            ShardEffect::new(
                &meta(participant_account, true),
                &Effect::Claim(claim.clone()),
            ),
        ]
    );

    assert_eq!(crate::apply(check_epoch, &published(2, &active)), None);
    assert_eq!(
        crate::apply(Effect::Consume(child.clone()), &child.to_data()),
        Some(ShardData::empty())
    );
    assert_eq!(
        crate::apply(Effect::Consume(credit.clone()), &credit.to_data()),
        Some(ShardData::empty())
    );

    let written = crate::apply(
        Effect::Claim(claim),
        &State::Participant(Participant::new(me, Some(referrer(parent)))).to_data(),
    )
    .expect("Claim writes the participant");
    assert_eq!(
        State::decode(&written),
        Some(State::Participant(Participant {
            children: BTreeMap::from([(c, vec![(2, 2)])]),
            reward_balance: 5,
            ..Participant::new(me, Some(referrer(parent)))
        }))
    );
}

#[test]
fn a_multi_epoch_claim_settles_its_epochs_in_order_and_forwards_per_epoch() {
    let (_, me) = node(1);
    let (_, parent) = node(2);
    let (_, c) = node(3);
    let participant_account = account(20);
    let child_note = account(41);
    let outgoing = account(43);
    // The referrer is active in epoch 2 only, so only epoch 2's total is forwarded.
    let second = BTreeSet::from([c, me, parent]);
    let third = BTreeSet::from([c, me]);
    let child = State::Child {
        node: c,
        referrer: me,
        since: 0,
    };
    let claim = Claim {
        epochs: vec![
            epoch_claim(2, &second, vec![child.clone()], 1),
            epoch_claim(3, &third, vec![], 1),
        ],
        referrer: Some(parent),
    };

    let plan = plan_for(
        vec![
            meta(participant_account, true),
            publication(2),
            meta(child_note, false),
            meta(outgoing, false),
            publication(3),
        ],
        Instruction::Claim(claim.clone()),
    );
    assert_eq!(
        plan.output().effects,
        vec![
            ShardEffect::new(
                &publication(2),
                &Effect::CheckEpoch {
                    epoch: 2,
                    active_digest: active_digest(&second),
                },
            ),
            ShardEffect::new(&meta(child_note, false), &Effect::Consume(child)),
            ShardEffect::new(
                &meta(outgoing, false),
                &Effect::Create(State::Credit {
                    recipient_node: parent,
                    amount: 1,
                    epoch: 2,
                    active_digest: active_digest(&second),
                }),
            ),
            ShardEffect::new(
                &publication(3),
                &Effect::CheckEpoch {
                    epoch: 3,
                    active_digest: active_digest(&third),
                },
            ),
            ShardEffect::new(
                &meta(participant_account, true),
                &Effect::Claim(claim.clone()),
            ),
        ]
    );

    let written = crate::apply(
        Effect::Claim(claim),
        &State::Participant(Participant::new(me, Some(referrer(parent)))).to_data(),
    )
    .expect("Claim writes the participant");
    assert_eq!(
        State::decode(&written),
        Some(State::Participant(Participant {
            children: BTreeMap::from([(c, vec![(2, 3)])]),
            reward_balance: 2,
            ..Participant::new(me, Some(referrer(parent)))
        }))
    );
}

#[test]
#[should_panic(expected = "participant authorization is missing")]
fn an_unauthorized_participant_cannot_claim() {
    let _plan = plan_for(
        vec![meta(account(20), false), publication(1)],
        Instruction::Claim(claim(1, &[], None)),
    );
}

#[test]
#[should_panic(expected = "account must be the epoch's publication account")]
fn claim_rejects_an_account_that_is_not_the_epochs_publication() {
    let _plan = plan_for(
        vec![meta(account(20), true), meta(ORACLE_ACCOUNT_ID, false)],
        Instruction::Claim(claim(1, &[], None)),
    );
}

#[test]
#[should_panic(expected = "a Claim names at least one epoch")]
fn a_claim_names_at_least_one_epoch() {
    let _plan = plan_for(
        vec![meta(account(20), true)],
        Instruction::Claim(Claim {
            epochs: vec![],
            referrer: None,
        }),
    );
}

#[test]
#[should_panic(expected = "a Claim's epochs must strictly increase")]
fn a_claims_epochs_must_strictly_increase() {
    let none = BTreeSet::new();
    let _plan = plan_for(
        vec![meta(account(20), true), publication(3), publication(2)],
        Instruction::Claim(Claim {
            epochs: vec![
                epoch_claim(3, &none, vec![], 1),
                epoch_claim(2, &none, vec![], 1),
            ],
            referrer: None,
        }),
    );
}

#[test]
#[should_panic(expected = "nothing to claim in epoch 1")]
fn each_epoch_of_a_claim_must_earn_something() {
    let _plan = plan_for(
        vec![meta(account(20), true), publication(1)],
        Instruction::Claim(claim(0, &[], None)),
    );
}

#[test]
#[should_panic(expected = "a Claim is missing the outgoing credit account")]
fn a_referred_claim_requires_an_outgoing_credit_account() {
    let (_, parent) = node(2);

    let _plan = plan_for(
        vec![meta(account(20), true), publication(1)],
        Instruction::Claim(claim(1, &[parent], Some(parent))),
    );
}

#[test]
fn a_claim_forwards_nothing_to_an_inactive_referrer() {
    let (_, me) = node(1);
    let (_, parent) = node(2);
    let (_, c) = node(3);
    let participant_account = account(20);
    let child_note = account(41);
    let active = BTreeSet::from([c, me]);
    let child = State::Child {
        node: c,
        referrer: me,
        since: 0,
    };
    let claim = Claim {
        epochs: vec![epoch_claim(2, &active, vec![child.clone()], 1)],
        referrer: Some(parent),
    };

    let plan = plan_for(
        vec![
            meta(participant_account, true),
            publication(2),
            meta(child_note, false),
        ],
        Instruction::Claim(claim.clone()),
    );
    assert_eq!(
        plan.output().effects,
        vec![
            ShardEffect::new(
                &publication(2),
                &Effect::CheckEpoch {
                    epoch: 2,
                    active_digest: active_digest(&active),
                },
            ),
            ShardEffect::new(&meta(child_note, false), &Effect::Consume(child)),
            ShardEffect::new(
                &meta(participant_account, true),
                &Effect::Claim(claim.clone()),
            ),
        ]
    );
    let written = crate::apply(
        Effect::Claim(claim),
        &State::Participant(Participant::new(me, Some(referrer(parent)))).to_data(),
    )
    .expect("Claim writes the participant");
    assert_eq!(
        State::decode(&written),
        Some(State::Participant(Participant {
            children: BTreeMap::from([(c, vec![(2, 2)])]),
            reward_balance: 1,
            ..Participant::new(me, Some(referrer(parent)))
        }))
    );
}

#[test]
#[should_panic(expected = "a Claim names more accounts than its epochs use")]
fn a_claim_cannot_forward_to_an_inactive_referrer() {
    let (_, me) = node(1);
    let (_, parent) = node(2);

    let _plan = plan_for(
        vec![
            meta(account(20), true),
            publication(1),
            meta(account(43), false),
        ],
        Instruction::Claim(claim(1, &[me], Some(parent))),
    );
}

#[test]
#[should_panic(expected = "a credit was earned in another publication")]
fn a_claim_rejects_a_credit_from_another_publication() {
    let (_, me) = node(1);
    let (_, c) = node(3);
    let fabricated = BTreeSet::from([c, me]);

    let _plan = plan_for(
        vec![
            meta(account(20), true),
            publication(2),
            meta(account(41), false),
        ],
        Instruction::Claim(Claim {
            epochs: vec![epoch_claim(
                2,
                &fabricated,
                vec![State::Credit {
                    recipient_node: me,
                    amount: 1,
                    epoch: 2,
                    active_digest: active_digest(&BTreeSet::from([c])),
                }],
                1,
            )],
            referrer: None,
        }),
    );
}

#[test]
#[should_panic(expected = "the claim total does not match")]
fn claim_rejects_a_total_that_does_not_match() {
    let (_, me) = node(1);

    let _written = crate::apply(
        Effect::Claim(claim(1, &[me], None)),
        &State::Participant(Participant::new(me, None)).to_data(),
    );
}

#[test]
#[should_panic(expected = "the claim names another referrer")]
fn claim_rejects_another_referrer() {
    let (_, me) = node(1);
    let (_, other) = node(2);

    let _written = crate::apply(
        Effect::Claim(claim(0, &[me], Some(other))),
        &State::Participant(Participant::new(me, None)).to_data(),
    );
}

#[test]
#[should_panic(expected = "note does not hold the claimed state")]
fn consume_rejects_a_note_that_differs_from_the_claim() {
    let (_, me) = node(1);

    let _written = crate::apply(
        Effect::Consume(State::Credit {
            recipient_node: me,
            amount: 1,
            epoch: 1,
            active_digest: [0; 32],
        }),
        &State::Credit {
            recipient_node: me,
            amount: 2,
            epoch: 1,
            active_digest: [0; 32],
        }
        .to_data(),
    );
}

/// A Claim consumes every note it names, so naming a publication would empty its account; the
/// participant's side of the claim refuses it, which reverts the whole transaction.
#[test]
#[should_panic(expected = "note does not hold a child or a credit")]
fn a_claim_cannot_consume_a_publication() {
    let (_, me) = node(1);
    let active = BTreeSet::from([me]);

    let _written = crate::apply(
        Effect::Claim(Claim {
            epochs: vec![epoch_claim(
                2,
                &active,
                vec![State::Publication {
                    epoch: 1,
                    active_digest: [0; 32],
                }],
                1,
            )],
            referrer: None,
        }),
        &State::Participant(Participant::new(me, None)).to_data(),
    );
}

#[test]
#[should_panic(expected = "the publication is of another epoch")]
fn check_epoch_rejects_another_epochs_publication() {
    let _written = crate::apply(
        Effect::CheckEpoch {
            epoch: 1,
            active_digest: active_digest(&BTreeSet::new()),
        },
        &published(2, &BTreeSet::new()),
    );
}

#[test]
#[should_panic(expected = "the claim names another active set")]
fn check_epoch_rejects_another_active_set() {
    let (_, a) = node(1);

    let _written = crate::apply(
        Effect::CheckEpoch {
            epoch: 2,
            active_digest: active_digest(&BTreeSet::from([a])),
        },
        &published(2, &BTreeSet::new()),
    );
}

#[test]
#[should_panic(expected = "account holds a decodable referral state")]
fn check_epoch_rejects_an_unpublished_epoch() {
    let _written = crate::apply(
        Effect::CheckEpoch {
            epoch: 2,
            active_digest: active_digest(&BTreeSet::new()),
        },
        &ShardData::empty(),
    );
}

// === CashOut ===

fn cash_out(node: NodeId, points: u128) -> Instruction {
    Instruction::CashOut {
        node,
        points,
        blinding_factor: [5; 32],
    }
}

fn holding(node: NodeId, reward_balance: u128) -> ShardData {
    State::Participant(Participant {
        reward_balance,
        ..Participant::new(node, None)
    })
    .to_data()
}

#[test]
fn a_cash_out_burns_the_full_balance_into_its_receipt() {
    let (_, me) = node(1);
    let (_, parent) = node(2);
    let (_, c) = node(3);
    let participant_account = account(20);
    let receipt = cash_out_receipt(PROGRAM, me, [5; 32]);

    let plan = plan_for(
        vec![meta(participant_account, true), meta(receipt, false)],
        cash_out(me, 7),
    );

    assert_eq!(
        plan.output().effects,
        vec![
            ShardEffect::new(
                &meta(participant_account, true),
                &Effect::CashOutBurn {
                    node: me,
                    points: 7
                },
            ),
            ShardEffect::new(
                &meta(receipt, false),
                &Effect::Create(State::CashOut { points: 7 }),
            ),
        ]
    );

    let earned = Participant {
        children: BTreeMap::from([(c, vec![(2, 2)])]),
        reward_balance: 7,
        ..Participant::new(me, Some(referrer(parent)))
    };
    let burned = crate::apply(
        Effect::CashOutBurn {
            node: me,
            points: 7,
        },
        &State::Participant(earned.clone()).to_data(),
    )
    .expect("the burn writes the participant");
    assert_eq!(
        State::decode(&burned),
        Some(State::Participant(Participant {
            reward_balance: 0,
            ..earned
        }))
    );
    assert_eq!(
        crate::apply(
            Effect::Create(State::CashOut { points: 7 }),
            &ShardData::empty()
        ),
        Some(State::CashOut { points: 7 }.to_data())
    );
}

#[test]
#[should_panic(expected = "the receipt account does not match the node and blinding factor")]
fn a_cash_out_rejects_a_receipt_for_another_factor() {
    let (_, me) = node(1);

    let _plan = plan_for(
        vec![
            meta(account(20), true),
            meta(cash_out_receipt(PROGRAM, me, [6; 32]), false),
        ],
        cash_out(me, 7),
    );
}

#[test]
#[should_panic(expected = "participant authorization is missing")]
fn an_unauthorized_participant_cannot_cash_out() {
    let (_, me) = node(1);

    let _plan = plan_for(
        vec![
            meta(account(20), false),
            meta(cash_out_receipt(PROGRAM, me, [5; 32]), false),
        ],
        cash_out(me, 7),
    );
}

#[test]
#[should_panic(expected = "nothing to cash out")]
fn a_cash_out_requires_points() {
    let (_, me) = node(1);

    let _plan = plan_for(
        vec![
            meta(account(20), true),
            meta(cash_out_receipt(PROGRAM, me, [5; 32]), false),
        ],
        cash_out(me, 0),
    );
}

#[test]
#[should_panic(expected = "the cash out names another node")]
fn the_burn_rejects_another_node() {
    let (_, me) = node(1);
    let (_, other) = node(2);

    let _written = crate::apply(
        Effect::CashOutBurn {
            node: other,
            points: 7,
        },
        &holding(me, 7),
    );
}

#[test]
#[should_panic(expected = "a cash out takes the full reward balance")]
fn the_burn_takes_the_full_balance() {
    let (_, me) = node(1);

    let _written = crate::apply(
        Effect::CashOutBurn {
            node: me,
            points: 6,
        },
        &holding(me, 7),
    );
}

#[test]
#[should_panic(expected = "account already holds referral state")]
fn a_receipt_is_never_written_twice() {
    let _written = crate::apply(
        Effect::Create(State::CashOut { points: 7 }),
        &State::CashOut { points: 7 }.to_data(),
    );
}
