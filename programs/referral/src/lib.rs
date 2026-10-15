use lee_core::{
    account::ShardData,
    program::{AccountMeta, Plan, PlanInput},
};
pub use referral_core as core;
use referral_core::{
    Claim, Effect, Instruction, ORACLE_ACCOUNT_ID, Participant, ParticipantAuthorizationV1, Points,
    Registry, State, active_digest, cash_out_receipt, epoch_account,
};

pub fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    assert!(
        input.caller_account_id.is_none(),
        "referral instructions are only invoked as top-level user transactions"
    );

    let mut plan = Plan::new(input);
    match instruction {
        Instruction::Publish { epoch, active } => {
            let [registry, publication] = input.accounts.as_slice() else {
                panic!("Publish requires the registry and the epoch's publication account")
            };
            assert!(registry.is_authorized, "oracle authorization is missing");
            assert_registry(registry);
            assert_publication(input, publication, epoch);
            let digest = active_digest(&active);
            plan.effect(registry, &Effect::Publish { epoch, active });
            plan.effect(
                publication,
                &Effect::Create(State::Publication {
                    epoch,
                    active_digest: digest,
                }),
            );
        }
        Instruction::Register {
            node,
            referrer,
            node_signature,
            pool,
            epoch,
        } => {
            let (participant, registry, child) = match input.accounts.as_slice() {
                [participant, registry] => (participant, registry, None),
                [participant, registry, child] => (participant, registry, Some(child)),
                _ => panic!(
                    "Register requires the participant, the registry and at most one child note account"
                ),
            };
            assert_eq!(
                referrer.is_some(),
                child.is_some(),
                "a Register announces the participant to its referrer exactly when it has one"
            );
            assert_authorized(participant);
            assert_registry(registry);
            let parent = referrer.as_ref().map(|referrer| referrer.node);
            if let Some(parent) = parent {
                assert!(pool.contains(&parent), "the pool must contain the referrer");
            }
            assert!(
                ParticipantAuthorizationV1::new(
                    input.self_account_id,
                    node,
                    participant.account_id,
                    parent,
                )
                .verify(&node_signature),
                "node authorization signature is invalid"
            );

            // The registry confirms the epoch is current, so the child note records the epoch the
            // participant registered in.
            plan.effect(
                participant,
                &Effect::Create(State::Participant(Participant::new(node, referrer))),
            );
            plan.effect(registry, &Effect::Register { node, pool, epoch });
            if let Some((parent, child)) = parent.zip(child) {
                plan.effect(
                    child,
                    &Effect::Create(State::Child {
                        node,
                        referrer: parent,
                        since: epoch,
                    }),
                );
            }
        }
        Instruction::Claim(claim) => {
            let [participant, rest @ ..] = input.accounts.as_slice() else {
                panic!("Claim requires the participant")
            };
            assert_authorized(participant);
            plan_claim(&mut plan, input, participant, rest, claim);
        }
        Instruction::CashOut {
            node,
            points,
            blinding_factor,
        } => {
            let [participant, receipt] = input.accounts.as_slice() else {
                panic!("CashOut requires the participant and its receipt account")
            };
            assert_authorized(participant);
            assert!(points > 0, "nothing to cash out");
            assert_eq!(
                receipt.account_id,
                cash_out_receipt(input.self_account_id, node, blinding_factor),
                "the receipt account does not match the node and blinding factor"
            );

            plan.effect(participant, &Effect::CashOutBurn { node, points });
            plan.effect(receipt, &Effect::Create(State::CashOut { points }));
        }
    }
    plan
}

/// Plans a claim's epochs in order. After the participant, the accounts are, for each epoch: its
/// publication account, one account per note, then the outgoing credit account exactly when the
/// referrer was active in that epoch.
fn plan_claim(
    plan: &mut Plan,
    input: &PlanInput,
    participant: &AccountMeta,
    rest: &[AccountMeta],
    claim: Claim,
) {
    assert!(!claim.epochs.is_empty(), "a Claim names at least one epoch");
    assert!(
        claim
            .epochs
            .windows(2)
            .all(|pair| matches!(pair, [earlier, later] if earlier.epoch < later.epoch)),
        "a Claim's epochs must strictly increase"
    );

    let mut accounts = rest.iter();
    let mut next = |what: &str| {
        accounts
            .next()
            .unwrap_or_else(|| panic!("a Claim is missing {what}"))
    };
    for epoch_claim in &claim.epochs {
        assert!(
            epoch_claim.total > 0,
            "nothing to claim in epoch {}",
            epoch_claim.epoch
        );
        let digest = active_digest(&epoch_claim.active);

        let publication = next("an epoch's publication account");
        assert_publication(input, publication, epoch_claim.epoch);
        plan.effect(
            publication,
            &Effect::CheckEpoch {
                epoch: epoch_claim.epoch,
                active_digest: digest,
            },
        );

        for note in &epoch_claim.notes {
            if let State::Credit {
                epoch,
                active_digest: earned_under,
                ..
            } = *note
            {
                assert_eq!(
                    (epoch, earned_under),
                    (epoch_claim.epoch, digest),
                    "a credit was earned in another publication"
                );
            }
            plan.effect(next("a note account"), &Effect::Consume(note.clone()));
        }

        if let Some(parent) = epoch_claim.forward_to(claim.referrer) {
            plan.effect(
                next("the outgoing credit account of an epoch its referrer was active in"),
                &Effect::Create(State::Credit {
                    recipient_node: parent,
                    amount: epoch_claim.total,
                    epoch: epoch_claim.epoch,
                    active_digest: digest,
                }),
            );
        }
    }
    assert!(
        accounts.next().is_none(),
        "a Claim names more accounts than its epochs use"
    );
    plan.effect(participant, &Effect::Claim(claim));
}

#[must_use]
pub fn apply(effect: Effect, pre_data: &ShardData) -> Option<ShardData> {
    match effect {
        Effect::Publish { epoch, active } => {
            let mut registry = decode_registry(pre_data);
            assert!(
                epoch > registry.epoch,
                "a publication must advance the epoch"
            );
            registry.epoch = epoch;
            registry.active_nodes = active;
            Some(State::Registry(registry).to_data())
        }
        Effect::Register { node, pool, epoch } => {
            let mut registry = decode_registry(pre_data);
            assert_eq!(
                registry.epoch, epoch,
                "the registry has moved to another epoch"
            );
            assert!(
                pool.is_subset(&registry.registered_nodes),
                "the pool names an unregistered node"
            );
            assert!(
                registry.registered_nodes.insert(node),
                "node is already registered"
            );
            Some(State::Registry(registry).to_data())
        }
        Effect::CheckEpoch {
            epoch,
            active_digest: digest,
        } => {
            let State::Publication {
                epoch: published,
                active_digest: published_digest,
            } = decode(pre_data)
            else {
                panic!("the epoch account does not hold a publication")
            };
            assert_eq!(published, epoch, "the publication is of another epoch");
            assert_eq!(
                published_digest, digest,
                "the claim names another active set"
            );
            None
        }
        Effect::Create(state) => {
            assert!(pre_data.is_empty(), "account already holds referral state");
            Some(state.to_data())
        }
        Effect::Claim(claim) => {
            let mut participant = decode_participant(pre_data);
            assert_eq!(
                participant.referrer_node(),
                claim.referrer,
                "the claim names another referrer"
            );
            for epoch_claim in &claim.epochs {
                let earned: Points = participant.claim(epoch_claim);
                assert_eq!(earned, epoch_claim.total, "the claim total does not match");
            }
            Some(State::Participant(participant).to_data())
        }
        Effect::Consume(note) => {
            assert_eq!(
                decode(pre_data),
                note,
                "note does not hold the claimed state"
            );
            Some(ShardData::empty())
        }
        Effect::CashOutBurn { node, points } => {
            let mut participant = decode_participant(pre_data);
            assert_eq!(participant.node, node, "the cash out names another node");
            assert_eq!(
                participant.reward_balance, points,
                "a cash out takes the full reward balance"
            );
            participant.reward_balance = 0;
            Some(State::Participant(participant).to_data())
        }
    }
}

fn decode(pre_data: &ShardData) -> State {
    State::decode(pre_data).expect("account holds a decodable referral state")
}

fn decode_participant(pre_data: &ShardData) -> Participant {
    let State::Participant(participant) = decode(pre_data) else {
        panic!("participant state must be a participant")
    };
    participant
}

fn decode_registry(pre_data: &ShardData) -> Registry {
    if pre_data.is_empty() {
        return Registry::default();
    }
    let State::Registry(registry) = decode(pre_data) else {
        panic!("registry account does not hold the registry")
    };
    registry
}

fn assert_authorized(participant: &AccountMeta) {
    assert!(
        participant.is_authorized,
        "participant authorization is missing"
    );
}

fn assert_registry(registry: &AccountMeta) {
    assert_eq!(
        registry.account_id, ORACLE_ACCOUNT_ID,
        "account must be the registry"
    );
}

fn assert_publication(input: &PlanInput, publication: &AccountMeta, epoch: referral_core::Epoch) {
    assert_eq!(
        publication.account_id,
        epoch_account(input.self_account_id, epoch),
        "account must be the epoch's publication account"
    );
}

mod tests;
