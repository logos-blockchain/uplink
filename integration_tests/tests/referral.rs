#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{collections::BTreeSet, time::Duration};

use anyhow::Result;
use common::transaction::LeeTransaction;
use integration_tests::{
    TestContext, public_mention,
    utils::{new_account, send, sync_private, wait_for_indexer_to_catch_up},
};
use key_protocol::key_management::secret_holders::SeedHolder;
use lee::{AccountId, PrivateKey, ProgramShardSelector};
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use referral_core::{
    Invitation, NodeId, ORACLE_ACCOUNT_ID, State, active_digest, cash_out_receipt,
    ed25519_dalek::{Signer as _, SigningKey},
    epoch_account,
};
use referral_methods::referral;
use testnet_initial_state::{PublicAccountPrivateInitialData, initial_pub_accounts_private_keys};
use tokio::test;
use uplink_wallet::{
    Referral, receipt_secret,
    store::{ClaimedEpoch, OperationKind, SubmissionStatus},
};
use wallet::{cli::execute_keys_restoration, program_facades::program_loader::ProgramLoader};

/// The key behind `ORACLE_ACCOUNT_ID` in this prototype, with which the tests publish epochs.
const PROTOTYPE_ORACLE_SIGNING_KEY: [u8; 32] = [11; 32];

const ORACLE_FUNDING: u128 = 100_000_000_000;

const SETTLE_ATTEMPTS: usize = 30;

const RESTORE_DEPTH: u32 = 5;

fn genesis_payer(ctx: &mut TestContext) -> PublicAccountPrivateInitialData {
    let payer = initial_pub_accounts_private_keys().swap_remove(0);
    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(payer.pub_sign_key.clone());
    payer
}

async fn deploy_referral(ctx: &mut TestContext, payer: AccountId) -> Result<AccountId> {
    let program = referral();
    let byte_len = program.user_elf().expect("a test program decodes").len();
    let mut segments = Vec::new();
    for _ in 0..byte_len.div_ceil(MAX_SEGMENT_DATA_LEN) {
        segments.push(new_account(ctx, false, None).await?);
    }
    let header = new_account(ctx, false, None).await?;

    ProgramLoader(ctx.wallet())
        .deploy(header, &segments, program.elf().to_vec(), true, Some(payer))
        .await
}

async fn fund_oracle(ctx: &mut TestContext, payer: AccountId) -> Result<()> {
    send(
        ctx,
        public_mention(payer),
        public_mention(ORACLE_ACCOUNT_ID),
        ORACLE_FUNDING,
    )
    .await?;
    import_oracle(ctx)
}

fn import_oracle(ctx: &mut TestContext) -> Result<()> {
    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(PrivateKey::try_new(PROTOTYPE_ORACLE_SIGNING_KEY)?);
    Ok(())
}

fn facade(ctx: &mut TestContext, program: AccountId) -> Referral<'_> {
    let indexer_addr = format!("http://{}", ctx.indexer_addr())
        .parse()
        .expect("the indexer address is a URL");
    Referral::new(ctx.wallet_mut(), referral(), program)
        .expect("the referral store opens")
        .with_indexer(indexer_addr)
}

/// Forgets the referral store, as losing the device it was kept on would.
fn forget_referral_store(ctx: &TestContext) -> Result<()> {
    match std::fs::remove_file(Referral::store_path(ctx.wallet())) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

async fn settle(ctx: &mut TestContext, program: AccountId, reference: [u8; 32]) -> Result<()> {
    for _ in 0..SETTLE_ATTEMPTS {
        match facade(ctx, program).reconcile(reference).await? {
            SubmissionStatus::Settled => return Ok(()),
            SubmissionStatus::Rejected => {
                anyhow::bail!("the operation was rejected instead of settling")
            }
            SubmissionStatus::Pending => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
    anyhow::bail!("the operation never settled on its effects")
}

fn node(seed: u8) -> (SigningKey, NodeId) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id = NodeId::new(key.verifying_key().to_bytes());
    (key, id)
}

/// `participant`'s invitation for nodes joining under it, signed by its node's key.
fn invite(
    ctx: &mut TestContext,
    program: AccountId,
    participant: AccountId,
    node_key: &SigningKey,
) -> Result<Invitation> {
    let node = NodeId::new(node_key.verifying_key().to_bytes());
    let authorization = facade(ctx, program).invitation_authorization(participant, node)?;
    let signature = node_key.sign(&authorization.message()).to_bytes();
    Ok(facade(ctx, program).invitation(participant, node, signature)?)
}

async fn register(
    ctx: &mut TestContext,
    program: AccountId,
    participant: AccountId,
    node_key: &SigningKey,
    referrer: Option<NodeId>,
    invitation: Option<Invitation>,
) -> Result<()> {
    if let Some(from_referrer) = invitation {
        facade(ctx, program).import_invitation(participant, from_referrer)?;
    }

    let node = NodeId::new(node_key.verifying_key().to_bytes());
    let authorization = facade(ctx, program).prepare_registration(participant, node, referrer)?;
    let signature = node_key.sign(&authorization.message()).to_bytes();
    facade(ctx, program).attach_node_signature(participant, signature)?;

    let reference = node.to_bytes();
    let (hash, _broadcast) = facade(ctx, program)
        .submit(reference, OperationKind::Register { participant })
        .await?;
    ctx.wallet().poll_transaction(hash).await?;
    settle(ctx, program, reference).await?;

    sync_private(ctx).await
}

async fn claim(
    ctx: &mut TestContext,
    program: AccountId,
    participant: AccountId,
    reference: [u8; 32],
) -> Result<u128> {
    let operations = facade(ctx, program).claim_operations(participant).await?;
    anyhow::ensure!(
        !operations.is_empty(),
        "the participant has nothing to claim"
    );
    for (batch, operation) in operations.into_iter().enumerate() {
        let mut reference = reference;
        reference[31] = u8::try_from(batch)?;
        let (hash, _broadcast) = facade(ctx, program).submit(reference, operation).await?;
        ctx.wallet().poll_transaction(hash).await?;
        settle(ctx, program, reference).await?;
        sync_private(ctx).await?;
    }
    reward_balance(ctx, program, participant)
}

async fn current_claim(
    ctx: &mut TestContext,
    program: AccountId,
    participant: AccountId,
) -> Result<OperationKind> {
    let registry = facade(ctx, program).registry().await?;
    Ok(OperationKind::Claim {
        participant,
        epochs: vec![ClaimedEpoch {
            epoch: registry.epoch,
            active_digest: active_digest(&registry.active_nodes),
            notes: note_ids(ctx, program, participant)?,
        }],
    })
}

async fn cash_out(
    ctx: &mut TestContext,
    program: AccountId,
    participant: AccountId,
    receipt_secret: &[u8; 32],
    reference: [u8; 32],
) -> Result<AccountId> {
    let (hash, _broadcast) = facade(ctx, program)
        .cash_out(reference, participant, receipt_secret)
        .await?;
    let (included, _block) = ctx.wallet().poll_transaction(hash).await?;
    settle(ctx, program, reference).await?;
    sync_private(ctx).await?;

    let LeeTransaction::PrivacyPreserving(transaction) = included else {
        anyhow::bail!("a cash out is a privacy-preserving transaction");
    };
    let [receipt] = transaction.message().public_actions.as_slice() else {
        anyhow::bail!("a cash out mentions exactly one public account");
    };
    Ok(receipt.account_id)
}

async fn publish(
    ctx: &mut TestContext,
    program: AccountId,
    epoch: u32,
    active: &[NodeId],
) -> Result<()> {
    let hash = facade(ctx, program)
        .publish(epoch, active.iter().copied().collect())
        .await?;
    ctx.wallet().poll_transaction(hash).await?;
    Ok(())
}

fn note_ids(
    ctx: &mut TestContext,
    program: AccountId,
    participant: AccountId,
) -> Result<Vec<AccountId>> {
    Ok(facade(ctx, program)
        .notes(participant)?
        .into_iter()
        .map(|(id, _state)| id)
        .collect())
}

/// Submits `operation` under `reference` and waits until it settles and the wallet has synced.
async fn submit_and_settle(
    ctx: &mut TestContext,
    program: AccountId,
    reference: [u8; 32],
    operation: OperationKind,
) -> Result<()> {
    let (hash, _broadcast) = facade(ctx, program).submit(reference, operation).await?;
    ctx.wallet().poll_transaction(hash).await?;
    settle(ctx, program, reference).await?;
    sync_private(ctx).await
}

/// Waits until `count` more blocks have been produced.
async fn wait_blocks(ctx: &TestContext, count: u64) -> Result<()> {
    let target = ctx
        .wallet()
        .get_last_block_id()
        .await?
        .saturating_add(count);
    while ctx.wallet().get_last_block_id().await? < target {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}

/// The digest archived for `epoch`, if it was published.
async fn archived_digest(
    ctx: &TestContext,
    program: AccountId,
    epoch: u32,
) -> Result<Option<[u8; 32]>> {
    let account = ctx
        .wallet()
        .get_account_view(ProgramShardSelector::new(
            epoch_account(program, epoch),
            program,
        ))
        .await?;
    Ok(match State::decode(account.data.shard(program)) {
        Some(State::Publication { active_digest, .. }) => Some(active_digest),
        _ => None,
    })
}

fn reward_balance(
    ctx: &mut TestContext,
    program: AccountId,
    participant: AccountId,
) -> Result<u128> {
    let State::Participant(record) = facade(ctx, program).state(participant)? else {
        anyhow::bail!("a registered participant's own state is a participant record");
    };
    Ok(record.reward_balance)
}

#[test]
async fn the_worked_example_pays_one_per_active_child_through_real_wallets() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer = genesis_payer(&mut ctx);
    let program = deploy_referral(&mut ctx, payer.account_id).await?;
    fund_oracle(&mut ctx, payer.account_id).await?;

    let (carol_key, carol_node) = node(3);
    let (alice_key, alice_node) = node(2);
    let (bob_key, bob_node) = node(1);
    let (dave_key, dave_node) = node(4);

    let carol = facade(&mut ctx, program).create_participant()?;
    let alice = facade(&mut ctx, program).create_participant()?;
    let bob = facade(&mut ctx, program).create_participant()?;
    let dave = facade(&mut ctx, program).create_participant()?;

    register(&mut ctx, program, carol, &carol_key, None, None).await?;
    let carol_invites_alice = invite(&mut ctx, program, carol, &carol_key)?;
    register(
        &mut ctx,
        program,
        alice,
        &alice_key,
        Some(carol_node),
        Some(carol_invites_alice),
    )
    .await?;
    let alice_invites_bob = invite(&mut ctx, program, alice, &alice_key)?;
    register(
        &mut ctx,
        program,
        bob,
        &bob_key,
        Some(alice_node),
        Some(alice_invites_bob),
    )
    .await?;

    for (participant, who) in [(carol, "Carol"), (alice, "Alice"), (bob, "Bob")] {
        assert_eq!(
            facade(&mut ctx, program).claimable(participant).await?,
            0,
            "{who} has nothing to claim before any epoch is published"
        );
    }
    let bob_claim = current_claim(&mut ctx, program, bob).await?;
    let bob_refused = facade(&mut ctx, program).submit([1; 32], bob_claim).await;
    assert!(
        bob_refused.is_err(),
        "an announced child pays nothing until its node is published as active: {bob_refused:?}"
    );

    publish(&mut ctx, program, 1, &[alice_node, bob_node]).await?;

    assert_eq!(
        facade(&mut ctx, program).claimable(alice).await?,
        1,
        "Alice's only child is active in the published epoch"
    );
    assert_eq!(
        claim(&mut ctx, program, alice, [2; 32]).await?,
        1,
        "one active child pays one"
    );
    assert!(
        facade(&mut ctx, program).notes(alice)?.is_empty(),
        "and the announcement it adopted was consumed"
    );

    let carol_holds: Vec<State> = facade(&mut ctx, program)
        .notes(carol)?
        .into_iter()
        .map(|(_id, state)| state)
        .collect();
    assert_eq!(
        carol_holds,
        vec![State::Child {
            node: alice_node,
            referrer: carol_node,
            since: 0,
        }],
        "Carol holds Alice's announcement and no credit for an epoch she was inactive in"
    );
    assert_eq!(
        facade(&mut ctx, program).claimable(carol).await?,
        0,
        "an inactive claimant earns nothing for her active child"
    );
    let carol_claim = current_claim(&mut ctx, program, carol).await?;
    let carol_refused = facade(&mut ctx, program).submit([3; 32], carol_claim).await;
    assert!(
        carol_refused.is_err(),
        "a claimant absent from the published epoch is refused: {carol_refused:?}"
    );

    assert_eq!(
        facade(&mut ctx, program).claimable(bob).await?,
        0,
        "Bob's own activity is never his own reward"
    );
    let bob_later_claim = current_claim(&mut ctx, program, bob).await?;
    let bob_refused_again = facade(&mut ctx, program)
        .submit([4; 32], bob_later_claim)
        .await;
    assert!(
        bob_refused_again.is_err(),
        "a participant with no active children has nothing to claim: {bob_refused_again:?}"
    );

    publish(
        &mut ctx,
        program,
        2,
        &[alice_node, bob_node, carol_node, dave_node],
    )
    .await?;

    assert_eq!(
        facade(&mut ctx, program).claimable(alice).await?,
        1,
        "Bob is active again in the second epoch"
    );
    assert_eq!(
        claim(&mut ctx, program, alice, [5; 32]).await?,
        2,
        "an epoch pays her child once"
    );
    assert_eq!(
        facade(&mut ctx, program).claimable(carol).await?,
        2,
        "her active child and the credit it forwarded, and nothing for the epoch she missed"
    );
    assert_eq!(
        claim(&mut ctx, program, carol, [6; 32]).await?,
        2,
        "the chain paid her for her child and for her child's child"
    );

    let carol_invites_dave = invite(&mut ctx, program, carol, &carol_key)?;
    register(
        &mut ctx,
        program,
        dave,
        &dave_key,
        Some(carol_node),
        Some(carol_invites_dave),
    )
    .await?;
    assert_eq!(
        facade(&mut ctx, program).claimable(carol).await?,
        1,
        "a child announced after this epoch's claim is still paid for it"
    );
    assert_eq!(
        claim(&mut ctx, program, carol, [7; 32]).await?,
        3,
        "the same epoch pays for the child announced after her claim"
    );

    assert_eq!(
        facade(&mut ctx, program).claimable(alice).await?,
        0,
        "the epoch that paid Alice's child pays it only once"
    );
    let alice_claim = current_claim(&mut ctx, program, alice).await?;
    let alice_refused = facade(&mut ctx, program).submit([8; 32], alice_claim).await;
    assert!(
        alice_refused.is_err(),
        "a second claim in the same epoch is refused: {alice_refused:?}"
    );

    publish(&mut ctx, program, 3, &[alice_node, bob_node, carol_node]).await?;
    assert_eq!(
        claim(&mut ctx, program, alice, [9; 32]).await?,
        3,
        "Bob is active in the third epoch"
    );
    let carol_late = current_claim(&mut ctx, program, carol).await?;

    // Publications never change, so a claim for epoch 3 stays valid after epoch 4 is published;
    // building it now reads epoch 3's active set back from the indexer.
    publish(&mut ctx, program, 4, &[bob_node]).await?;
    // A wallet that did not publish epoch 3 itself reads its active set back from the indexer.
    forget_referral_store(&ctx)?;
    wait_for_indexer_to_catch_up(&ctx).await?;
    let (hash, _broadcast) = facade(&mut ctx, program)
        .submit([10; 32], carol_late)
        .await?;
    ctx.wallet().poll_transaction(hash).await?;
    settle(&mut ctx, program, [10; 32]).await?;
    sync_private(&mut ctx).await?;
    assert_eq!(
        reward_balance(&mut ctx, program, carol)?,
        5,
        "a claim for a past epoch pays its active child and the credit forwarded in it"
    );
    assert_eq!(
        facade(&mut ctx, program).claimable(carol).await?,
        0,
        "Carol is inactive in the fourth epoch, and the third is settled"
    );

    Ok(())
}

#[test]
async fn registration_bookkeeping_resumes_and_refuses_conflicts() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer = genesis_payer(&mut ctx);
    let program = deploy_referral(&mut ctx, payer.account_id).await?;

    let (bob_key, bob_node) = node(1);
    let (alice_key, alice_node) = node(2);
    let bob = facade(&mut ctx, program).create_participant()?;
    let stranger = facade(&mut ctx, program).create_participant()?;

    let authorization = facade(&mut ctx, program).prepare_registration(bob, bob_node, None)?;
    let signature = bob_key.sign(&authorization.message()).to_bytes();
    facade(&mut ctx, program).attach_node_signature(bob, signature)?;

    let resumed = facade(&mut ctx, program).prepare_registration(bob, bob_node, None)?;
    assert_eq!(
        resumed.message(),
        authorization.message(),
        "the same configuration resumes the registration already recorded"
    );

    let other_node = facade(&mut ctx, program).prepare_registration(bob, alice_node, None);
    assert!(
        other_node.is_err(),
        "a second node for an unresolved registration is a conflict: {other_node:?}"
    );
    let kept = facade(&mut ctx, program)
        .pending_registration(bob)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the refused node must leave the recorded registration"))?;
    assert_eq!(
        kept.node, bob_node,
        "the recorded node is the authorized one"
    );
    assert_eq!(
        kept.signed(),
        Some(signature),
        "and its node signature survives the refusal"
    );

    let other_deployment =
        facade(&mut ctx, AccountId::new([0xAB; 32])).prepare_registration(bob, bob_node, None);
    assert!(
        other_deployment.is_err(),
        "another deployment with the same node is a conflict: {other_deployment:?}"
    );

    let stranger_invitation = invite(&mut ctx, program, stranger, &alice_key)?;
    let foreign = facade(&mut ctx, program).import_invitation(bob, stranger_invitation);
    assert!(
        foreign.is_err(),
        "an invitation naming another referrer than the participant's is refused: {foreign:?}"
    );
    let unbacked = facade(&mut ctx, program).prepare_registration(bob, bob_node, Some(alice_node));
    assert!(
        unbacked.is_err(),
        "a registration for a referrer without its invitation is refused: {unbacked:?}"
    );

    register(&mut ctx, program, bob, &bob_key, None, None).await?;
    let repeat = facade(&mut ctx, program).prepare_registration(bob, bob_node, None);
    assert!(
        repeat.is_err(),
        "a registered participant refuses a second registration: {repeat:?}"
    );

    let twin = facade(&mut ctx, program).create_participant()?;
    let twin_authorization =
        facade(&mut ctx, program).prepare_registration(twin, bob_node, None)?;
    let twin_signature = bob_key.sign(&twin_authorization.message()).to_bytes();
    facade(&mut ctx, program).attach_node_signature(twin, twin_signature)?;
    let taken = facade(&mut ctx, program)
        .submit([0x77; 32], OperationKind::Register { participant: twin })
        .await;
    assert!(
        taken.is_err(),
        "a fresh participant for a node the registry already holds is refused when its registration is built: {taken:?}"
    );
    assert_eq!(
        facade(&mut ctx, program).operation_status([0x77; 32]),
        None,
        "the refused registration is never recorded"
    );

    Ok(())
}

#[test]
async fn a_slack_referrer_catches_up_in_one_claim_from_each_childs_registration() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer = genesis_payer(&mut ctx);
    let program = deploy_referral(&mut ctx, payer.account_id).await?;
    fund_oracle(&mut ctx, payer.account_id).await?;

    let (carol_key, carol_node) = node(3);
    let (alice_key, alice_node) = node(2);
    let (dave_key, dave_node) = node(4);
    let carol = facade(&mut ctx, program).create_participant()?;
    let alice = facade(&mut ctx, program).create_participant()?;
    let dave = facade(&mut ctx, program).create_participant()?;
    register(&mut ctx, program, carol, &carol_key, None, None).await?;
    let carol_invites_alice = invite(&mut ctx, program, carol, &carol_key)?;
    register(
        &mut ctx,
        program,
        alice,
        &alice_key,
        Some(carol_node),
        Some(carol_invites_alice),
    )
    .await?;

    // Dave runs a node from the first epoch, but registers under Carol only in the third.
    for epoch in 1..=3 {
        publish(
            &mut ctx,
            program,
            epoch,
            &[alice_node, carol_node, dave_node],
        )
        .await?;
    }
    let carol_invites_dave = invite(&mut ctx, program, carol, &carol_key)?;
    register(
        &mut ctx,
        program,
        dave,
        &dave_key,
        Some(carol_node),
        Some(carol_invites_dave),
    )
    .await?;

    assert_eq!(
        facade(&mut ctx, program)
            .claim_operations(carol)
            .await?
            .len(),
        1,
        "one claim settles the three epochs Carol did not claim"
    );
    assert_eq!(
        claim(&mut ctx, program, carol, [1; 32]).await?,
        4,
        "three epochs of Alice, and of Dave only the epoch he registered in"
    );
    assert_eq!(
        facade(&mut ctx, program).claimable(carol).await?,
        0,
        "every epoch pays each child once"
    );

    Ok(())
}

#[test]
async fn cash_out_receipts_survive_a_mnemonic_only_restore() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let (_, mnemonic) = SeedHolder::new_mnemonic("");
    let password = ctx.wallet_password().to_owned();
    ctx.wallet_mut().restore_storage(&mnemonic, &password)?;
    let payer = genesis_payer(&mut ctx);
    let program = deploy_referral(&mut ctx, payer.account_id).await?;
    fund_oracle(&mut ctx, payer.account_id).await?;

    let (carol_key, carol_node) = node(3);
    let (alice_key, alice_node) = node(2);
    let (bob_key, bob_node) = node(1);
    let carol = facade(&mut ctx, program).create_participant()?;
    let alice = facade(&mut ctx, program).create_participant()?;
    let bob = facade(&mut ctx, program).create_participant()?;
    register(&mut ctx, program, carol, &carol_key, None, None).await?;
    let carol_invites_alice = invite(&mut ctx, program, carol, &carol_key)?;
    register(
        &mut ctx,
        program,
        alice,
        &alice_key,
        Some(carol_node),
        Some(carol_invites_alice),
    )
    .await?;
    let alice_invites_bob = invite(&mut ctx, program, alice, &alice_key)?;
    register(
        &mut ctx,
        program,
        bob,
        &bob_key,
        Some(alice_node),
        Some(alice_invites_bob),
    )
    .await?;

    // Carol's operator derives the receipt secret from her node key and hands it to her wallet.
    let carol_secret = receipt_secret(&carol_key.to_bytes());
    let mut sent = Vec::new();
    for (epoch, claimed, cashed_out) in [(1, [1; 32], [2; 32]), (2, [3; 32], [4; 32])] {
        publish(&mut ctx, program, epoch, &[alice_node, carol_node]).await?;
        assert_eq!(
            claim(&mut ctx, program, carol, claimed).await?,
            1,
            "Carol's active child pays one per epoch"
        );
        sent.push(cash_out(&mut ctx, program, carol, &carol_secret, cashed_out).await?);
        assert_eq!(
            reward_balance(&mut ctx, program, carol)?,
            0,
            "a cash out burns the whole balance"
        );
    }

    let receipts = facade(&mut ctx, program)
        .receipts(carol, &carol_secret)
        .await?;
    assert_eq!(
        receipts
            .iter()
            .map(|receipt| (receipt.index, receipt.account_id, receipt.points))
            .collect::<Vec<_>>(),
        vec![(0, sent[0], 1), (1, sent[1], 1)],
        "each cash out took the next index for the receipt it sent"
    );

    ctx.wallet_mut().restore_storage(&mnemonic, &password)?;
    forget_referral_store(&ctx)?;
    execute_keys_restoration(ctx.wallet_mut(), RESTORE_DEPTH).await?;

    assert_eq!(
        facade(&mut ctx, program).operation_status([2; 32]),
        None,
        "restoring from the mnemonic forgets every recorded operation"
    );
    // Nor did the receipt secret survive: the operator derives it again from the node key.
    let rederived_secret = receipt_secret(&carol_key.to_bytes());
    assert_eq!(
        facade(&mut ctx, program)
            .receipts(carol, &rederived_secret)
            .await?,
        receipts,
        "the node key, the mnemonic and the chain recover every receipt"
    );
    assert!(
        facade(&mut ctx, program)
            .receipts(carol, &receipt_secret(&alice_key.to_bytes()))
            .await?
            .is_empty(),
        "another node's receipt secret opens none of Carol's receipts"
    );
    for (index, sent_to) in (0..).zip(&sent) {
        let opening = facade(&mut ctx, program).opening(carol, index, &rederived_secret)?;
        assert_eq!(
            cash_out_receipt(opening.uplink_account, carol_node, opening.blinding_factor),
            *sent_to,
            "the recovered opening recomputes the receipt its cash out sent"
        );
    }

    assert!(
        facade(&mut ctx, program).intent(alice).is_none(),
        "the restored wallet no longer holds the invitation Alice registered with"
    );
    import_oracle(&mut ctx)?;
    publish(&mut ctx, program, 3, &[bob_node, alice_node, carol_node]).await?;
    // The restored wallet lost the publications it had seen, so Alice's claim reads epochs 1 and 2
    // back from the indexer.
    wait_for_indexer_to_catch_up(&ctx).await?;
    assert_eq!(
        claim(&mut ctx, program, alice, [7; 32]).await?,
        1,
        "the restored Alice is paid for her active child"
    );
    assert_eq!(
        claim(&mut ctx, program, carol, [5; 32]).await?,
        2,
        "the restored Carol keeps earning, with the credit Alice addressed from her own state"
    );
    let third = cash_out(&mut ctx, program, carol, &rederived_secret, [6; 32]).await?;
    assert_eq!(
        facade(&mut ctx, program)
            .receipts(carol, &rederived_secret)
            .await?
            .iter()
            .map(|receipt| (receipt.index, receipt.account_id))
            .collect::<Vec<_>>(),
        vec![(0, sent[0]), (1, sent[1]), (2, third)],
        "the restored wallet cashes out after its last receipt"
    );

    Ok(())
}

#[test]
async fn late_epochs_still_pay_and_each_credit_is_redeemed_once() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer = genesis_payer(&mut ctx);
    let program = deploy_referral(&mut ctx, payer.account_id).await?;
    fund_oracle(&mut ctx, payer.account_id).await?;

    // Bob refers Alice, who refers Chris, and later Dan.
    let (bob_key, bob_node) = node(1);
    let (alice_key, alice_node) = node(2);
    let (chris_key, chris_node) = node(3);
    let (dan_key, dan_node) = node(4);
    let bob = facade(&mut ctx, program).create_participant()?;
    let alice = facade(&mut ctx, program).create_participant()?;
    let chris = facade(&mut ctx, program).create_participant()?;
    let dan = facade(&mut ctx, program).create_participant()?;
    register(&mut ctx, program, bob, &bob_key, None, None).await?;
    let bob_invites_alice = invite(&mut ctx, program, bob, &bob_key)?;
    register(
        &mut ctx,
        program,
        alice,
        &alice_key,
        Some(bob_node),
        Some(bob_invites_alice),
    )
    .await?;
    let alice_invites_chris = invite(&mut ctx, program, alice, &alice_key)?;
    register(
        &mut ctx,
        program,
        chris,
        &chris_key,
        Some(alice_node),
        Some(alice_invites_chris),
    )
    .await?;

    let everyone = [bob_node, alice_node, chris_node, dan_node];
    for epoch in 1..=3 {
        publish(&mut ctx, program, epoch, &everyone).await?;
    }

    // Alice claims epoch 3 first, out of order.
    let latest = current_claim(&mut ctx, program, alice).await?;
    submit_and_settle(&mut ctx, program, [1; 32], latest).await?;
    assert_eq!(
        reward_balance(&mut ctx, program, alice)?,
        1,
        "epoch 3 pays Alice for Chris"
    );
    assert_eq!(
        facade(&mut ctx, program).claimable(alice).await?,
        2,
        "the epochs an earlier claim skipped still pay"
    );
    assert_eq!(
        claim(&mut ctx, program, alice, [2; 32]).await?,
        3,
        "epochs 1 and 2 pay Alice for Chris once each"
    );

    // Dan registers under Alice during epoch 3, after Alice already claimed it.
    let alice_invites_dan = invite(&mut ctx, program, alice, &alice_key)?;
    register(
        &mut ctx,
        program,
        dan,
        &dan_key,
        Some(alice_node),
        Some(alice_invites_dan),
    )
    .await?;
    assert_eq!(
        claim(&mut ctx, program, alice, [3; 32]).await?,
        4,
        "epoch 3 pays again for Dan alone, who counts only from the epoch he registered in"
    );

    // Alice forwarded one credit for each of epochs 1 and 2, and two for epoch 3.
    let notes = facade(&mut ctx, program).notes(bob)?;
    let third_credits: Vec<AccountId> = notes
        .iter()
        .filter(|(_id, note)| matches!(note, State::Credit { epoch: 3, .. }))
        .map(|(id, _note)| *id)
        .collect();
    assert_eq!(
        third_credits.len(),
        2,
        "two claims of epoch 3 forwarded two credits"
    );
    let announcement = notes
        .iter()
        .filter(|(_id, note)| matches!(note, State::Child { .. }))
        .map(|(id, _note)| *id);

    // Bob redeems one epoch 3 credit, then the planner settles the rest.
    let third = facade(&mut ctx, program).registry().await?;
    let one_credit = OperationKind::Claim {
        participant: bob,
        epochs: vec![ClaimedEpoch {
            epoch: 3,
            active_digest: active_digest(&third.active_nodes),
            notes: announcement.chain(third_credits.first().copied()).collect(),
        }],
    };
    submit_and_settle(&mut ctx, program, [4; 32], one_credit).await?;
    assert_eq!(
        reward_balance(&mut ctx, program, bob)?,
        2,
        "epoch 3 pays Bob for Alice and for the one credit redeemed"
    );
    assert_eq!(
        facade(&mut ctx, program).claimable(bob).await?,
        5,
        "epochs 1 and 2 pay for Alice and their credits, and the second epoch 3 credit pays alone"
    );
    assert_eq!(
        claim(&mut ctx, program, bob, [5; 32]).await?,
        7,
        "every credit is redeemed once"
    );
    assert_eq!(
        facade(&mut ctx, program).claimable(bob).await?,
        0,
        "nothing is left to redeem"
    );

    Ok(())
}

#[test]
async fn publications_only_advance_and_never_change() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer = genesis_payer(&mut ctx);
    let program = deploy_referral(&mut ctx, payer.account_id).await?;
    fund_oracle(&mut ctx, payer.account_id).await?;
    let (_, first) = node(1);
    let (_, second) = node(2);

    publish(&mut ctx, program, 1, &[first]).await?;
    publish(&mut ctx, program, 2, &[first]).await?;
    let archived = archived_digest(&ctx, program, 2).await?;
    assert_eq!(
        archived,
        Some(active_digest(&BTreeSet::from([first]))),
        "a publication archives its active set's digest"
    );

    // Republishing epoch 2 and publishing an earlier epoch are both refused. Whether the sequencer
    // turns them away at submission or they fail at inclusion, nothing changes.
    let _repeated = facade(&mut ctx, program)
        .publish(2, BTreeSet::from([second]))
        .await;
    let _earlier = facade(&mut ctx, program)
        .publish(1, BTreeSet::from([second]))
        .await;
    // Let any refused attempt leave the mempool before the oracle publishes again.
    wait_blocks(&ctx, 3).await?;
    publish(&mut ctx, program, 3, &[second]).await?;

    assert_eq!(
        archived_digest(&ctx, program, 2).await?,
        archived,
        "an epoch's archived publication never changes"
    );
    let registry = facade(&mut ctx, program).registry().await?;
    assert_eq!(
        (registry.epoch, registry.active_nodes),
        (3, BTreeSet::from([second])),
        "the registry holds only the publications that advanced it"
    );

    Ok(())
}
