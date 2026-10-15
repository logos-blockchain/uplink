use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
};

use anyhow::Context as _;
use common::{HashType, transaction::LeeTransaction};
use indexer_service_protocol::Transaction as IndexedTransaction;
use indexer_service_rpc::RpcClient as _;
use jsonrpsee::http_client::HttpClientBuilder;
use lee::{
    Account, AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies,
    program::Program,
};
use lee_core::{
    BlockId, Commitment, PrivateAccountKind,
    account::{ProgramShardSelector, ShardData},
    program::InstructionData,
};
use referral_core::{
    Claim, Effect, Epoch, EpochClaim, Instruction, Invitation, NodeId, ORACLE_ACCOUNT_ID,
    Participant, ParticipantAuthorizationV1, Points, Referrer, Registry, State, active_digest,
    blinding_factor, cash_out_receipt, ed25519_dalek::Signature, epoch_account,
};
use url::Url;
use wallet::{
    AccountIdentity, AccountMention, ExecutionFailureKind, WalletCore,
    storage::key_chain::FoundPrivateAccount,
};

use crate::store::{
    ClaimedEpoch, OperationKind, PendingOperation, PendingRegistration, Publication,
    ReferralIntent, ReferralStore, RegistryGuard, SubmissionStatus, random_identifier,
};

const HISTORY_PAGE_LIMIT: u64 = 10;

/// Blocks after which a sent attempt that is neither included nor outspent counts as lost, and a
/// later submit builds it again. Both attempts spend the same inputs, so at most one is included.
const RESUBMIT_AFTER_BLOCKS: BlockId = 20;

/// Most epochs one claim settles. A claim's proof grows with every epoch it carries.
const MAX_CLAIM_EPOCHS: usize = 16;

/// Most active-set entries one claim carries across its epochs, about 2,200 guest cycles each. An
/// epoch whose set alone is larger still goes in a claim of its own.
const MAX_CLAIM_ACTIVE_ENTRIES: usize = 2_048;

/// File name of the referral store, kept next to the wallet's own storage.
const STORE_FILE_NAME: &str = "referral.json";

pub struct Referral<'wallet> {
    wallet: &'wallet mut WalletCore,
    program: ProgramWithDependencies,
    store: ReferralStore,
    store_path: PathBuf,
    indexer_addr: Option<Url>,
}

/// One attempt's account mentions and instruction, with what is recorded alongside it.
struct Request {
    accounts: Vec<AccountMention>,
    instruction: InstructionData,
    /// The wallet's own private accounts the attempt spends.
    inputs: Vec<AccountId>,
    registry_guard: Option<RegistryGuard>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Opening {
    pub uplink_account: AccountId,
    pub node: NodeId,
    pub blinding_factor: [u8; 32],
    pub account_id: AccountId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub index: u64,
    pub account_id: AccountId,
    pub points: Points,
}

struct ReceiptKeys {
    uplink_account: AccountId,
    participant: AccountId,
    node: NodeId,
    receipt_secret: [u8; 32],
}

impl ReceiptKeys {
    fn opening(&self, index: u64) -> Opening {
        let blinding_factor = blinding_factor(
            &self.receipt_secret,
            self.uplink_account,
            self.participant,
            index,
        );
        Opening {
            uplink_account: self.uplink_account,
            node: self.node,
            blinding_factor,
            account_id: cash_out_receipt(self.uplink_account, self.node, blinding_factor),
        }
    }
}

impl<'wallet> Referral<'wallet> {
    /// Opens the referral deployment at `uplink_account` over `wallet`, with the referral store
    /// that sits next to the wallet's storage.
    pub fn new(
        wallet: &'wallet mut WalletCore,
        program: Program,
        uplink_account: AccountId,
    ) -> Result<Self, ExecutionFailureKind> {
        let store_path = Self::store_path(wallet);
        let store =
            ReferralStore::load(&store_path).map_err(ExecutionFailureKind::SequencerError)?;
        let dependencies = HashMap::from([(uplink_account, program.clone())]);
        Ok(Self {
            wallet,
            program: ProgramWithDependencies::new(program, uplink_account, dependencies),
            store,
            store_path,
            indexer_addr: None,
        })
    }

    /// Where the referral store of `wallet` is kept.
    #[must_use]
    pub fn store_path(wallet: &WalletCore) -> PathBuf {
        wallet.storage_path().with_file_name(STORE_FILE_NAME)
    }

    /// Reads past publications' active sets from the indexer at `indexer_addr`, which claiming any
    /// epoch but the current one needs.
    #[must_use]
    pub fn with_indexer(mut self, indexer_addr: Url) -> Self {
        self.indexer_addr = Some(indexer_addr);
        self
    }

    #[must_use]
    pub const fn uplink_account(&self) -> AccountId {
        self.program.self_account_id
    }

    pub fn create_participant(&mut self) -> Result<AccountId, ExecutionFailureKind> {
        let identifier = random_identifier();
        let key_chain = self.wallet.storage_mut().key_chain_mut();
        let cci = key_chain.create_private_accounts_key(None);
        let participant = key_chain
            .register_identifier_on_private_key_chain(&cci, identifier)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        key_chain
            .insert_private_account(
                participant,
                PrivateAccountKind::Regular(identifier),
                Account::default(),
            )
            .map_err(ExecutionFailureKind::SequencerError)?;
        self.persist()?;
        Ok(participant)
    }

    pub fn state(&self, account: AccountId) -> Result<State, ExecutionFailureKind> {
        let found = self.found(account)?;
        State::decode(found.account.data.shard(self.uplink_account()))
            .ok_or(ExecutionFailureKind::AccountDataError(account))
    }

    #[must_use]
    pub fn intent(&self, participant: AccountId) -> Option<&ReferralIntent> {
        self.store.intents.get(&participant)
    }

    #[must_use]
    pub fn pending_registration(&self, participant: AccountId) -> Option<&PendingRegistration> {
        self.intent(participant)?.registration.as_ref()
    }

    #[must_use]
    pub fn operation_status(&self, reference: [u8; 32]) -> Option<SubmissionStatus> {
        self.store
            .operation(reference)
            .map(|operation| operation.status)
    }

    pub fn invitation(
        &self,
        participant: AccountId,
        node: NodeId,
    ) -> Result<Invitation, ExecutionFailureKind> {
        let found = self.found(participant)?;
        Ok(Invitation::new(
            node,
            found.key_chain.nullifier_public_key,
            found.key_chain.viewing_public_key.clone(),
        ))
    }

    pub fn import_invitation(
        &mut self,
        participant: AccountId,
        invitation: Invitation,
    ) -> Result<(), ExecutionFailureKind> {
        let parent = invitation.parent_node;
        let mut intent = self
            .intent(participant)
            .cloned()
            .unwrap_or_else(|| ReferralIntent::new(self.uplink_account()));
        let recorded = intent.registration.as_ref().map_or_else(
            || {
                self.participant(participant)
                    .ok()
                    .map(|me| me.referrer_node())
            },
            |pending| Some(pending.referrer),
        );
        if recorded.is_some_and(|referrer| referrer != Some(parent)) {
            return Err(conflict(
                "this invitation names another referrer than the participant's",
            ));
        }

        intent.invitation = Some(invitation);
        self.store_intent(participant, intent)
    }

    pub fn prepare_registration(
        &mut self,
        participant: AccountId,
        node: NodeId,
        referrer: Option<NodeId>,
    ) -> Result<ParticipantAuthorizationV1, ExecutionFailureKind> {
        let uplink_account = self.uplink_account();
        let mut intent = self
            .intent(participant)
            .cloned()
            .unwrap_or_else(|| ReferralIntent::new(uplink_account));

        if let Some(parent) = referrer
            && intent
                .invitation
                .as_ref()
                .map(|invitation| invitation.parent_node)
                != Some(parent)
        {
            return Err(conflict(
                "the referrer's invitation is needed before its registration",
            ));
        }
        if self.participant(participant).is_ok() {
            return Err(conflict("this participant is already registered"));
        }

        match &intent.registration {
            Some(pending)
                if intent.uplink_account == uplink_account
                    && pending.node == node
                    && pending.referrer == referrer => {}
            Some(_pending) => {
                return Err(conflict(
                    "a pending registration for another deployment, node or referrer is unresolved",
                ));
            }
            None => {
                intent.uplink_account = uplink_account;
                intent.registration = Some(PendingRegistration {
                    node,
                    referrer,
                    signature: None,
                });
            }
        }
        self.store_intent(participant, intent)?;

        Ok(ParticipantAuthorizationV1::new(
            uplink_account,
            node,
            participant,
            referrer,
        ))
    }

    pub fn attach_node_signature(
        &mut self,
        participant: AccountId,
        signature: [u8; 64],
    ) -> Result<(), ExecutionFailureKind> {
        let mut intent = self
            .intent(participant)
            .cloned()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        let pending = intent
            .registration
            .as_mut()
            .ok_or(ExecutionFailureKind::AccountDataError(participant))?;
        pending.signature = Some(Signature::from_bytes(&signature));

        let authorization = ParticipantAuthorizationV1::new(
            intent.uplink_account,
            pending.node,
            participant,
            pending.referrer,
        );
        if !authorization.verify(&signature) {
            return Err(ExecutionFailureKind::AccountDataError(participant));
        }

        self.store_intent(participant, intent)
    }

    pub async fn registry(&self) -> Result<Registry, ExecutionFailureKind> {
        let uplink_account = self.uplink_account();
        let account = self
            .wallet
            .get_account_view(ProgramShardSelector::new(ORACLE_ACCOUNT_ID, uplink_account))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        decode_registry(&account, uplink_account)
    }

    pub fn notes(
        &self,
        participant: AccountId,
    ) -> Result<Vec<(AccountId, State)>, ExecutionFailureKind> {
        let uplink_account = self.uplink_account();
        let found = self.found(participant)?;
        let me = decode_participant(found.account, uplink_account)?;
        let npk = found.key_chain.nullifier_public_key;
        Ok(self
            .wallet
            .storage()
            .key_chain()
            .private_accounts()
            .filter(|note| note.key_chain.nullifier_public_key == npk)
            .filter_map(|note| {
                let state = State::decode(note.account.data.shard(uplink_account))?;
                let addressed = match state {
                    State::Child { referrer, .. } => referrer == me.node,
                    State::Credit { recipient_node, .. } => recipient_node == me.node,
                    State::Registry(_)
                    | State::Participant(_)
                    | State::CashOut { .. }
                    | State::Publication { .. } => false,
                };
                addressed.then(|| {
                    let id = AccountId::for_private_account(
                        &note.key_chain.nullifier_public_key,
                        &note.key_chain.viewing_public_key,
                        note.kind,
                    );
                    (id, state)
                })
            })
            .collect())
    }

    pub async fn claimable(
        &mut self,
        participant: AccountId,
    ) -> Result<Points, ExecutionFailureKind> {
        self.batches(participant)
            .await?
            .iter()
            .try_fold(0, |sum: Points, (_operation, total)| {
                sum.checked_add(*total)
            })
            .ok_or_else(|| conflict("the claimable total overflows"))
    }

    pub async fn claim_operations(
        &mut self,
        participant: AccountId,
    ) -> Result<Vec<OperationKind>, ExecutionFailureKind> {
        Ok(self
            .batches(participant)
            .await?
            .into_iter()
            .map(|(operation, _total)| operation)
            .collect())
    }

    /// Plans the participant's claims: every published epoch it can still earn in, oldest first,
    /// batched by [`MAX_CLAIM_EPOCHS`] and [`MAX_CLAIM_ACTIVE_ENTRIES`], each with what it pays.
    ///
    /// Epochs go in order, so each child is paid for every epoch it can be; the program would pay
    /// an earlier epoch claimed later only its credits.
    async fn batches(
        &mut self,
        participant: AccountId,
    ) -> Result<Vec<(OperationKind, Points)>, ExecutionFailureKind> {
        let claimant = self.participant(participant)?;
        let registry = self.registry().await?;
        let notes = self.notes(participant)?;

        let Some(earliest) = earliest_claimable(&claimant, &notes) else {
            return Ok(Vec::new());
        };
        let mut published = BTreeMap::new();
        for epoch in earliest.max(1)..=registry.epoch {
            if let Some(active) = self.published_active(&registry, epoch).await? {
                published.insert(epoch, active);
            }
        }

        batch_claims(participant, plan_epochs(&claimant, notes, published))
    }

    /// The active set of published `epoch`, checked against its publication account, or `None` if
    /// the epoch was never published.
    async fn published_active(
        &mut self,
        registry: &Registry,
        epoch: Epoch,
    ) -> Result<Option<BTreeSet<NodeId>>, ExecutionFailureKind> {
        let uplink_account = self.uplink_account();
        let account = self
            .wallet
            .get_account_view(ProgramShardSelector::new(
                epoch_account(uplink_account, epoch),
                uplink_account,
            ))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let Some(State::Publication {
            epoch: published,
            active_digest: digest,
        }) = State::decode(account.data.shard(uplink_account))
        else {
            return Ok(None);
        };
        if published != epoch {
            return Err(conflict(
                "an epoch account holds another epoch's publication",
            ));
        }
        Ok(Some(self.publication(registry, epoch, digest).await?))
    }

    async fn publication(
        &mut self,
        registry: &Registry,
        epoch: Epoch,
        digest: [u8; 32],
    ) -> Result<BTreeSet<NodeId>, ExecutionFailureKind> {
        if (registry.epoch, active_digest(&registry.active_nodes)) == (epoch, digest) {
            return Ok(registry.active_nodes.clone());
        }
        let uplink_account = self.uplink_account();
        if let Some(active) = self.store.publication(uplink_account, epoch, digest) {
            return Ok(active.clone());
        }
        self.refresh_publications().await?;
        self.store
            .publication(uplink_account, epoch, digest)
            .cloned()
            .ok_or_else(|| conflict("the active set of that publication is not available"))
    }

    async fn refresh_publications(&mut self) -> Result<(), ExecutionFailureKind> {
        let uplink_account = self.uplink_account();
        let mut offset = self
            .store
            .history_offsets
            .get(&uplink_account)
            .copied()
            .unwrap_or(0);
        let indexer_addr = self
            .indexer_addr
            .as_ref()
            .ok_or_else(|| conflict("past publications need an indexer endpoint"))?;
        let indexer = HttpClientBuilder::default()
            .build(indexer_addr)
            .context("Failed to create the indexer client")
            .map_err(ExecutionFailureKind::SequencerError)?;
        let oracle = indexer_service_protocol::AccountId {
            value: *ORACLE_ACCOUNT_ID.value(),
        };
        let mut found = Vec::new();
        loop {
            let page = indexer
                .get_transactions_by_account(oracle, offset, HISTORY_PAGE_LIMIT)
                .await
                .context("Failed to read the oracle's history from the indexer")
                .map_err(ExecutionFailureKind::SequencerError)?;
            let fetched = u64::try_from(page.len()).expect("a page length fits in u64");
            offset = offset
                .checked_add(fetched)
                .expect("the history offset fits in u64");
            found.extend(
                page.iter()
                    .filter_map(|transaction| published(transaction, uplink_account)),
            );
            if fetched < HISTORY_PAGE_LIMIT {
                break;
            }
        }
        self.persisted(|store| {
            for publication in found {
                if !store.publications.contains(&publication) {
                    store.publications.push(publication);
                }
            }
            store.history_offsets.insert(uplink_account, offset);
        })
    }

    pub async fn publish(
        &self,
        epoch: Epoch,
        active: BTreeSet<NodeId>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let uplink_account = self.uplink_account();
        self.wallet
            .send_pub_tx(
                vec![
                    AccountIdentity::Public(ORACLE_ACCOUNT_ID).select_program_shard(uplink_account),
                    AccountIdentity::PublicNoSign(epoch_account(uplink_account, epoch))
                        .select_program_shard(uplink_account),
                ],
                instruction_data(Instruction::Publish { epoch, active }),
                uplink_account,
            )
            .await
    }

    /// The opening of the participant's `index`-th receipt, under its node's `receipt_secret`.
    pub fn opening(
        &self,
        participant: AccountId,
        index: u64,
        receipt_secret: &[u8; 32],
    ) -> Result<Opening, ExecutionFailureKind> {
        Ok(self
            .receipt_keys(participant, receipt_secret)?
            .opening(index))
    }

    /// The participant's receipts, found from its node's `receipt_secret` and the chain alone.
    pub async fn receipts(
        &self,
        participant: AccountId,
        receipt_secret: &[u8; 32],
    ) -> Result<Vec<Receipt>, ExecutionFailureKind> {
        let keys = self.receipt_keys(participant, receipt_secret)?;
        Ok(self.scan(&keys).await?.0)
    }

    /// Cashes the whole reward balance out into the participant's next receipt, under its node's
    /// `receipt_secret`. The secret is used for this call only and never stored.
    pub async fn cash_out(
        &mut self,
        reference: [u8; 32],
        participant: AccountId,
        receipt_secret: &[u8; 32],
    ) -> Result<(HashType, SubmissionStatus), ExecutionFailureKind> {
        let keys = self.receipt_keys(participant, receipt_secret)?;
        let recorded = self
            .store
            .operation(reference)
            .map(|recorded| recorded.operation.clone());
        let index = match recorded {
            Some(OperationKind::CashOut {
                participant: holder,
                index,
                ..
            }) if holder == participant => index,
            _ => self.scan(&keys).await?.1,
        };
        let operation = OperationKind::CashOut {
            participant,
            index,
            receipt: keys.opening(index).account_id,
        };
        self.submit_with(reference, operation, Some(receipt_secret))
            .await
    }

    /// Submits `operation` under `reference`, or resumes the attempt already recorded under it.
    ///
    /// A cash-out needs its receipt secret and goes through [`Self::cash_out`] instead.
    pub async fn submit(
        &mut self,
        reference: [u8; 32],
        operation: OperationKind,
    ) -> Result<(HashType, SubmissionStatus), ExecutionFailureKind> {
        self.submit_with(reference, operation, None).await
    }

    async fn submit_with(
        &mut self,
        reference: [u8; 32],
        operation: OperationKind,
        receipt_secret: Option<&[u8; 32]>,
    ) -> Result<(HashType, SubmissionStatus), ExecutionFailureKind> {
        let uplink_account = self.uplink_account();
        let recorded = self.store.operation(reference).cloned();
        if let Some(recorded) = recorded {
            if recorded.uplink_account != uplink_account || recorded.operation != operation {
                return Err(conflict(
                    "this reference was already used for a different deployment or operation",
                ));
            }
            // A pending attempt is left to land. One that is lost, outspent or superseded
            // reconciles as rejected and is built again from the current state.
            let status = self.reconcile(reference).await?;
            if status != SubmissionStatus::Rejected {
                return Ok((recorded.hash, status));
            }
        }

        let participant = operation.participant();
        let unresolved: Vec<[u8; 32]> = self
            .store
            .operations
            .values()
            .filter(|other| {
                other.reference != reference
                    && !other.status.is_conclusive()
                    && other.operation.participant() == participant
            })
            .map(|other| other.reference)
            .collect();
        for other in unresolved {
            if !self.reconcile(other).await?.is_conclusive() {
                return Err(conflict(
                    "another unresolved operation for this participant is in flight",
                ));
            }
        }

        let sent = self.send(reference, operation, receipt_secret).await?;
        let hash = sent.hash;
        self.persisted(|store| store.record_operation(sent))?;
        Ok((hash, SubmissionStatus::Pending))
    }

    pub async fn reconcile(
        &mut self,
        reference: [u8; 32],
    ) -> Result<SubmissionStatus, ExecutionFailureKind> {
        let Some(recorded) = self.store.operation(reference).cloned() else {
            return Ok(SubmissionStatus::Rejected);
        };
        if recorded.status != SubmissionStatus::Settled
            && let OperationKind::CashOut { receipt, .. } = recorded.operation
        {
            let shard = self.receipt_shard(recorded.uplink_account, receipt).await?;
            return match cash_out_transition(recorded.status, &shard, self.is_outspent(&recorded)) {
                Some(status) => self.set_status(reference, status),
                None => Ok(recorded.status),
            };
        }
        if recorded.status.is_conclusive() {
            return Ok(recorded.status);
        }

        let registry = self
            .wallet
            .get_account_view(ProgramShardSelector::new(
                ORACLE_ACCOUNT_ID,
                recorded.uplink_account,
            ))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        if self.is_included(&recorded).await? {
            return self.set_status(reference, SubmissionStatus::Settled);
        }

        if self.is_outspent(&recorded) || is_superseded(&recorded, &registry)? {
            return self.set_status(reference, SubmissionStatus::Rejected);
        }

        if self.is_lost(&recorded).await? {
            return self.set_status(reference, SubmissionStatus::Rejected);
        }

        Ok(SubmissionStatus::Pending)
    }

    /// Whether the attempt's transaction is in a block and its new commitments are in the
    /// commitment set.
    async fn is_included(&self, recorded: &PendingOperation) -> Result<bool, ExecutionFailureKind> {
        let included = self
            .wallet
            .get_transaction(recorded.hash)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let Some((LeeTransaction::PrivacyPreserving(transaction), _block)) = included else {
            return Ok(false);
        };
        self.commitments_settled(&transaction.message().commitments())
            .await
    }

    async fn commitments_settled(
        &self,
        commitments: &[Commitment],
    ) -> Result<bool, ExecutionFailureKind> {
        if commitments.is_empty() {
            return Ok(false);
        }
        let (proofs, _root) = self
            .wallet
            .get_proofs_and_root(commitments)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        Ok(proofs.len() == commitments.len() && proofs.iter().all(Option::is_some))
    }

    /// Whether the attempt has waited [`RESUBMIT_AFTER_BLOCKS`] without being included.
    async fn is_lost(&self, recorded: &PendingOperation) -> Result<bool, ExecutionFailureKind> {
        let last_block = self
            .wallet
            .get_last_block_id()
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        Ok(is_lost_at(last_block, recorded.sent_at_block))
    }

    /// Builds, proves and sends one attempt at `operation`, returning what to record for it.
    async fn send(
        &mut self,
        reference: [u8; 32],
        operation: OperationKind,
        receipt_secret: Option<&[u8; 32]>,
    ) -> Result<PendingOperation, ExecutionFailureKind> {
        let request = match &operation {
            OperationKind::Register { participant } => self.register_request(*participant).await?,
            OperationKind::Claim {
                participant,
                epochs,
            } => self.claim_request(*participant, epochs).await?,
            OperationKind::CashOut {
                participant,
                index,
                receipt,
            } => {
                let receipt_secret = receipt_secret
                    .ok_or_else(|| conflict("a cash out needs its receipt secret; use cash_out"))?;
                self.cash_out_request(*participant, *index, *receipt, receipt_secret)
                    .await?
            }
        };

        // Taken before sending: these are the states the attempt spends, which a later commitment
        // that differs from them shows to be outspent.
        let input_commitments = request
            .inputs
            .iter()
            .map(|account_id| {
                self.wallet
                    .get_private_account_commitment(*account_id)
                    .map(|commitment| (*account_id, commitment))
                    .ok_or(ExecutionFailureKind::KeyNotFoundError)
            })
            .collect::<Result<_, _>>()?;
        let sent_at_block = self
            .wallet
            .get_last_block_id()
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let (hash, _shared_secrets) = self
            .wallet
            .send_privacy_preserving_tx(request.accounts, request.instruction, &self.program)
            .await?;

        Ok(PendingOperation {
            reference,
            uplink_account: self.uplink_account(),
            operation,
            hash,
            sent_at_block,
            registry_guard: request.registry_guard,
            input_commitments,
            status: SubmissionStatus::Pending,
        })
    }

    async fn register_request(
        &self,
        participant: AccountId,
    ) -> Result<Request, ExecutionFailureKind> {
        let uplink_account = self.uplink_account();
        let (node, referrer, node_signature) = self
            .pending_registration(participant)
            .and_then(|pending| Some((pending.node, pending.referrer, pending.signed()?)))
            .ok_or_else(|| conflict("this participant has no signed registration"))?;
        let registry = self.registry().await?;
        if registry.registered_nodes.contains(&node) {
            return Err(conflict("this node is already registered"));
        }
        if referrer.is_some_and(|parent| !registry.registered_nodes.contains(&parent)) {
            return Err(conflict("the referrer is not registered"));
        }

        // The participant's state keeps the referrer's keys, so later claims address the
        // referrer without the invitation.
        let referrer = referrer
            .map(|parent| {
                self.intent(participant)
                    .and_then(|intent| intent.invitation.clone())
                    .filter(|invitation| invitation.parent_node == parent)
                    .map(Referrer::from)
                    .ok_or_else(|| {
                        conflict("the referrer's invitation is needed to address its note")
                    })
            })
            .transpose()?;

        let mut accounts = vec![
            self.own_private(participant)?
                .select_program_shard(uplink_account),
            AccountIdentity::PublicNoSign(ORACLE_ACCOUNT_ID).select_program_shard(uplink_account),
        ];
        self.deliver(referrer.as_ref(), &mut accounts);

        Ok(Request {
            accounts,
            instruction: instruction_data(Instruction::Register {
                node,
                referrer,
                node_signature,
                pool: registry.registered_nodes,
                epoch: registry.epoch,
            }),
            inputs: vec![participant],
            registry_guard: Some(RegistryGuard::Registers {
                node,
                epoch: registry.epoch,
            }),
        })
    }

    /// Builds a claim of `epochs` against the current state, so each epoch's total is what the
    /// program will compute.
    async fn claim_request(
        &mut self,
        participant: AccountId,
        epochs: &[ClaimedEpoch],
    ) -> Result<Request, ExecutionFailureKind> {
        let registry = self.registry().await?;
        let claimant = self.participant(participant)?;
        let listed = self.notes(participant)?;
        let uplink_account = self.uplink_account();

        let mut simulated = claimant.clone();
        let mut accounts = vec![
            self.own_private(participant)?
                .select_program_shard(uplink_account),
        ];
        let mut inputs = vec![participant];
        let mut claims = Vec::with_capacity(epochs.len());
        for claimed in epochs {
            let active = self
                .published_active(&registry, claimed.epoch)
                .await?
                .ok_or_else(|| conflict("a claimed epoch was never published"))?;
            if active_digest(&active) != claimed.active_digest {
                return Err(conflict(
                    "a claimed epoch was published with another active set",
                ));
            }
            if !active.contains(&simulated.node) {
                return Err(conflict("the participant cannot claim that epoch"));
            }
            let notes = claimed
                .notes
                .iter()
                .map(|note| {
                    listed
                        .iter()
                        .find_map(|(id, state)| (id == note).then(|| state.clone()))
                        .ok_or_else(|| conflict("this note is not addressed to the participant"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut epoch_claim = EpochClaim {
                epoch: claimed.epoch,
                active,
                notes,
                total: 0,
            };
            let total = simulated.claim(&epoch_claim);
            epoch_claim.total = total;
            if total == 0 {
                return Err(conflict("nothing to claim in a claimed epoch"));
            }

            accounts.push(
                AccountIdentity::PublicNoSign(epoch_account(uplink_account, claimed.epoch))
                    .select_program_shard(uplink_account),
            );
            for note in &claimed.notes {
                accounts.push(
                    self.own_private(*note)?
                        .select_program_shard(uplink_account),
                );
            }
            inputs.extend(claimed.notes.iter().copied());
            let forward_to = epoch_claim.forward_to(claimant.referrer_node());
            let referrer = claimant
                .referrer
                .as_ref()
                .filter(|referrer| Some(referrer.node) == forward_to);
            self.deliver(referrer, &mut accounts);
            claims.push(epoch_claim);
        }

        Ok(Request {
            accounts,
            instruction: instruction_data(Instruction::Claim(Claim {
                epochs: claims,
                referrer: claimant.referrer_node(),
            })),
            inputs,
            registry_guard: None,
        })
    }

    async fn cash_out_request(
        &self,
        participant: AccountId,
        index: u64,
        receipt: AccountId,
        receipt_secret: &[u8; 32],
    ) -> Result<Request, ExecutionFailureKind> {
        let uplink_account = self.uplink_account();
        let points = self.participant(participant)?.reward_balance;
        if points == 0 {
            return Err(conflict("nothing to cash out"));
        }
        let keys = self.receipt_keys(participant, receipt_secret)?;
        if self.scan(&keys).await?.1 != index {
            return Err(conflict(
                "a cash out takes the participant's first free receipt index",
            ));
        }
        let opening = keys.opening(index);
        if opening.account_id != receipt {
            return Err(conflict(
                "this receipt secret opens another receipt than the one recorded",
            ));
        }

        Ok(Request {
            accounts: vec![
                self.own_private(participant)?
                    .select_program_shard(uplink_account),
                AccountIdentity::PublicNoSign(opening.account_id)
                    .select_program_shard(uplink_account),
            ],
            instruction: instruction_data(Instruction::CashOut {
                node: opening.node,
                points,
                blinding_factor: opening.blinding_factor,
            }),
            inputs: vec![participant],
            registry_guard: None,
        })
    }

    async fn scan(&self, keys: &ReceiptKeys) -> Result<(Vec<Receipt>, u64), ExecutionFailureKind> {
        let mut receipts = Vec::new();
        let mut index = 0;
        loop {
            let account_id = keys.opening(index).account_id;
            let shard = self.receipt_shard(keys.uplink_account, account_id).await?;
            if shard.is_empty() {
                return Ok((receipts, index));
            }
            if let Some(State::CashOut { points }) = State::decode(&shard) {
                receipts.push(Receipt {
                    index,
                    account_id,
                    points,
                });
            }
            index = index.checked_add(1).expect("cash-out index fits in u64");
        }
    }

    fn receipt_keys(
        &self,
        participant: AccountId,
        receipt_secret: &[u8; 32],
    ) -> Result<ReceiptKeys, ExecutionFailureKind> {
        Ok(ReceiptKeys {
            uplink_account: self.uplink_account(),
            participant,
            node: self.participant(participant)?.node,
            receipt_secret: *receipt_secret,
        })
    }

    async fn receipt_shard(
        &self,
        uplink_account: AccountId,
        receipt: AccountId,
    ) -> Result<ShardData, ExecutionFailureKind> {
        let account = self
            .wallet
            .get_account_view(ProgramShardSelector::new(receipt, uplink_account))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        Ok(account.data.shard(uplink_account).clone())
    }

    /// Mentions a new note account addressed to `referrer`, if there is one to notify.
    fn deliver(&self, referrer: Option<&Referrer>, accounts: &mut Vec<AccountMention>) {
        if let Some(referrer) = referrer {
            accounts.push(foreign_note(referrer).select_program_shard(self.uplink_account()));
        }
    }

    fn is_outspent(&self, recorded: &PendingOperation) -> bool {
        recorded
            .input_commitments
            .iter()
            .any(|(account_id, spent)| {
                self.wallet
                    .get_private_account_commitment(*account_id)
                    .is_some_and(|current| current != *spent)
            })
    }

    fn set_status(
        &mut self,
        reference: [u8; 32],
        status: SubmissionStatus,
    ) -> Result<SubmissionStatus, ExecutionFailureKind> {
        self.persisted(|store| {
            let Some(recorded) = store.operation_mut(reference) else {
                return;
            };
            recorded.status = status;
            if status != SubmissionStatus::Settled {
                return;
            }
            let registered = matches!(recorded.operation, OperationKind::Register { .. });
            let participant = recorded.operation.participant();
            if let Some(intent) = store.intents.get_mut(&participant)
                && registered
            {
                intent.registration = None;
            }
        })?;
        Ok(status)
    }

    fn store_intent(
        &mut self,
        participant: AccountId,
        intent: ReferralIntent,
    ) -> Result<(), ExecutionFailureKind> {
        self.persisted(|store| {
            store.intents.insert(participant, intent);
        })
    }

    fn persisted<T>(
        &mut self,
        mutate: impl FnOnce(&mut ReferralStore) -> T,
    ) -> Result<T, ExecutionFailureKind> {
        let snapshot = self.store.clone();
        let value = mutate(&mut self.store);
        if let Err(error) = self.store.save(&self.store_path) {
            self.store = snapshot;
            return Err(ExecutionFailureKind::SequencerError(error));
        }
        Ok(value)
    }

    fn persist(&self) -> Result<(), ExecutionFailureKind> {
        self.wallet
            .store_persistent_data()
            .map_err(ExecutionFailureKind::SequencerError)
    }

    fn participant(&self, account: AccountId) -> Result<Participant, ExecutionFailureKind> {
        decode_participant(self.found(account)?.account, self.uplink_account())
    }

    fn own_private(&self, account: AccountId) -> Result<AccountIdentity, ExecutionFailureKind> {
        self.wallet
            .resolve_private_account(account)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)
    }

    fn found(&self, account: AccountId) -> Result<FoundPrivateAccount<'_>, ExecutionFailureKind> {
        self.wallet
            .storage()
            .key_chain()
            .private_account(account)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)
    }
}

fn decode_participant(
    account: &Account,
    uplink_account: AccountId,
) -> Result<Participant, ExecutionFailureKind> {
    let Some(State::Participant(participant)) = State::decode(account.data.shard(uplink_account))
    else {
        return Err(conflict("this participant is not registered yet"));
    };
    Ok(participant)
}

fn decode_registry(
    account: &Account,
    uplink_account: AccountId,
) -> Result<Registry, ExecutionFailureKind> {
    match State::decode(account.data.shard(uplink_account)) {
        None => Ok(Registry::default()),
        Some(State::Registry(registry)) => Ok(registry),
        Some(
            State::Participant(_)
            | State::Child { .. }
            | State::Credit { .. }
            | State::CashOut { .. }
            | State::Publication { .. },
        ) => Err(ExecutionFailureKind::AccountDataError(ORACLE_ACCOUNT_ID)),
    }
}

/// The earliest epoch the participant could still earn in: each child's first unsettled epoch,
/// each announced child's registration epoch, and each waiting credit's epoch. `None` if it has no
/// children and no notes.
fn earliest_claimable(claimant: &Participant, notes: &[(AccountId, State)]) -> Option<Epoch> {
    claimant
        .children
        .values()
        .map(|settled| first_unsettled(settled))
        .chain(notes.iter().map(|(_id, state)| match *state {
            State::Child { since, .. } => since,
            State::Credit { epoch, .. } => epoch,
            State::Registry(_)
            | State::Participant(_)
            | State::CashOut { .. }
            | State::Publication { .. } => Epoch::MAX,
        }))
        .min()
}

/// Plans the participant's claims over `published` epochs, oldest first: each epoch that would pay,
/// with the credits earned in it, its active set's size and what it pays. Announced children go
/// with the first epoch planned.
///
/// Simulates the claims with the program's own [`Participant::claim`], so each total is what the
/// program will compute.
fn plan_epochs(
    claimant: &Participant,
    notes: Vec<(AccountId, State)>,
    published: BTreeMap<Epoch, BTreeSet<NodeId>>,
) -> Vec<(ClaimedEpoch, usize, Points)> {
    // Announced children are adopted in the first epoch claimed, so simulate them adopted from the
    // start: an epoch before the first one claimed pays nothing either way.
    let (children, credits): (Vec<_>, Vec<_>) = notes
        .into_iter()
        .partition(|(_id, state)| matches!(state, State::Child { .. }));
    let mut simulated = claimant.clone();
    for (_id, child) in &children {
        if let State::Child { node, since, .. } = *child {
            simulated.adopt(node, since);
        }
    }

    let mut planned: Vec<(ClaimedEpoch, usize, Points)> = Vec::new();
    for (epoch, active) in published {
        if !active.contains(&claimant.node) {
            continue;
        }
        let digest = active_digest(&active);
        let (ids, states): (Vec<AccountId>, Vec<State>) = credits
            .iter()
            .filter(|(_id, state)| {
                matches!(*state, State::Credit { epoch: earned, active_digest: under, .. }
                    if (earned, under) == (epoch, digest))
            })
            .cloned()
            .unzip();
        let entries = active.len();
        let total = simulated.claim(&EpochClaim {
            epoch,
            active,
            notes: states,
            total: 0,
        });
        if total > 0 {
            planned.push((
                ClaimedEpoch {
                    epoch,
                    active_digest: digest,
                    notes: ids,
                },
                entries,
                total,
            ));
        }
    }
    if let Some((first, _entries, _total)) = planned.first_mut() {
        first
            .notes
            .splice(0..0, children.iter().map(|(id, _state)| *id));
    }
    planned
}

/// Whether an attempt sent at `sent_at_block` and not yet included counts as lost at `last_block`.
const fn is_lost_at(last_block: BlockId, sent_at_block: BlockId) -> bool {
    last_block.saturating_sub(sent_at_block) >= RESUBMIT_AFTER_BLOCKS
}

/// The first epoch not yet settled for a child, given its settled ranges. Epoch 0 is never
/// published, so it counts as settled.
fn first_unsettled(settled: &[(Epoch, Epoch)]) -> Epoch {
    let mut next: Epoch = 1;
    for &(first, last) in settled {
        if first > next {
            break;
        }
        next = next.max(last.saturating_add(1));
    }
    next
}

/// Splits a participant's planned epochs, in order, into claims of at most [`MAX_CLAIM_EPOCHS`]
/// epochs and [`MAX_CLAIM_ACTIVE_ENTRIES`] active-set entries. An epoch over the entry cap on its
/// own still gets a claim. Each planned epoch carries its active set's size and what it pays.
fn batch_claims(
    participant: AccountId,
    planned: Vec<(ClaimedEpoch, usize, Points)>,
) -> Result<Vec<(OperationKind, Points)>, ExecutionFailureKind> {
    let mut batches: Vec<(OperationKind, Points)> = Vec::new();
    let mut epochs = Vec::new();
    let (mut entries, mut total): (usize, Points) = (0, 0);
    for (claimed, epoch_entries, epoch_total) in planned {
        let full = epochs.len() >= MAX_CLAIM_EPOCHS
            || entries.saturating_add(epoch_entries) > MAX_CLAIM_ACTIVE_ENTRIES;
        if full && !epochs.is_empty() {
            batches.push((
                OperationKind::Claim {
                    participant,
                    epochs: std::mem::take(&mut epochs),
                },
                total,
            ));
            (entries, total) = (0, 0);
        }
        epochs.push(claimed);
        entries = entries.saturating_add(epoch_entries);
        total = total
            .checked_add(epoch_total)
            .ok_or_else(|| conflict("the claimable total overflows"))?;
    }
    if !epochs.is_empty() {
        batches.push((
            OperationKind::Claim {
                participant,
                epochs,
            },
            total,
        ));
    }
    Ok(batches)
}

fn is_superseded(
    recorded: &PendingOperation,
    registry: &Account,
) -> Result<bool, ExecutionFailureKind> {
    let registry = decode_registry(registry, recorded.uplink_account)?;
    Ok(match recorded.registry_guard {
        Some(RegistryGuard::Registers { node, epoch }) => {
            registry.registered_nodes.contains(&node) || registry.epoch != epoch
        }
        None => false,
    })
}

fn published(transaction: &IndexedTransaction, uplink_account: AccountId) -> Option<Publication> {
    let program = *uplink_account.value();
    let (epoch, active) = match transaction {
        IndexedTransaction::Public(public) => {
            if public.message.program_account_id.value != program {
                return None;
            }
            let Instruction::Publish { epoch, active } =
                borsh::from_slice(&public.message.instruction_data).ok()?
            else {
                return None;
            };
            (epoch, active)
        }
        IndexedTransaction::PrivacyPreserving(private) => private
            .message
            .public_actions
            .iter()
            .filter(|action| action.account_id.value == *ORACLE_ACCOUNT_ID.value())
            .flat_map(|action| &action.effects)
            .filter(|effect| effect.program_account_id.value == program)
            .find_map(|effect| {
                let Effect::Publish { epoch, active } = borsh::from_slice(&effect.data).ok()?
                else {
                    return None;
                };
                Some((epoch, active))
            })?,
    };
    Some(Publication {
        uplink_account,
        epoch,
        active,
    })
}

fn cash_out_transition(
    recorded: SubmissionStatus,
    receipt: &ShardData,
    outspent: bool,
) -> Option<SubmissionStatus> {
    let status = if matches!(State::decode(receipt), Some(State::CashOut { .. })) {
        SubmissionStatus::Settled
    } else if outspent || !receipt.is_empty() {
        SubmissionStatus::Rejected
    } else {
        SubmissionStatus::Pending
    };
    (status != recorded).then_some(status)
}

fn conflict(message: &str) -> ExecutionFailureKind {
    ExecutionFailureKind::TransactionBuildError(lee::error::LeeError::InvalidInput(
        message.to_owned(),
    ))
}

fn foreign_note(referrer: &Referrer) -> AccountIdentity {
    AccountIdentity::PrivateForeign {
        npk: referrer.npk,
        vpk: referrer.vpk.clone(),
        kind: PrivateAccountKind::Regular(random_identifier()),
    }
}

fn instruction_data(instruction: Instruction) -> InstructionData {
    Program::serialize_instruction(instruction).expect("Instruction should serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: NodeId = NodeId::new([5; 32]);

    fn indexed_id(account_id: AccountId) -> indexer_service_protocol::AccountId {
        indexer_service_protocol::AccountId {
            value: *account_id.value(),
        }
    }

    fn indexed_call(uplink_account: AccountId, instruction: &Instruction) -> IndexedTransaction {
        IndexedTransaction::Public(indexer_service_protocol::PublicTransaction {
            hash: indexer_service_protocol::HashType([0; 32]),
            message: indexer_service_protocol::PublicMessage {
                program_account_id: indexed_id(uplink_account),
                shard_selectors: Vec::new(),
                nonces: Vec::new(),
                instruction_data: borsh::to_vec(instruction).unwrap(),
                fee: None,
            },
            witness_set: indexer_service_protocol::WitnessSet {
                signatures_and_public_keys: Vec::new(),
                proof: None,
            },
        })
    }

    fn indexed_effect(uplink_account: AccountId, effect: &Effect) -> IndexedTransaction {
        IndexedTransaction::PrivacyPreserving(
            indexer_service_protocol::PrivacyPreservingTransaction {
                hash: indexer_service_protocol::HashType([0; 32]),
                message: indexer_service_protocol::PrivacyPreservingMessage {
                    public_actions: vec![indexer_service_protocol::PublicActionWithID {
                        account_id: indexed_id(ORACLE_ACCOUNT_ID),
                        effects: vec![indexer_service_protocol::DeferredPublicEffect {
                            program_account_id: indexed_id(uplink_account),
                            shard_program_account_id: indexed_id(uplink_account),
                            data: borsh::to_vec(effect).unwrap(),
                        }],
                    }],
                    nonces: Vec::new(),
                    private_actions: Vec::new(),
                    block_validity_window: indexer_service_protocol::ValidityWindow((None, None)),
                    timestamp_validity_window: indexer_service_protocol::ValidityWindow((
                        None, None,
                    )),
                },
                witness_set: indexer_service_protocol::WitnessSet {
                    signatures_and_public_keys: Vec::new(),
                    proof: None,
                },
            },
        )
    }

    #[test]
    fn publications_are_read_from_this_programs_history_by_epoch_and_digest() {
        let ours = AccountId::new([1; 32]);
        let other = AccountId::new([2; 32]);
        let first = BTreeSet::from([NodeId::new([7; 32])]);
        let corrected = BTreeSet::from([NodeId::new([8; 32])]);
        let history = [
            indexed_call(
                ours,
                &Instruction::Publish {
                    epoch: 1,
                    active: first.clone(),
                },
            ),
            indexed_call(
                other,
                &Instruction::Publish {
                    epoch: 1,
                    active: BTreeSet::new(),
                },
            ),
            indexed_call(
                ours,
                &Instruction::CashOut {
                    node: NodeId::new([7; 32]),
                    points: 1,
                    blinding_factor: [0; 32],
                },
            ),
            indexed_effect(
                ours,
                &Effect::CheckEpoch {
                    epoch: 1,
                    active_digest: active_digest(&first),
                },
            ),
            indexed_effect(
                ours,
                &Effect::Publish {
                    epoch: 1,
                    active: corrected.clone(),
                },
            ),
        ];
        let store = ReferralStore {
            publications: history
                .iter()
                .filter_map(|transaction| published(transaction, ours))
                .collect(),
            ..ReferralStore::default()
        };

        assert_eq!(store.publications.len(), 2);
        assert_eq!(
            store.publication(ours, 1, active_digest(&first)),
            Some(&first)
        );
        assert_eq!(
            store.publication(ours, 1, active_digest(&corrected)),
            Some(&corrected)
        );
        assert_eq!(store.publication(ours, 2, active_digest(&first)), None);
        assert_eq!(
            store.publication(other, 1, active_digest(&BTreeSet::new())),
            None
        );
    }

    #[test]
    fn reconciliation_reads_the_recorded_deployment() {
        let ours = AccountId::new([1; 32]);
        let other = AccountId::new([2; 32]);
        let node = NodeId::new([9; 32]);
        let registering = |epoch| PendingOperation {
            reference: [0; 32],
            uplink_account: ours,
            operation: OperationKind::Register {
                participant: AccountId::new([3; 32]),
            },
            hash: HashType([0; 32]),
            sent_at_block: 0,
            registry_guard: Some(RegistryGuard::Registers { node, epoch }),
            input_commitments: Vec::new(),
            status: SubmissionStatus::Pending,
        };
        let registry = |ours_epoch, ours_nodes: BTreeSet<NodeId>| {
            Account::default()
                .with_shard(
                    ours,
                    State::Registry(Registry {
                        epoch: ours_epoch,
                        registered_nodes: ours_nodes,
                        ..Registry::default()
                    })
                    .to_data(),
                )
                .with_shard(
                    other,
                    State::Registry(Registry {
                        epoch: 1,
                        ..Registry::default()
                    })
                    .to_data(),
                )
        };

        assert!(
            !is_superseded(&registering(1), &registry(1, BTreeSet::new())).unwrap(),
            "the registration's epoch is still current"
        );
        assert!(
            is_superseded(&registering(1), &registry(2, BTreeSet::new())).unwrap(),
            "our deployment has moved on, whatever another deployment holds"
        );
        assert!(
            is_superseded(&registering(1), &registry(1, BTreeSet::from([node]))).unwrap(),
            "the node is already registered"
        );
    }

    #[test]
    fn a_cash_out_settles_on_its_receipt_and_otherwise_follows_its_input() {
        let receipt = State::CashOut { points: 7 }.to_data();
        let note = State::Credit {
            recipient_node: NodeId::new([1; 32]),
            amount: 1,
            epoch: 1,
            active_digest: [0; 32],
        }
        .to_data();
        let empty = ShardData::empty();

        assert_eq!(
            cash_out_transition(SubmissionStatus::Pending, &receipt, false),
            Some(SubmissionStatus::Settled)
        );
        assert_eq!(
            cash_out_transition(SubmissionStatus::Rejected, &receipt, true),
            Some(SubmissionStatus::Settled),
            "another attempt at the same index created the receipt"
        );
        assert_eq!(
            cash_out_transition(SubmissionStatus::Pending, &note, false),
            Some(SubmissionStatus::Rejected)
        );
        assert_eq!(
            cash_out_transition(SubmissionStatus::Pending, &empty, true),
            Some(SubmissionStatus::Rejected)
        );
        assert_eq!(
            cash_out_transition(SubmissionStatus::Pending, &empty, false),
            None
        );
        assert_eq!(
            cash_out_transition(SubmissionStatus::Rejected, &empty, true),
            None
        );
    }

    #[test]
    fn a_participant_is_read_from_its_own_deployment() {
        let (ours, other) = (AccountId::new([1; 32]), AccountId::new([2; 32]));
        let (our_node, other_node) = (NodeId::new([5; 32]), NodeId::new([6; 32]));
        let account = Account::default()
            .with_shard(
                ours,
                State::Participant(Participant::new(our_node, None)).to_data(),
            )
            .with_shard(
                other,
                State::Participant(Participant::new(other_node, None)).to_data(),
            );

        assert_eq!(
            decode_participant(&account, other)
                .expect("the other deployment registered the participant")
                .node,
            other_node
        );
        assert!(
            decode_participant(&Account::default(), other).is_err(),
            "a deployment that never registered the participant holds no participant"
        );
    }

    fn planned(epoch: Epoch, entries: usize) -> (ClaimedEpoch, usize, Points) {
        (
            ClaimedEpoch {
                epoch,
                active_digest: [0; 32],
                notes: Vec::new(),
            },
            entries,
            1,
        )
    }

    fn batch_sizes(planned: Vec<(ClaimedEpoch, usize, Points)>) -> Vec<(usize, Points)> {
        batch_claims(AccountId::new([3; 32]), planned)
            .unwrap()
            .into_iter()
            .map(|(operation, total)| {
                let OperationKind::Claim { epochs, .. } = operation else {
                    panic!("batching makes claims")
                };
                (epochs.len(), total)
            })
            .collect()
    }

    #[test]
    fn the_first_unsettled_epoch_follows_the_ranges_from_the_first_published_one() {
        assert_eq!(first_unsettled(&[]), 1);
        assert_eq!(first_unsettled(&[(1, 2)]), 3);
        assert_eq!(first_unsettled(&[(0, 2)]), 3);
        assert_eq!(first_unsettled(&[(0, 2), (4, 6)]), 3);
        assert_eq!(first_unsettled(&[(2, 3)]), 1);
    }

    fn active(nodes: &[NodeId]) -> BTreeSet<NodeId> {
        nodes.iter().copied().collect()
    }

    #[test]
    fn the_planner_keeps_only_paying_epochs_and_adopts_announcements_in_the_first() {
        let a = NodeId::new([1; 32]);
        let third = active(&[ME, a]);
        let (announcement, credit) = (AccountId::new([11; 32]), AccountId::new([12; 32]));
        let notes = vec![
            (
                announcement,
                State::Child {
                    node: a,
                    referrer: ME,
                    since: 2,
                },
            ),
            (
                credit,
                State::Credit {
                    recipient_node: ME,
                    amount: 5,
                    epoch: 3,
                    active_digest: active_digest(&third),
                },
            ),
        ];
        let published = BTreeMap::from([
            // Before the child registered: nothing.
            (1, active(&[ME, a])),
            // The claimant was inactive: unclaimable.
            (2, active(&[a])),
            // The child and the credit.
            (3, third.clone()),
            // Nobody below the claimant was active.
            (4, active(&[ME])),
        ]);

        assert_eq!(
            plan_epochs(&Participant::new(ME, None), notes, published),
            vec![(
                ClaimedEpoch {
                    epoch: 3,
                    active_digest: active_digest(&third),
                    notes: vec![announcement, credit],
                },
                2,
                6,
            )]
        );
    }

    #[test]
    fn the_planner_fills_an_epoch_an_earlier_claim_skipped() {
        let a = NodeId::new([1; 32]);
        // Epoch 2 was claimed before epoch 1.
        let claimant = Participant {
            children: BTreeMap::from([(a, vec![(0, 0), (2, 2)])]),
            ..Participant::new(ME, None)
        };
        let published = (1..=3).map(|epoch| (epoch, active(&[ME, a]))).collect();

        let epochs: Vec<Epoch> = plan_epochs(&claimant, Vec::new(), published)
            .into_iter()
            .map(|(claimed, _entries, _total)| claimed.epoch)
            .collect();
        assert_eq!(epochs, vec![1, 3]);
    }

    #[test]
    fn the_earliest_claimable_epoch_is_the_oldest_unsettled_child_or_note() {
        let claimant = Participant::new(ME, None);
        assert_eq!(earliest_claimable(&claimant, &[]), None);

        let settled = Participant {
            children: BTreeMap::from([(NodeId::new([1; 32]), vec![(0, 4)])]),
            ..claimant
        };
        assert_eq!(earliest_claimable(&settled, &[]), Some(5));

        let credit = (
            AccountId::new([11; 32]),
            State::Credit {
                recipient_node: ME,
                amount: 1,
                epoch: 3,
                active_digest: [0; 32],
            },
        );
        assert_eq!(earliest_claimable(&settled, &[credit]), Some(3));

        let announcement = (
            AccountId::new([12; 32]),
            State::Child {
                node: NodeId::new([2; 32]),
                referrer: ME,
                since: 2,
            },
        );
        assert_eq!(earliest_claimable(&settled, &[announcement]), Some(2));
    }

    #[test]
    fn an_attempt_counts_as_lost_once_the_resubmit_window_passes() {
        let sent = 100;
        let due = sent + RESUBMIT_AFTER_BLOCKS;

        assert!(!is_lost_at(due - 1, sent));
        assert!(is_lost_at(due, sent));
        assert!(
            !is_lost_at(sent - 10, sent),
            "a height behind the attempt never counts it lost"
        );
    }

    #[test]
    fn claims_carry_at_most_the_epoch_cap() {
        let epochs = (1..=20).map(|epoch| planned(epoch, 1)).collect();

        assert_eq!(batch_sizes(epochs), vec![(16, 16), (4, 4)]);
    }

    #[test]
    fn claims_carry_at_most_the_active_entry_cap_but_always_one_epoch() {
        let epochs = vec![
            planned(1, 1_500),
            planned(2, 1_500),
            planned(3, 5_000),
            planned(4, 10),
        ];

        assert_eq!(batch_sizes(epochs), vec![(1, 1), (1, 1), (1, 1), (1, 1)]);
        assert_eq!(
            batch_sizes(vec![planned(1, 1_000), planned(2, 1_048)]),
            vec![(2, 2)]
        );
        assert!(batch_sizes(Vec::new()).is_empty());
    }

    fn keys(secret: u8, uplink_account: u8, participant: u8) -> ReceiptKeys {
        ReceiptKeys {
            uplink_account: AccountId::new([uplink_account; 32]),
            participant: AccountId::new([participant; 32]),
            node: NodeId::new([7; 32]),
            receipt_secret: [secret; 32],
        }
    }

    #[test]
    fn an_opening_is_the_core_blinding_factor_and_its_receipt() {
        let opening = keys(1, 2, 3).opening(4);
        let factor = blinding_factor(
            &[1; 32],
            AccountId::new([2; 32]),
            AccountId::new([3; 32]),
            4,
        );

        assert_eq!(opening.blinding_factor, factor);
        assert_eq!(opening.node, NodeId::new([7; 32]));
        assert_eq!(
            opening.account_id,
            cash_out_receipt(AccountId::new([2; 32]), NodeId::new([7; 32]), factor)
        );
    }

    #[test]
    fn openings_differ_per_secret_deployment_participant_and_index() {
        let opening = keys(1, 2, 3).opening(0).account_id;

        assert_ne!(keys(1, 2, 3).opening(1).account_id, opening);
        assert_ne!(keys(4, 2, 3).opening(0).account_id, opening);
        assert_ne!(keys(1, 5, 3).opening(0).account_id, opening);
        assert_ne!(keys(1, 2, 6).opening(0).account_id, opening);
    }
}
