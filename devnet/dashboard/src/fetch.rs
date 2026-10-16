//! Reads everything the dashboard shows, from the chains themselves.
//!
//! Each refresh reads the blockchain nodes' and the indexer's current state anew. The one thing
//! kept between refreshes is the uplink activity decoded from LEZ blocks already read: a
//! finalized block never changes, so only the blocks after it are read again.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use indexer_service_protocol::{
    AccountId as IndexedAccountId, ProgramShardSelector, Transaction as IndexedTransaction,
};
use indexer_service_rpc::RpcClient as _;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use lb_common_http_client::CommonHttpClient;
use lb_core::sdp::{Declaration, DeclarationId, ServiceType};
use lb_http_api_common::paths::{MANTLE_SDP_DECLARATIONS, MANTLE_SDP_SNAPSHOT, NETWORK_INFO};
use lee::AccountId;
use referral_core::{
    Effect, Epoch, Instruction, NodeId, ORACLE_ACCOUNT_ID, Participant, Points, Registry, State,
};
use url::Url;
use wallet::WalletCore;

const BLOCK_PAGE: u64 = 100;

pub struct Sources {
    pub nodes: Vec<(String, Url)>,
    pub indexer: Url,
    pub program: Option<AccountId>,
    pub wallets: Vec<(String, PathBuf)>,
}

pub struct Snapshot {
    pub nodes: Vec<(String, Result<NodeInfo, String>)>,
    pub blend: Result<Blend, String>,
    pub lez: Result<Lez, String>,
    pub participants: Vec<(String, Result<Option<Participant>, String>)>,
}

pub struct NodeInfo {
    pub state: String,
    pub height: u64,
    pub tip_slot: u64,
    pub lib_slot: u64,
    pub slots_per_epoch: u64,
    pub peers: Option<u64>,
}

impl NodeInfo {
    pub const fn epoch(&self, slot: u64) -> u64 {
        match slot.checked_div(self.slots_per_epoch) {
            Some(epoch) => epoch,
            None => 0,
        }
    }
}

/// The blend network as one node sees it: every declaration, and which are in the current
/// epoch's snapshot.
pub struct Blend {
    pub source: String,
    pub declarations: Vec<BlendDeclaration>,
}

pub struct BlendDeclaration {
    pub provider: NodeId,
    pub locators: String,
    pub created: u32,
    pub active: u32,
    pub withdraw_at: Option<u32>,
    pub in_snapshot: bool,
}

pub struct Lez {
    pub indexer_state: String,
    pub indexed_block: Option<u64>,
    pub uplink: Option<Uplink>,
}

pub struct Uplink {
    pub registry: Option<Registry>,
    pub oracle_balance: Option<u128>,
    pub publications: BTreeMap<Epoch, BTreeSet<NodeId>>,
    pub events: Vec<(u64, Activity)>,
}

/// Uplink activity a LEZ block shows publicly.
#[derive(Clone)]
pub enum Activity {
    Publish {
        epoch: Epoch,
        active: BTreeSet<NodeId>,
    },
    Register {
        node: NodeId,
        epoch: Epoch,
    },
    Claim {
        epochs: Vec<Epoch>,
    },
    CashOut {
        receipt: IndexedAccountId,
        points: Points,
    },
}

pub struct Fetcher {
    sources: Sources,
    http: CommonHttpClient,
    indexer: HttpClient,
    /// Uplink activity in each LEZ block read so far, by block id.
    blocks: BTreeMap<u64, Vec<Activity>>,
}

impl Fetcher {
    pub fn new(sources: Sources) -> Result<Self> {
        let indexer = HttpClientBuilder::default()
            .build(sources.indexer.as_str())
            .context("Failed to create the indexer client")?;
        Ok(Self {
            sources,
            http: CommonHttpClient::new(None),
            indexer,
            blocks: BTreeMap::new(),
        })
    }

    pub async fn fetch(&mut self) -> Snapshot {
        let mut nodes = Vec::new();
        for (name, url) in &self.sources.nodes {
            nodes.push((
                name.clone(),
                self.node(url).await.map_err(|error| show(&error)),
            ));
        }
        let blend = self.blend().await.map_err(|error| show(&error));
        let lez = self.lez().await.map_err(|error| show(&error));
        let participants = self
            .sources
            .wallets
            .iter()
            .map(|(name, dir)| {
                (
                    name.clone(),
                    self.participant(dir).map_err(|error| show(&error)),
                )
            })
            .collect();
        Snapshot {
            nodes,
            blend,
            lez,
            participants,
        }
    }

    async fn node(&self, url: &Url) -> Result<NodeInfo> {
        let time = self.http.time_info(url.clone()).await?;
        let info = self
            .http
            .consensus_info(url.clone())
            .await?
            .cryptarchia_info;
        let network: serde_json::Value = self
            .http
            .get::<(), _>(url.join(NETWORK_INFO.trim_start_matches('/'))?, None)
            .await?;
        Ok(NodeInfo {
            state: format!("{:?}", info.state),
            height: info.height,
            tip_slot: u64::from(info.slot),
            lib_slot: u64::from(info.lib_slot),
            slots_per_epoch: time.slots_per_epoch,
            peers: network.get("n_peers").and_then(serde_json::Value::as_u64),
        })
    }

    /// The declarations of the first node that answers.
    async fn blend(&self) -> Result<Blend> {
        let mut last_error = anyhow::anyhow!("no blockchain nodes are configured");
        for (name, url) in &self.sources.nodes {
            match self.declarations(url).await {
                Ok(declarations) => {
                    return Ok(Blend {
                        source: name.clone(),
                        declarations,
                    });
                }
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    async fn declarations(&self, url: &Url) -> Result<Vec<BlendDeclaration>> {
        let all: HashMap<DeclarationId, Declaration> = self
            .http
            .get::<(), _>(
                url.join(MANTLE_SDP_DECLARATIONS.trim_start_matches('/'))?,
                None,
            )
            .await?;
        let snapshot: HashMap<DeclarationId, Declaration> = self
            .http
            .get::<(), _>(url.join(MANTLE_SDP_SNAPSHOT.trim_start_matches('/'))?, None)
            .await?;
        let mut declarations: Vec<BlendDeclaration> = all
            .iter()
            .filter(|(_id, declaration)| declaration.service_type == ServiceType::BlendNetwork)
            .map(|(id, declaration)| BlendDeclaration {
                provider: NodeId::new(*declaration.provider_id.as_ref()),
                locators: declaration
                    .locators
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" "),
                created: declaration.created.into_inner(),
                active: declaration.active.into_inner(),
                withdraw_at: declaration.withdraw_at.map(u32::from),
                in_snapshot: snapshot.contains_key(id),
            })
            .collect();
        declarations.sort_by_key(|declaration| (declaration.created, declaration.provider));
        Ok(declarations)
    }

    async fn lez(&mut self) -> Result<Lez> {
        let status = self.indexer.get_status().await?;
        let uplink = match self.sources.program {
            Some(program) => Some(self.uplink(program, status.indexed_block_id).await?),
            None => None,
        };
        Ok(Lez {
            indexer_state: format!("{:?}", status.state),
            indexed_block: status.indexed_block_id,
            uplink,
        })
    }

    async fn uplink(&mut self, program: AccountId, indexed: Option<u64>) -> Result<Uplink> {
        let program_id = indexed_id(program);
        let registry = self
            .indexer
            .get_account_view(ProgramShardSelector {
                account_id: indexed_id(ORACLE_ACCOUNT_ID),
                program_account_id: program_id,
            })
            .await?
            .data
            .shards
            .get(&program_id)
            .and_then(|shard| borsh::from_slice::<State>(&shard.0).ok())
            .and_then(|state| match state {
                State::Registry(registry) => Some(registry),
                State::Participant(_)
                | State::Child { .. }
                | State::Credit { .. }
                | State::CashOut { .. }
                | State::Publication { .. } => None,
            });
        let oracle_balance = self
            .indexer
            .get_account_summary(indexed_id(ORACLE_ACCOUNT_ID))
            .await?
            .balance;

        self.read_blocks(&program_id, indexed).await?;
        let mut publications = BTreeMap::new();
        let mut events = Vec::new();
        for (block, activities) in &self.blocks {
            for activity in activities {
                if let Activity::Publish { epoch, active } = activity {
                    publications.insert(*epoch, active.clone());
                }
                events.push((*block, activity.clone()));
            }
        }
        Ok(Uplink {
            registry,
            oracle_balance,
            publications,
            events,
        })
    }

    /// Reads the blocks after the last one read, up to `indexed`.
    async fn read_blocks(
        &mut self,
        program: &IndexedAccountId,
        indexed: Option<u64>,
    ) -> Result<()> {
        let Some(indexed) = indexed else {
            return Ok(());
        };
        // An indexer behind what was read has started over on a reset chain.
        if self
            .blocks
            .last_key_value()
            .is_some_and(|(last, _)| *last > indexed)
        {
            self.blocks.clear();
        }
        let known = self.blocks.last_key_value().map(|(last, _)| *last);
        let mut before = Some(indexed.saturating_add(1));
        loop {
            let page = self.indexer.get_blocks(before, BLOCK_PAGE).await?;
            let Some(lowest) = page.iter().map(|block| block.header.block_id).min() else {
                break;
            };
            for block in &page {
                let id = block.header.block_id;
                if known.is_some_and(|known| id <= known) {
                    continue;
                }
                let activities = block
                    .body
                    .transactions
                    .iter()
                    .flat_map(|transaction| activity(transaction, program))
                    .collect();
                self.blocks.insert(id, activities);
            }
            if known.is_some_and(|known| lowest <= known.saturating_add(1))
                || u64::try_from(page.len()).is_ok_and(|len| len < BLOCK_PAGE)
            {
                break;
            }
            before = Some(lowest);
        }
        Ok(())
    }

    /// The participant in the wallet at `dir`, as of the wallet's last sync.
    fn participant(&self, dir: &Path) -> Result<Option<Participant>> {
        let Some(program) = self.sources.program else {
            return Ok(None);
        };
        let Ok(id) = fs::read_to_string(dir.join("participant")) else {
            return Ok(None);
        };
        let id: AccountId = id.trim().parse()?;
        let wallet = WalletCore::new_update_chain(
            dir.join("wallet_config.json"),
            dir.join("storage.json"),
            None,
        )?;
        let Some(account) = wallet.private_account_state(id) else {
            return Ok(None);
        };
        match State::decode(account.data.shard(program)) {
            Some(State::Participant(participant)) => Ok(Some(participant)),
            _ => Ok(None),
        }
    }
}

/// The uplink activity one LEZ transaction shows publicly.
fn activity(transaction: &IndexedTransaction, program: &IndexedAccountId) -> Vec<Activity> {
    match transaction {
        IndexedTransaction::Public(public) => {
            if public.message.program_account_id != *program {
                return Vec::new();
            }
            match borsh::from_slice(&public.message.instruction_data) {
                Ok(Instruction::Publish { epoch, active }) => {
                    vec![Activity::Publish { epoch, active }]
                }
                _ => Vec::new(),
            }
        }
        IndexedTransaction::PrivacyPreserving(private) => {
            let mut activities = Vec::new();
            let mut claimed = Vec::new();
            for action in &private.message.public_actions {
                for effect in &action.effects {
                    if effect.program_account_id != *program {
                        continue;
                    }
                    match borsh::from_slice(&effect.data) {
                        Ok(Effect::Register { node, epoch, .. }) => {
                            activities.push(Activity::Register { node, epoch });
                        }
                        Ok(Effect::CheckEpoch { epoch, .. }) => claimed.push(epoch),
                        Ok(Effect::Create(State::CashOut { points })) => {
                            activities.push(Activity::CashOut {
                                receipt: action.account_id,
                                points,
                            });
                        }
                        _ => {}
                    }
                }
            }
            if !claimed.is_empty() {
                activities.push(Activity::Claim { epochs: claimed });
            }
            activities
        }
    }
}

const fn indexed_id(account: AccountId) -> IndexedAccountId {
    IndexedAccountId {
        value: *account.value(),
    }
}

fn show(error: &anyhow::Error) -> String {
    format!("{error:#}")
}
