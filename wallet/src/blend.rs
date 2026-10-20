//! Blend network membership, read from a Logos blockchain node for the oracle to publish.

use std::collections::{BTreeSet, HashMap};

use anyhow::{Context as _, Result};
use lb_common_http_client::CommonHttpClient;
use lb_core::sdp::{Declaration, DeclarationId, ServiceType};
use lb_http_api_common::paths::MANTLE_SDP_SNAPSHOT;
use referral_core::NodeId;
use url::Url;

/// An epoch of the chain, as its slots number it. The oracle publishes once per chain epoch, but
/// numbers its publications as Uplink epochs of its own.
pub type ChainEpoch = u64;

/// A Logos blockchain node, read over its HTTP API.
pub struct BlendNode {
    client: CommonHttpClient,
    base_url: Url,
}

impl BlendNode {
    #[must_use]
    pub fn new(base_url: Url) -> Self {
        Self {
            client: CommonHttpClient::new(None),
            base_url,
        }
    }

    /// The blend network's members in the node's current chain epoch, once that epoch is final:
    /// the providers of the epoch's active Blend declarations, each node named by its Ed25519
    /// provider key. `None` until the node's last irreversible block is in the tip's epoch.
    ///
    /// The ledger snapshots an epoch's active declarations when the epoch begins and keeps them
    /// for the whole epoch, so once the last irreversible block is inside it, no reorg can change
    /// them. The snapshot is read at the tip, so the tip is read again after it: if the tip has
    /// meanwhile moved on to the next epoch, the read may be of that epoch, and it is discarded.
    pub async fn finalized_membership(&self) -> Result<Option<(ChainEpoch, BTreeSet<NodeId>)>> {
        let slots_per_epoch = self
            .client
            .time_info(self.base_url.clone())
            .await
            .context("Failed to read the node's time info")?
            .slots_per_epoch;
        let before = self.tip_and_lib_slots().await?;
        let Some(epoch) = finalized_epoch(slots_per_epoch, before)? else {
            return Ok(None);
        };

        let snapshot: HashMap<DeclarationId, Declaration> = self
            .client
            .get::<(), _>(
                self.base_url
                    .join(MANTLE_SDP_SNAPSHOT.trim_start_matches('/'))?,
                None,
            )
            .await
            .context("Failed to read the node's SDP snapshot")?;

        let (tip_after, _lib) = self.tip_and_lib_slots().await?;
        if epoch_of(slots_per_epoch, tip_after)? != epoch {
            return Ok(None);
        }
        Ok(Some((epoch, blend_members(snapshot.values()))))
    }

    async fn tip_and_lib_slots(&self) -> Result<(u64, u64)> {
        let info = self
            .client
            .consensus_info(self.base_url.clone())
            .await
            .context("Failed to read the node's consensus info")?
            .cryptarchia_info;
        Ok((u64::from(info.slot), u64::from(info.lib_slot)))
    }
}

/// The providers of the Blend declarations among `declarations`.
fn blend_members<'declaration>(
    declarations: impl IntoIterator<Item = &'declaration Declaration>,
) -> BTreeSet<NodeId> {
    declarations
        .into_iter()
        .filter(|declaration| declaration.service_type == ServiceType::BlendNetwork)
        .map(|declaration| NodeId::new(*declaration.provider_id.as_ref()))
        .collect()
}

/// The tip's epoch, if the last irreversible block is in it too.
fn finalized_epoch(slots_per_epoch: u64, (tip, lib): (u64, u64)) -> Result<Option<ChainEpoch>> {
    let epoch = epoch_of(slots_per_epoch, tip)?;
    Ok((epoch_of(slots_per_epoch, lib)? == epoch).then_some(epoch))
}

fn epoch_of(slots_per_epoch: u64, slot: u64) -> Result<ChainEpoch> {
    slot.checked_div(slots_per_epoch)
        .context("the node reports epochs of no slots")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_epoch_is_final_once_the_last_irreversible_block_enters_it() {
        assert_eq!(finalized_epoch(100, (250, 199)).unwrap(), None);
        assert_eq!(finalized_epoch(100, (250, 200)).unwrap(), Some(2));
        assert_eq!(finalized_epoch(100, (299, 250)).unwrap(), Some(2));
    }

    #[test]
    fn an_epoch_is_not_final_while_the_tip_is_past_it() {
        // The tip has entered epoch 3 but the last irreversible block is still in epoch 2.
        assert_eq!(finalized_epoch(100, (300, 299)).unwrap(), None);
    }

    #[test]
    fn epochs_of_no_slots_are_rejected() {
        assert!(finalized_epoch(0, (1, 1)).is_err());
    }
}
