//! The oracle: publishes the blend network's membership in each finalized chain epoch, as the next
//! Uplink epoch.

use core::time::Duration;
use std::time::Instant;

use anyhow::{Context as _, Result};
use referral_core::Epoch;
use uplink_wallet::{BlendNode, Referral, blend::ChainEpoch, store::OraclePublication};

/// How long a sent publication may stay unincluded before the oracle sends it again. A second
/// publication of the same epoch is rejected on chain, so resending never publishes twice.
const RESEND_AFTER: Duration = Duration::from_mins(1);

/// Publishes each chain epoch once the node finalizes it, checking every `interval`. With `once`,
/// checks a single time and returns any error instead of logging it.
#[expect(
    clippy::print_stderr,
    reason = "A long-running oracle logs the failures it retries past"
)]
pub async fn run(
    facade: &mut Referral<'_>,
    node: &BlendNode,
    interval: Duration,
    once: bool,
) -> Result<()> {
    let mut sent = None;
    loop {
        match step(facade, node, &mut sent).await {
            Ok(Some(report)) => println!("{report}"),
            Ok(None) if once => println!("Nothing to publish"),
            Ok(None) => {}
            Err(error) if once => return Err(error),
            Err(error) => eprintln!("oracle: {error:#}"),
        }
        if once {
            return Ok(());
        }
        tokio::time::sleep(interval).await;
    }
}

/// Publishes the node's finalized chain epoch as the next epoch, unless it was already published
/// or was just sent. Returns what it published.
async fn step(
    facade: &mut Referral<'_>,
    node: &BlendNode,
    sent: &mut Option<(Epoch, Instant)>,
) -> Result<Option<String>> {
    let Some((chain_epoch, active)) = node.finalized_membership().await? else {
        return Ok(None);
    };
    let published = facade.registry().await?.epoch;
    let Some(epoch) = next_publication(facade.oracle_publication(), chain_epoch, published)? else {
        return Ok(None);
    };
    if sent.is_some_and(|(pending, at)| pending == epoch && at.elapsed() < RESEND_AFTER) {
        return Ok(None);
    }
    let members = active.len();
    let hash = facade
        .publish_chain_epoch(chain_epoch, epoch, active)
        .await?;
    *sent = Some((epoch, Instant::now()));
    Ok(Some(format!(
        "Published chain epoch {chain_epoch} as epoch {epoch} with {members} blend members in {hash}"
    )))
}

/// The epoch to publish `chain_epoch`'s membership as, given the oracle's last publication and the
/// last `published` epoch, or `None` if there is nothing to publish.
///
/// Each chain epoch is published at most once, as the epoch after the last published one. A
/// recorded publication that is not yet included is sent again, and one that never was is
/// replaced by a later chain epoch.
fn next_publication(
    last: Option<OraclePublication>,
    chain_epoch: ChainEpoch,
    published: Epoch,
) -> Result<Option<Epoch>> {
    if let Some(last) = last {
        let done = last.chain_epoch == chain_epoch && last.epoch <= published;
        if last.chain_epoch > chain_epoch || done {
            return Ok(None);
        }
    }
    published
        .checked_add(1)
        .map(Some)
        .context("every epoch has been published")
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn record(chain_epoch: ChainEpoch, epoch: Epoch) -> OraclePublication {
        OraclePublication { chain_epoch, epoch }
    }

    #[test]
    fn the_first_chain_epoch_is_published_as_the_next_epoch() {
        assert_eq!(next_publication(None, 40, 0).unwrap(), Some(1));
        // A wallet that never published continues from whatever is on chain.
        assert_eq!(next_publication(None, 40, 6).unwrap(), Some(7));
    }

    #[test]
    fn a_published_chain_epoch_is_not_published_again() {
        assert_eq!(next_publication(Some(record(40, 7)), 40, 7).unwrap(), None);
        // Even when another publisher has since moved the registry on.
        assert_eq!(next_publication(Some(record(40, 7)), 40, 8).unwrap(), None);
    }

    #[test]
    fn an_unincluded_publication_is_sent_again_as_the_same_epoch() {
        assert_eq!(
            next_publication(Some(record(40, 7)), 40, 6).unwrap(),
            Some(7)
        );
    }

    #[test]
    fn the_next_chain_epoch_is_the_next_epoch_however_many_were_missed() {
        assert_eq!(
            next_publication(Some(record(40, 7)), 41, 7).unwrap(),
            Some(8)
        );
        assert_eq!(
            next_publication(Some(record(40, 7)), 55, 7).unwrap(),
            Some(8)
        );
        // A publication that was never included is replaced by the later chain epoch.
        assert_eq!(
            next_publication(Some(record(40, 7)), 41, 6).unwrap(),
            Some(7)
        );
    }

    #[test]
    fn an_earlier_chain_epoch_is_never_published() {
        // A node that is behind the one the oracle last read.
        assert_eq!(next_publication(Some(record(40, 7)), 39, 7).unwrap(), None);
        assert_eq!(next_publication(Some(record(40, 7)), 39, 6).unwrap(), None);
    }
}
