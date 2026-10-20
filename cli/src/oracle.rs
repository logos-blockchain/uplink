//! The oracle: publishes the blend network's membership in each finalized chain epoch.

use core::time::Duration;
use std::time::Instant;

use anyhow::Result;
use referral_core::Epoch;
use uplink_wallet::{BlendNode, Referral};

/// How long a sent publication may stay unincluded before the oracle sends it again. A second
/// publication of the same epoch is rejected on chain, so resending never publishes twice.
const RESEND_AFTER: Duration = Duration::from_mins(1);

/// Publishes each epoch once the node finalizes it, checking every `interval`. With `once`, checks
/// a single time and returns any error instead of logging it.
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

/// Publishes the node's finalized epoch if it is after the last published one and was not just
/// sent. Returns what it published.
async fn step(
    facade: &mut Referral<'_>,
    node: &BlendNode,
    sent: &mut Option<(Epoch, Instant)>,
) -> Result<Option<String>> {
    let Some((epoch, active)) = node.finalized_membership().await? else {
        return Ok(None);
    };
    if epoch <= facade.registry().await?.epoch {
        return Ok(None);
    }
    if sent.is_some_and(|(pending, at)| pending == epoch && at.elapsed() < RESEND_AFTER) {
        return Ok(None);
    }
    let members = active.len();
    let hash = facade.publish(epoch, active).await?;
    *sent = Some((epoch, Instant::now()));
    Ok(Some(format!(
        "Published epoch {epoch} with {members} blend members in {hash}"
    )))
}
