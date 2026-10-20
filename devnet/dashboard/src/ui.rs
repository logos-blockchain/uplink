//! Draws a snapshot.

use std::collections::{BTreeSet, HashMap};

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize as _},
    text::{Line, Span},
    widgets::{Block, Cell, Paragraph, Row, Table, Wrap},
};
use referral_core::{Epoch, NodeId};

use crate::fetch::{Activity, Blend, Lez, Snapshot};

/// Names for nodes, by their key.
pub type Labels = HashMap<NodeId, String>;

pub fn draw(frame: &mut Frame<'_>, snapshot: Option<&Snapshot>, labels: &Labels, age: u64) {
    let [title, top, middle, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(8),
        Constraint::Fill(1),
        Constraint::Fill(1),
    ])
    .areas(frame.area());

    let Some(snapshot) = snapshot else {
        frame.render_widget(Paragraph::new("Reading the devnet..."), title);
        return;
    };
    let chain_epoch = snapshot
        .nodes
        .iter()
        .find_map(|(_name, node)| node.as_ref().ok())
        .map(|node| node.epoch(node.tip_slot));
    let lez_block = snapshot.lez.as_ref().ok().and_then(|lez| lez.indexed_block);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::from(" uplink devnet ").bold().reversed(),
            Span::from(format!(
                "  chain epoch {}  ·  LEZ block {}  ·  read {age}s ago  ·  q to quit",
                show_option(chain_epoch),
                show_option(lez_block)
            )),
        ])),
        title,
    );

    let [nodes, blend] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(top);
    draw_nodes(frame, nodes, snapshot);
    draw_blend(frame, blend, &snapshot.blend, labels);

    let [registry, publications] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(middle);
    draw_registry(frame, registry, &snapshot.lez, labels);
    draw_publications(frame, publications, snapshot, labels);

    let [participants, events] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(bottom);
    draw_participants(frame, participants, snapshot, labels);
    draw_events(frame, events, &snapshot.lez, labels);
}

fn draw_nodes(frame: &mut Frame<'_>, area: Rect, snapshot: &Snapshot) {
    let rows = snapshot.nodes.iter().map(|(name, node)| match node {
        Ok(node) => Row::new(vec![
            Cell::from(name.clone()),
            Cell::from(node.state.clone()),
            Cell::from(node.height.to_string()),
            Cell::from(format!(
                "{} (e{})",
                node.tip_slot,
                node.epoch(node.tip_slot)
            )),
            Cell::from(format!(
                "{} (e{})",
                node.lib_slot,
                node.epoch(node.lib_slot)
            )),
            Cell::from(show_option(node.peers)),
        ]),
        Err(error) => Row::new(vec![
            Cell::from(name.clone()),
            Cell::from(error.clone()).red(),
        ]),
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(13),
            Constraint::Length(7),
            Constraint::Length(13),
            Constraint::Length(13),
            Constraint::Length(5),
        ],
    )
    .header(header(&[
        "node", "state", "height", "tip slot", "LIB slot", "peers",
    ]))
    .block(Block::bordered().title(" Blockchain nodes "));
    frame.render_widget(table, area);
}

fn draw_blend(frame: &mut Frame<'_>, area: Rect, blend: &Result<Blend, String>, labels: &Labels) {
    let block = Block::bordered().title(" Blend declarations (SDP) ");
    let blend = match blend {
        Ok(blend) => blend,
        Err(error) => return frame.render_widget(error_text(error).block(block), area),
    };
    if blend.declarations.is_empty() {
        return frame.render_widget(
            Paragraph::new("No node has declared itself a blend node yet.").block(block),
            area,
        );
    }
    let rows = blend.declarations.iter().map(|declaration| {
        let member = if declaration.in_snapshot {
            Cell::from("member").green()
        } else {
            Cell::from("pending").yellow()
        };
        Row::new(vec![
            Cell::from(label(labels, &declaration.provider)),
            member,
            Cell::from(declaration.created.to_string()),
            Cell::from(declaration.active.to_string()),
            Cell::from(show_option(declaration.withdraw_at)),
            Cell::from(declaration.locators.clone()),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Fill(1),
        ],
    )
    .header(header(&[
        "provider", "now", "created", "active", "withdraw", "locator",
    ]))
    .block(block.title_bottom(format!(" as {} sees it ", blend.source)));
    frame.render_widget(table, area);
}

fn draw_registry(frame: &mut Frame<'_>, area: Rect, lez: &Result<Lez, String>, labels: &Labels) {
    let block = Block::bordered().title(" Uplink registry (LEZ) ");
    let lez = match lez {
        Ok(lez) => lez,
        Err(error) => return frame.render_widget(error_text(error).block(block), area),
    };
    let mut lines = vec![Line::from(format!(
        "indexer {} at block {}",
        lez.indexer_state,
        show_option(lez.indexed_block)
    ))];
    match &lez.uplink {
        None => lines.push(Line::from(
            "No program given: pass --program to see uplink.",
        )),
        Some(uplink) => {
            lines.push(Line::from(format!(
                "oracle balance {}",
                show_option(uplink.oracle_balance)
            )));
            match &uplink.registry {
                None => lines.push(Line::from("Registry: nothing registered or published yet.")),
                Some(registry) => {
                    lines.push(Line::from(format!(
                        "last published epoch {}",
                        registry.epoch
                    )));
                    lines.push(Line::from(format!(
                        "registered  {}",
                        labelled(labels, &registry.registered_nodes)
                    )));
                    lines.push(Line::from(format!(
                        "active      {}",
                        labelled(labels, &registry.active_nodes)
                    )));
                }
            }
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

/// Blend membership by epoch: each epoch the oracle published, and the live snapshot of the chain's
/// current epoch, which is numbered apart from the published ones.
fn draw_publications(frame: &mut Frame<'_>, area: Rect, snapshot: &Snapshot, labels: &Labels) {
    let block = Block::bordered().title(" Blend membership by epoch ");
    let mut rows = Vec::new();
    if let Ok(blend) = &snapshot.blend {
        let live: BTreeSet<NodeId> = blend
            .declarations
            .iter()
            .filter(|declaration| declaration.in_snapshot)
            .map(|declaration| declaration.provider)
            .collect();
        let epoch = snapshot
            .nodes
            .iter()
            .find_map(|(_name, node)| node.as_ref().ok())
            .map(|node| node.epoch(node.tip_slot));
        rows.push(
            Row::new(vec![
                Cell::from(format!("chain {} live", show_option(epoch))),
                Cell::from(labelled(labels, &live)),
            ])
            .style(Style::new().fg(Color::Cyan)),
        );
    }
    if let Ok(Lez {
        uplink: Some(uplink),
        ..
    }) = &snapshot.lez
    {
        for (epoch, active) in uplink.publications.iter().rev() {
            rows.push(Row::new(vec![
                Cell::from(format!("{epoch} published")),
                Cell::from(labelled(labels, active)),
            ]));
        }
    }
    let table = Table::new(rows, [Constraint::Length(18), Constraint::Fill(1)])
        .header(header(&["epoch", "members"]))
        .block(block);
    frame.render_widget(table, area);
}

fn draw_participants(frame: &mut Frame<'_>, area: Rect, snapshot: &Snapshot, labels: &Labels) {
    let block =
        Block::bordered().title(" Participants (private; each wallet's view as of its last sync) ");
    let rows = snapshot
        .participants
        .iter()
        .map(|(name, participant)| match participant {
            Ok(Some(participant)) => Row::new(vec![
                Cell::from(name.clone()),
                Cell::from(label(labels, &participant.node)),
                Cell::from(
                    participant
                        .referrer_node()
                        .map_or_else(|| "-".to_owned(), |node| label(labels, &node)),
                ),
                Cell::from(participant.reward_balance.to_string()),
                Cell::from(
                    participant
                        .children
                        .iter()
                        .map(|(child, settled)| {
                            format!("{}{}", label(labels, child), ranges(settled))
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
            ]),
            Ok(None) => Row::new(vec![Cell::from(name.clone()), Cell::from("not registered")]),
            Err(error) => Row::new(vec![
                Cell::from(name.clone()),
                Cell::from(error.clone()).red(),
            ]),
        });
    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Fill(1),
        ],
    )
    .header(header(&[
        "wallet",
        "node",
        "referrer",
        "points",
        "children (settled epochs)",
    ]))
    .block(block);
    frame.render_widget(table, area);
}

fn draw_events(frame: &mut Frame<'_>, area: Rect, lez: &Result<Lez, String>, labels: &Labels) {
    let block = Block::bordered().title(" Uplink activity on LEZ, newest first ");
    let Ok(Lez {
        uplink: Some(uplink),
        ..
    }) = lez
    else {
        return frame.render_widget(block, area);
    };
    let rows = uplink.events.iter().rev().map(|(height, activity)| {
        let text = match activity {
            Activity::Publish { epoch, active } => {
                format!(
                    "oracle published epoch {epoch}: {}",
                    labelled(labels, active)
                )
            }
            Activity::Register { node, epoch } => {
                format!("{} registered in epoch {epoch}", label(labels, node))
            }
            Activity::Claim { epochs } => format!(
                "a participant claimed epoch{} {}",
                if epochs.len() == 1 { "" } else { "s" },
                epochs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Activity::CashOut { receipt, points } => {
                format!("{points} points cashed out to receipt {receipt}")
            }
        };
        Row::new(vec![Cell::from(height.to_string()), Cell::from(text)])
    });
    let table = Table::new(rows, [Constraint::Length(7), Constraint::Fill(1)])
        .header(header(&["block", "event"]))
        .block(block);
    frame.render_widget(table, area);
}

fn header(titles: &[&str]) -> Row<'static> {
    Row::new(titles.iter().map(|title| Cell::from((*title).to_owned())))
        .style(Style::new().add_modifier(Modifier::BOLD))
}

fn error_text(error: &str) -> Paragraph<'static> {
    Paragraph::new(error.to_owned())
        .red()
        .wrap(Wrap { trim: true })
}

fn label(labels: &Labels, node: &NodeId) -> String {
    labels
        .get(node)
        .cloned()
        .unwrap_or_else(|| hex::encode(&node.to_bytes()[..4]))
}

fn labelled(labels: &Labels, nodes: &BTreeSet<NodeId>) -> String {
    if nodes.is_empty() {
        return "none".to_owned();
    }
    let mut names: Vec<String> = nodes.iter().map(|node| label(labels, node)).collect();
    names.sort();
    names.join(" ")
}

fn ranges(settled: &[(Epoch, Epoch)]) -> String {
    let ranges: Vec<String> = settled
        .iter()
        .map(|&(first, last)| {
            if first == last {
                first.to_string()
            } else {
                format!("{first}-{last}")
            }
        })
        .collect();
    format!("[{}]", ranges.join(","))
}

fn show_option<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}
