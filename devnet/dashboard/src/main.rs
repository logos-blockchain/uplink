//! `uplink-dashboard`: a terminal view of the uplink devnet, read from the chains.
//!
//! Shows the blockchain nodes and their blend declarations, the blend membership the oracle
//! published for each epoch, the uplink program's public state and activity on LEZ, and, given
//! the operators' wallets, each participant's private state as its wallet last saw it.

use core::time::Duration;
use std::{
    fs,
    io::Write as _,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context as _, Result};
use clap::Parser;
use lee::AccountId;
use ratatui::{
    Terminal,
    backend::TestBackend,
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
};
use referral_core::NodeId;
use url::Url;

use crate::{
    fetch::{Fetcher, Snapshot, Sources},
    ui::Labels,
};

mod fetch;
mod ui;

#[derive(Parser)]
#[command(about = "A terminal view of the uplink devnet, read from the chains")]
struct Args {
    /// A blockchain node's HTTP API, as NAME=URL. Repeat for each node.
    #[arg(
        long = "node",
        value_parser = parse_named::<Url>,
        default_values = [
            "node-0=http://127.0.0.1:18080",
            "node-1=http://127.0.0.1:18081",
            "node-2=http://127.0.0.1:18082",
            "node-3=http://127.0.0.1:18083",
        ],
    )]
    nodes: Vec<(String, Url)>,
    /// The LEZ indexer's RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8779")]
    indexer: Url,
    /// The referral program's account. Without it, only the chains are shown.
    #[arg(long, env = "UPLINK_PROGRAM")]
    program: Option<AccountId>,
    /// A directory whose `node-*/provider_id` files name the nodes by their keys.
    #[arg(long)]
    labels: Option<PathBuf>,
    /// An operator's LEZ wallet directory, as NAME=DIR, whose `participant` file names its
    /// participant account. Repeat for each operator.
    #[arg(long = "wallet", value_parser = parse_named::<PathBuf>)]
    wallets: Vec<(String, PathBuf)>,
    /// Seconds between reads.
    #[arg(long, default_value_t = 2)]
    interval: u64,
    /// Read once and print the dashboard as text, `COLUMNSxROWS` in size, instead of running it.
    #[arg(long, value_name = "COLUMNSxROWS", value_parser = parse_size)]
    print: Option<(u16, u16)>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let labels = args
        .labels
        .as_ref()
        .map(read_labels)
        .transpose()?
        .unwrap_or_default();
    let mut fetcher = Fetcher::new(Sources {
        nodes: args.nodes,
        indexer: args.indexer,
        program: args.program,
        wallets: args.wallets,
    })?;

    if let Some((columns, rows)) = args.print {
        let snapshot = fetcher.fetch().await;
        let mut terminal = Terminal::new(TestBackend::new(columns, rows))?;
        terminal.draw(|frame| ui::draw(frame, Some(&snapshot), &labels, 0))?;
        let buffer = terminal.backend().buffer();
        let mut out = std::io::stdout().lock();
        for row in 0..rows {
            let line: String = (0..columns)
                .map(|column| buffer[(column, row)].symbol())
                .collect();
            writeln!(out, "{}", line.trim_end())?;
        }
        return Ok(());
    }

    let latest: Arc<Mutex<Option<(Snapshot, Instant)>>> = Arc::default();
    let writer = Arc::clone(&latest);
    let interval = Duration::from_secs(args.interval);
    tokio::spawn(async move {
        loop {
            let snapshot = fetcher.fetch().await;
            if let Ok(mut slot) = writer.lock() {
                *slot = Some((snapshot, Instant::now()));
            }
            tokio::time::sleep(interval).await;
        }
    });

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &latest, &labels);
    ratatui::restore();
    result
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    latest: &Mutex<Option<(Snapshot, Instant)>>,
    labels: &Labels,
) -> Result<()> {
    loop {
        {
            let latest = latest
                .lock()
                .map_err(|_poisoned| anyhow::anyhow!("the reader panicked"))?;
            let (snapshot, age) = latest.as_ref().map_or((None, 0), |(snapshot, at)| {
                (Some(snapshot), at.elapsed().as_secs())
            });
            terminal.draw(|frame| ui::draw(frame, snapshot, labels, age))?;
        }
        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && (matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                || (key.code == KeyCode::Char('c')
                    && key.modifiers.contains(KeyModifiers::CONTROL)))
        {
            return Ok(());
        }
    }
}

/// Names each node in `dir/node-*/provider_id` after its directory.
fn read_labels(dir: &PathBuf) -> Result<Labels> {
    let mut labels = Labels::new();
    for entry in fs::read_dir(dir).with_context(|| format!("Failed to read {}", dir.display()))? {
        let entry = entry?;
        let Ok(provider) = fs::read_to_string(entry.path().join("provider_id")) else {
            continue;
        };
        let bytes: [u8; 32] = hex::decode(provider.trim())?
            .try_into()
            .map_err(|_bytes| anyhow::anyhow!("a provider id is not 32 bytes"))?;
        labels.insert(
            NodeId::new(bytes),
            entry.file_name().to_string_lossy().into_owned(),
        );
    }
    Ok(labels)
}

fn parse_named<T: core::str::FromStr>(text: &str) -> Result<(String, T)>
where
    T::Err: core::fmt::Display,
{
    let (name, value) = text.split_once('=').context("expected NAME=VALUE")?;
    let value = value.parse().map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok((name.to_owned(), value))
}

fn parse_size(text: &str) -> Result<(u16, u16)> {
    let (columns, rows) = text.split_once('x').context("expected COLUMNSxROWS")?;
    Ok((columns.parse()?, rows.parse()?))
}
