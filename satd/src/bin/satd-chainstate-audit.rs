//! Offline consistency audit of a stopped node's chainstate.
//!
//! Answers one question about a suspect datadir: does the UTXO set agree with
//! the blocks the node says are on its active chain? It walks the tip's
//! ancestry by parent pointer, reads each block out of the flat files, and
//! checks the coins, the height index, the txindex and the cumulative
//! transaction counts against what those blocks actually contain.
//!
//! It exists because the alternative, on the one occasion it was needed, was a
//! throwaway RocksDB reader written by hand under time pressure. Diagnosing
//! that incident took four separate on-disk artifacts, and the fourth reversed
//! the conclusion the first three supported — so this reports *what* disagreed
//! (the outpoint, the height, the txid) rather than a verdict.
//!
//! It issues no writes of its own, but it is **not** non-mutating: opening the
//! chainstate opens RocksDB read-write, which replays and truncates the WAL,
//! may flush memtables and compact, rewrites the MANIFEST, deletes obsolete
//! files, creates any missing column family, and stamps the schema version.
//! Opening the block files creates `xor.dat` if it is absent. So if the datadir
//! is evidence — which is the case this tool exists for — copy it first and
//! audit the copy. The tool says so on every run.
//!
//! It takes the RocksDB lock, so the node must be stopped — the same
//! requirement `satd-chainstate-repair` has, and for the same reason.
//!
//! This diagnoses; it does not repair. A missing coin is only recoverable by
//! replaying the block that created it, which is `-reindex-chainstate` or, for
//! a single block, `satd-chainstate-repair`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use node::chain::consistency::verify_chainstate_with;
use node::chain::tip_ancestry::DEFAULT_ANCESTRY_WINDOW;
use node::storage::Store;
use node::storage::flatfile::{FlatFileManager, FlatFilePos};
use node::storage::rocksdb_store::RocksDbStore;

#[derive(Parser)]
#[command(
    name = "satd-chainstate-audit",
    about = "Check a stopped satd node's UTXO set against the blocks on its active chain",
    long_about = "Walks the tip's ancestry, reads each block back from the flat files, and \
                  reports every disagreement between the blocks and the chainstate: coins that \
                  should exist and do not, spent coins still present, height-index rows naming \
                  the wrong block, txindex rows pointing at the wrong block, and cumulative \
                  transaction counts that do not follow from their parent.\n\n\
                  Read-only — it never writes to the datadir — but it takes the RocksDB lock, \
                  so the node MUST be stopped.\n\n\
                  Exit status: 0 consistent, 1 could not run, 2 inconsistencies found."
)]
struct Args {
    /// Network datadir of the node (the directory holding `chainstate/` and
    /// `blocks/`). For non-mainnet nodes pass the network subdirectory itself.
    #[arg(long)]
    datadir: PathBuf,

    /// Block-files directory. Defaults to `<datadir>/blocks`.
    #[arg(long)]
    blocksdir: Option<PathBuf>,

    /// Whether the node runs with -txindex. When false, absent txindex rows
    /// are the correct state and are not reported as faults.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    txindex: bool,

    /// How many blocks below the tip to check. The default matches the window
    /// the node itself audits at startup. Raise it to widen the search; the
    /// cost is one block read per height.
    #[arg(long, default_value_t = DEFAULT_ANCESTRY_WINDOW)]
    window: u32,

    /// Print every offending outpoint/height/txid rather than the first few.
    #[arg(long)]
    verbose: bool,
}

/// How many members of each fault list to print without `--verbose`. A log line
/// is not a data dump, and these can carry thousands of entries.
const SHOW: usize = 20;

fn run(args: &Args) -> Result<node::chain::consistency::ChainstateReport, String> {
    if !args.datadir.join("chainstate").is_dir() {
        return Err(format!(
            "{} has no chainstate/ subdirectory — pass the node's network datadir (for \
             non-mainnet chains that is the network subdirectory itself)",
            args.datadir.display()
        ));
    }

    eprintln!(
        "NOTE: this opens the chainstate read-write. It issues no writes of its own, but\n\
         RocksDB replays the WAL, may compact, and rewrites bookkeeping on open, and the\n\
         block-file layer creates xor.dat if absent. If this datadir is evidence, stop now\n\
         and audit a copy instead.\n"
    );

    // Opening takes the RocksDB lock: fails loudly if the node is still
    // running, which is exactly what we want.
    //
    // 256 MB of block cache and a bounded descriptor count: this is a
    // sequential scan that reads each block once, so a large cache buys
    // nothing, and `max_open_files = -1` (unlimited) is the setting
    // `rocksdb_store` blames for wedging a multi-gigabyte process during a
    // mainnet IBD. An audit runs on a box that is already having a bad day.
    let store = RocksDbStore::open(&args.datadir, args.txindex, 256, false, 1000)
        .map_err(|e| format!("cannot open chainstate (is the node stopped?): {e}"))?;

    let tip_hash = store
        .get_tip()
        .ok_or("chainstate has no tip — nothing to audit")?;
    let tip_entry = store
        .get_block_index(&tip_hash)
        .ok_or_else(|| format!("tip {tip_hash} has no block-index entry"))?;

    let blocksdir = args
        .blocksdir
        .clone()
        .unwrap_or_else(|| args.datadir.join("blocks"));
    let mut flat = FlatFileManager::new(&blocksdir)
        .map_err(|e| format!("cannot open block files: {e}"))?;

    eprintln!(
        "auditing {} blocks below tip {} (height {})",
        args.window.min(tip_entry.height + 1),
        tip_hash,
        tip_entry.height
    );

    let report = verify_chainstate_with(
        &store,
        &mut |hash, entry| {
            let pos = FlatFilePos {
                file_number: entry.file_number,
                data_pos: entry.data_pos,
            };
            let raw = flat.read_block(&pos).ok()?;
            let block: bitcoin::Block = bitcoin::consensus::deserialize(&raw).ok()?;
            // A mis-recorded offset lands on another record's start, not on
            // garbage, so deserialization succeeds and hands back a different
            // block. Treat that as unreadable rather than auditing the wrong
            // block's contents against this height.
            (block.block_hash() == *hash).then_some(block)
        },
        tip_hash,
        tip_entry.height,
        args.window,
        // An offline audit has no attached background chainstate, so an
        // AssumeUTXO node's base cannot be identified. It lands in the
        // unvalidated floor, which is reported but is not a fault.
        None,
    );

    Ok(report)
}

fn print_list<T: std::fmt::Display>(label: &str, items: &[T], verbose: bool) {
    if items.is_empty() {
        return;
    }
    println!("{label}: {}", items.len());
    let shown = if verbose { items.len() } else { SHOW.min(items.len()) };
    for item in &items[..shown] {
        println!("  {item}");
    }
    if shown < items.len() {
        println!("  … {} more (--verbose for all)", items.len() - shown);
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let report = match run(&args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    println!(
        "checked {} blocks, heights {}..=tip",
        report.blocks_checked, report.lowest_height
    );

    if !report.ancestry.holes.is_empty() {
        println!("ancestors never connected: {}", report.ancestry.holes.len());
        let shown = if args.verbose {
            report.ancestry.holes.len()
        } else {
            SHOW.min(report.ancestry.holes.len())
        };
        for h in &report.ancestry.holes[..shown] {
            println!("  height {} {} status {:?}", h.height, h.hash, h.status);
        }
    }
    if let Some(broken) = &report.ancestry.broken {
        println!("ancestry walk stopped early: {broken:?}");
    }
    if !report.ancestry.unvalidated_floor.is_empty() {
        println!(
            "not validated by this chainstate (normal for AssumeUTXO history): {}",
            report.ancestry.unvalidated_floor.len()
        );
    }

    print_list("coins missing", &report.missing_coins, args.verbose);
    print_list("spent coins still present", &report.unspent_spends, args.verbose);
    print_list("height rows wrong", &report.height_mismatches, args.verbose);
    print_list("blocks unreadable", &report.unreadable, args.verbose);

    if !report.tx_index_wrong.is_empty() {
        println!("txindex rows wrong: {}", report.tx_index_wrong.len());
        let shown = if args.verbose {
            report.tx_index_wrong.len()
        } else {
            SHOW.min(report.tx_index_wrong.len())
        };
        for (txid, block) in &report.tx_index_wrong[..shown] {
            println!("  {txid} -> {block}");
        }
    }
    if !report.chain_tx_faults.is_empty() {
        println!("chain_tx rows wrong: {}", report.chain_tx_faults.len());
        let shown = if args.verbose {
            report.chain_tx_faults.len()
        } else {
            SHOW.min(report.chain_tx_faults.len())
        };
        for (height, hash) in &report.chain_tx_faults[..shown] {
            println!("  height {height} {hash}");
        }
    }
    if args.txindex && report.tx_index_absent > 0 {
        println!(
            "txindex rows absent: {} (expected only when the node runs without -txindex)",
            report.tx_index_absent
        );
    }

    if report.is_consistent() {
        println!("consistent");
        ExitCode::SUCCESS
    } else {
        println!("INCONSISTENT: {}", report.describe());
        println!(
            "This tool does not repair. A missing coin is recoverable only by replaying the \
             block that created it: -reindex-chainstate, or satd-chainstate-repair for a \
             single block."
        );
        ExitCode::from(2)
    }
}
