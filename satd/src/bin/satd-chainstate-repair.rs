//! Offline surgical repair for a single lost connect delta.
//!
//! Wraps [`node::chain::repair::repair_lost_connect_delta`] in an
//! operator CLI: opens the (stopped) node's chainstate directly,
//! reads the holed block from flat files, optionally snapshots the
//! database via a RocksDB checkpoint, and re-applies the lost delta.
//! Dry-run by default; `--apply` writes, and demands either
//! `--checkpoint <dir>` or an explicit `--no-checkpoint`.
//!
//! See the module docs in `node/src/chain/repair.rs` for why this is
//! sound (the lost delta commutes with every block connected after it)
//! and for the damage signature it insists on before writing.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use node::chain::repair::{RepairReport, repair_lost_connect_delta};
use node::index::address::AddressIndexConfig;
use node::storage::Store;
use node::storage::flatfile::{FlatFileManager, FlatFilePos};
use node::storage::rocksdb_store::RocksDbStore;
use node::validation::script::RustVerifier;

#[derive(Parser)]
#[command(
    name = "satd-chainstate-repair",
    about = "Re-apply a single block's lost connect delta to a stopped satd node's chainstate",
    long_about = "Repairs the \"lost connect delta\" damage left by the pre-fix BulkLoad \
                  durability bug: one block's entire connect batch (coins, undo, txindex, \
                  address/outpoint-spend rows) evaporated across a restart while the tip and \
                  every other block stayed intact.\n\n\
                  The node MUST be stopped (this tool takes the RocksDB lock). Dry-run by \
                  default: it verifies the damage matches the lost-delta signature and reports \
                  the delta it would write. Run with --apply --checkpoint <dir> to repair."
)]
struct Args {
    /// Network datadir of the node (the directory holding `chainstate/`
    /// and `blocks/`), e.g. /satd for a mainnet node. For non-mainnet
    /// nodes pass the network subdirectory itself (e.g.
    /// /satd/signet/signet).
    #[arg(long)]
    datadir: PathBuf,

    /// Block-files directory. Defaults to `<datadir>/blocks`.
    #[arg(long)]
    blocksdir: Option<PathBuf>,

    /// Network the node runs on (drives script verification):
    /// main | testnet4 | signet | regtest.
    #[arg(long)]
    network: String,

    /// Hash of the block whose connect delta was lost.
    #[arg(long)]
    blockhash: String,

    /// Whether the node runs with -txindex (mainnet dogfood: yes).
    /// Must match the node's configuration so the rebuilt delta only
    /// populates indices the node actually maintains.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    txindex: bool,

    /// Whether the node runs with -addressindex (mainnet dogfood: yes).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    addressindex: bool,

    /// Write the repair. Without this flag the tool only verifies the
    /// damage signature and prints the delta it would apply.
    #[arg(long)]
    apply: bool,

    /// Before writing, snapshot the database into this directory via a
    /// RocksDB checkpoint (hardlinks — instant, near-free on the same
    /// filesystem). Must not exist yet. Restore by replacing
    /// `<datadir>/chainstate` with it.
    #[arg(long)]
    checkpoint: Option<PathBuf>,

    /// Allow --apply without a checkpoint. Not recommended.
    #[arg(long)]
    no_checkpoint: bool,

    /// Worker threads for UTXO resolution and script verification.
    #[arg(long, default_value_t = default_threads())]
    threads: usize,
}

fn default_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
}

fn parse_network(s: &str) -> Result<bitcoin::Network, String> {
    match s {
        "main" | "mainnet" | "bitcoin" => Ok(bitcoin::Network::Bitcoin),
        "testnet4" => Ok(bitcoin::Network::Testnet4),
        "testnet" | "testnet3" => Ok(bitcoin::Network::Testnet),
        "signet" => Ok(bitcoin::Network::Signet),
        "regtest" => Ok(bitcoin::Network::Regtest),
        other => Err(format!("unknown network {other:?} (expected main|testnet4|signet|regtest)")),
    }
}

fn run(args: &Args) -> Result<RepairReport, String> {
    let network = parse_network(&args.network)?;
    let blockhash: bitcoin::BlockHash =
        args.blockhash.parse().map_err(|e| format!("bad --blockhash: {e}"))?;
    if args.apply && args.checkpoint.is_none() && !args.no_checkpoint {
        return Err("--apply requires --checkpoint <dir> (or an explicit --no-checkpoint)".into());
    }
    if !args.datadir.join("chainstate").is_dir() {
        return Err(format!("{} has no chainstate/ subdirectory — pass the node's network \
             datadir (for non-mainnet chains that is the network subdirectory itself)",
            args.datadir.display()
        ));
    }

    // Opening takes the RocksDB lock: fails loudly if the node is
    // still running, which is exactly what we want.
    let store = RocksDbStore::open(&args.datadir, args.txindex, 1024, false, -1)
        .map_err(|e| format!("cannot open chainstate (is the node stopped?): {e}"))?;

    let entry = store
        .get_block_index(&blockhash)
        .ok_or_else(|| format!("block {blockhash} not found in the block index"))?;
    eprintln!(
        "block {} at height {} — status {:?}, {} txs, blk{:05}.dat offset {}",
        blockhash, entry.height, entry.status, entry.num_tx, entry.file_number, entry.data_pos
    );

    let blocksdir = args.blocksdir.clone().unwrap_or_else(|| args.datadir.join("blocks"));
    let mut flat_files =
        FlatFileManager::new(&blocksdir).map_err(|e| format!("cannot open block files: {e}"))?;
    let pos = FlatFilePos { file_number: entry.file_number, data_pos: entry.data_pos };
    let raw = flat_files
        .read_block(&pos)
        .map_err(|e| format!("cannot read block data from flat files: {e}"))?;
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&raw)
        .map_err(|e| format!("block data failed to deserialize: {e}"))?;
    if block.block_hash() != blockhash {
        return Err(format!(
            "flat-file data at blk{:05}.dat:{} hashes to {}, not {} — block index entry is \
             inconsistent, refusing",
            pos.file_number,
            pos.data_pos,
            block.block_hash(),
            blockhash
        ));
    }

    if args.apply
        && let Some(checkpoint_dir) = &args.checkpoint
    {
        store
            .create_checkpoint(checkpoint_dir)
            .map_err(|e| format!("checkpoint failed, nothing written: {e}"))?;
        eprintln!("checkpoint written to {}", checkpoint_dir.display());
    }

    let verifier = RustVerifier::new(network);
    let address_index =
        AddressIndexConfig { enabled: args.addressindex, ..Default::default() };
    repair_lost_connect_delta(
        &store,
        &block,
        &verifier,
        network,
        args.threads,
        &address_index,
        args.apply,
    )
    .map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(report) => {
            let mode = if report.applied { "APPLIED" } else { "DRY RUN (nothing written)" };
            println!("{mode}");
            println!(
                "  block {} at height {} (tip {} at height {})",
                report.block_hash, report.height, report.tip_hash, report.tip_height
            );
            println!(
                "  delta: {} coins created, {} phantom coins removed, {} txindex rows, \
                 {} addr funding rows, {} addr spending rows, {} outpoint-spend rows",
                report.coins_created,
                report.coins_spent,
                report.tx_index_rows,
                report.addr_funding_rows,
                report.addr_spending_rows,
                report.outpoint_spend_rows,
            );
            println!(
                "  cumulative-tx-count rows rewritten for {} descendant block(s)",
                report.chain_tx_rewrites
            );
            if !report.applied {
                println!("re-run with --apply --checkpoint <dir> to write the repair");
            } else {
                println!("repair written and flushed durably; restart the node to verify \
                     it connects new blocks");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
