use bitcoin::consensus::Decodable;
use bitcoin::{Block, OutPoint, Transaction};
use clap::Parser;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "block-analyzer", about = "Analyze block data for pre-pass parallelization potential")]
struct Args {
    /// Path to blocks directory containing blk*.dat files
    #[arg(long)]
    blocks_dir: PathBuf,

    /// Network magic bytes (mainnet default)
    #[arg(long, default_value = "f9beb4d9")]
    magic: String,

    /// Maximum number of blocks to analyze (0 = all)
    #[arg(long, default_value = "0")]
    max_blocks: usize,

    /// Print per-block stats (verbose)
    #[arg(long)]
    verbose: bool,
}

/// Per-block analysis results.
struct BlockStats {
    height: u32, // 0 if unknown (out-of-order)
    tx_count: usize,
    input_count: usize,
    output_count: usize,
    intra_block_spends: usize,
    script_bytes_total: u64,
    block_size: usize,
    deser_us: u64,        // deserialization time in microseconds
    ctx_free_us: u64,     // context-free validation time
    /// For each input, the age (in blocks) of the coin it spends.
    /// None if the coin was created in this block (intra-block) or unknown.
    coin_ages: Vec<Option<u32>>,
}

/// Aggregated stats for a height range.
#[derive(Default)]
struct RangeStats {
    blocks: u64,
    total_txs: u64,
    total_inputs: u64,
    total_outputs: u64,
    total_intra_block: u64,
    total_script_bytes: u64,
    total_block_bytes: u64,
    total_deser_us: u64,
    total_ctx_free_us: u64,
    // Coin age buckets: [same_block, 1-10, 11-100, 101-1000, 1001-10000, 10000+]
    age_buckets: [u64; 6],
    total_aged_inputs: u64,
}

impl RangeStats {
    fn add(&mut self, bs: &BlockStats) {
        self.blocks += 1;
        self.total_txs += bs.tx_count as u64;
        self.total_inputs += bs.input_count as u64;
        self.total_outputs += bs.output_count as u64;
        self.total_intra_block += bs.intra_block_spends as u64;
        self.total_script_bytes += bs.script_bytes_total;
        self.total_block_bytes += bs.block_size as u64;
        self.total_deser_us += bs.deser_us;
        self.total_ctx_free_us += bs.ctx_free_us;

        for age in &bs.coin_ages {
            match age {
                None => self.age_buckets[0] += 1, // intra-block
                Some(a) if *a <= 10 => {
                    self.age_buckets[1] += 1;
                    self.total_aged_inputs += 1;
                }
                Some(a) if *a <= 100 => {
                    self.age_buckets[2] += 1;
                    self.total_aged_inputs += 1;
                }
                Some(a) if *a <= 1000 => {
                    self.age_buckets[3] += 1;
                    self.total_aged_inputs += 1;
                }
                Some(a) if *a <= 10000 => {
                    self.age_buckets[4] += 1;
                    self.total_aged_inputs += 1;
                }
                Some(_) => {
                    self.age_buckets[5] += 1;
                    self.total_aged_inputs += 1;
                }
            }
        }
    }

    fn print(&self, label: &str) {
        if self.blocks == 0 {
            return;
        }
        let avg_txs = self.total_txs as f64 / self.blocks as f64;
        let avg_inputs = self.total_inputs as f64 / self.blocks as f64;
        let avg_outputs = self.total_outputs as f64 / self.blocks as f64;
        let avg_size = self.total_block_bytes as f64 / self.blocks as f64 / 1024.0;
        let intra_pct = if self.total_inputs > 0 {
            self.total_intra_block as f64 / self.total_inputs as f64 * 100.0
        } else {
            0.0
        };
        let avg_deser = self.total_deser_us as f64 / self.blocks as f64;
        let avg_ctx_free = self.total_ctx_free_us as f64 / self.blocks as f64;

        // Pre-pass viability: % of inputs with coin age > 10 blocks
        // These would be correctly resolved by a pre-pass that's 10 blocks ahead
        let prepass_viable_10 = if self.total_inputs > 0 {
            let viable = self.age_buckets[2] + self.age_buckets[3]
                + self.age_buckets[4] + self.age_buckets[5];
            viable as f64 / self.total_inputs as f64 * 100.0
        } else {
            0.0
        };

        // % viable with 100-block lookahead
        let prepass_viable_100 = if self.total_inputs > 0 {
            let viable = self.age_buckets[3] + self.age_buckets[4] + self.age_buckets[5];
            viable as f64 / self.total_inputs as f64 * 100.0
        } else {
            0.0
        };

        let avg_script = if self.total_inputs > 0 {
            self.total_script_bytes as f64 / self.total_inputs as f64
        } else {
            0.0
        };

        println!("=== {} ({} blocks) ===", label, self.blocks);
        println!("  Avg block:     {:.0} txs, {:.0} inputs, {:.0} outputs, {:.1} KB",
            avg_txs, avg_inputs, avg_outputs, avg_size);
        println!("  Intra-block:   {:.2}% of inputs spend outputs from same block", intra_pct);
        println!("  Avg script:    {:.0} bytes/input", avg_script);
        println!("  Timing:        deser {:.0}us, ctx-free {:.0}us per block", avg_deser, avg_ctx_free);
        println!("  Coin age distribution:");
        println!("    Same block:  {:>10} ({:.1}%)", self.age_buckets[0],
            self.age_buckets[0] as f64 / self.total_inputs.max(1) as f64 * 100.0);
        println!("    1-10 blocks: {:>10} ({:.1}%)", self.age_buckets[1],
            self.age_buckets[1] as f64 / self.total_inputs.max(1) as f64 * 100.0);
        println!("    11-100:      {:>10} ({:.1}%)", self.age_buckets[2],
            self.age_buckets[2] as f64 / self.total_inputs.max(1) as f64 * 100.0);
        println!("    101-1K:      {:>10} ({:.1}%)", self.age_buckets[3],
            self.age_buckets[3] as f64 / self.total_inputs.max(1) as f64 * 100.0);
        println!("    1K-10K:      {:>10} ({:.1}%)", self.age_buckets[4],
            self.age_buckets[4] as f64 / self.total_inputs.max(1) as f64 * 100.0);
        println!("    10K+:        {:>10} ({:.1}%)", self.age_buckets[5],
            self.age_buckets[5] as f64 / self.total_inputs.max(1) as f64 * 100.0);
        println!("  Pre-pass viability:");
        println!("    10-block lookahead:  {:.1}% of inputs correctly pre-resolved", prepass_viable_10);
        println!("    100-block lookahead: {:.1}% of inputs correctly pre-resolved", prepass_viable_100);
        println!();
    }
}

/// Read all blocks from flat files. Returns (block, file_offset) pairs.
fn read_blocks(blocks_dir: &PathBuf, magic: &[u8; 4], max_blocks: usize) -> Vec<(Block, u64)> {
    let mut blocks = Vec::new();
    let mut file_num = 0u32;
    let start = Instant::now();

    loop {
        let path = blocks_dir.join(format!("blk{:05}.dat", file_num));
        if !path.exists() {
            break;
        }

        let file = match File::open(&path) {
            Ok(f) => f,
            Err(_) => break,
        };
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut reader = BufReader::with_capacity(4 * 1024 * 1024, file);
        let mut pos = 0u64;

        while pos + 8 < file_len {
            // Read magic + size header
            let mut header = [0u8; 8];
            if reader.read_exact(&mut header).is_err() {
                break;
            }

            let file_magic = &header[0..4];
            let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as u64;

            if file_magic != magic {
                break;
            }

            if size == 0 || pos + 8 + size > file_len {
                break;
            }

            let mut block_data = vec![0u8; size as usize];
            if reader.read_exact(&mut block_data).is_err() {
                break;
            }

            match Block::consensus_decode(&mut block_data.as_slice()) {
                Ok(block) => blocks.push((block, pos)),
                Err(_) => {
                    // Skip corrupted block
                }
            }

            pos += 8 + size;

            if max_blocks > 0 && blocks.len() >= max_blocks {
                break;
            }
        }

        if max_blocks > 0 && blocks.len() >= max_blocks {
            break;
        }

        file_num += 1;
        if file_num % 100 == 0 {
            eprint!("\rReading file {}... ({} blocks)", file_num, blocks.len());
        }
    }

    let elapsed = start.elapsed();
    eprintln!("\rRead {} blocks from {} files in {:.1}s",
        blocks.len(), file_num, elapsed.as_secs_f64());

    blocks
}

/// Sort blocks by building the chain (following prev_blockhash links).
fn sort_blocks_by_height(blocks: Vec<(Block, u64)>) -> Vec<(Block, u32)> {
    eprintln!("Sorting blocks by height...");
    let start = Instant::now();

    // Build hash → (block, offset) map
    let mut by_hash: HashMap<bitcoin::BlockHash, (Block, u64)> = HashMap::with_capacity(blocks.len());
    for (block, offset) in blocks {
        by_hash.insert(block.block_hash(), (block, offset));
    }

    // Find genesis (block whose prev_blockhash is all zeros or not in our set)
    let genesis_hash = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin).block_hash();

    let mut sorted = Vec::with_capacity(by_hash.len());
    let mut current_hash = genesis_hash;
    let mut height = 0u32;

    // Build reverse map: prev_hash → hash
    let mut children: HashMap<bitcoin::BlockHash, bitcoin::BlockHash> = HashMap::new();
    for (hash, (block, _)) in &by_hash {
        children.insert(block.header.prev_blockhash, *hash);
    }

    // Walk the chain from genesis
    loop {
        if let Some(child_hash) = children.get(&current_hash) {
            if let Some((block, _)) = by_hash.remove(child_hash) {
                sorted.push((block, height));
                current_hash = *child_hash;
                height += 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    let elapsed = start.elapsed();
    eprintln!("Sorted {} blocks in {:.1}s ({} orphans discarded)",
        sorted.len(), elapsed.as_secs_f64(), by_hash.len());

    sorted
}

/// Context-free transaction validation (mimics check_transaction).
fn check_transaction_ctx_free(tx: &Transaction) -> bool {
    if tx.input.is_empty() || tx.output.is_empty() {
        return false;
    }
    // Check for duplicate inputs
    let mut seen = HashSet::new();
    for input in &tx.input {
        if !seen.insert(input.previous_output) {
            return false;
        }
    }
    true
}

/// Analyze a single block.
fn analyze_block(
    block: &Block,
    height: u32,
    utxo_heights: &HashMap<OutPoint, u32>,
) -> BlockStats {
    let deser_start = Instant::now();
    // Deserialization already done, but measure txid computation
    let _hash = block.block_hash();
    let deser_us = deser_start.elapsed().as_micros() as u64;

    let ctx_free_start = Instant::now();
    for tx in &block.txdata {
        let _txid = tx.compute_txid();
        check_transaction_ctx_free(tx);
    }
    let ctx_free_us = ctx_free_start.elapsed().as_micros() as u64;

    let mut input_count = 0usize;
    let mut output_count = 0usize;
    let mut intra_block_spends = 0usize;
    let mut script_bytes_total = 0u64;
    let mut coin_ages = Vec::new();

    // Track outputs created in this block
    let mut this_block_outputs: HashSet<OutPoint> = HashSet::new();

    for tx in &block.txdata {
        let txid = tx.compute_txid();

        if !tx.is_coinbase() {
            for input in &tx.input {
                input_count += 1;
                script_bytes_total += input.script_sig.len() as u64;
                // Add witness bytes
                for w in &input.witness.to_vec() {
                    script_bytes_total += w.len() as u64;
                }

                if this_block_outputs.contains(&input.previous_output) {
                    intra_block_spends += 1;
                    coin_ages.push(None);
                } else if let Some(&coin_height) = utxo_heights.get(&input.previous_output) {
                    coin_ages.push(Some(height.saturating_sub(coin_height)));
                } else {
                    // Unknown — coin was created before our analysis window
                    coin_ages.push(Some(height)); // treat as very old
                }
            }
        }

        for (vout, output) in tx.output.iter().enumerate() {
            output_count += 1;
            let outpoint = OutPoint { txid, vout: vout as u32 };
            this_block_outputs.insert(outpoint);
            let _ = output; // suppress unused
        }
    }

    let block_size = bitcoin::consensus::serialize(block).len();

    BlockStats {
        height,
        tx_count: block.txdata.len(),
        input_count,
        output_count,
        intra_block_spends,
        script_bytes_total,
        block_size,
        deser_us,
        ctx_free_us,
        coin_ages,
    }
}

fn main() {
    let args = Args::parse();

    let magic_bytes: [u8; 4] = {
        let hex = hex::decode(&args.magic).expect("Invalid magic hex");
        [hex[0], hex[1], hex[2], hex[3]]
    };

    // Phase 1: Read all blocks from flat files
    let raw_blocks = read_blocks(&args.blocks_dir, &magic_bytes, args.max_blocks);

    if raw_blocks.is_empty() {
        eprintln!("No blocks found");
        return;
    }

    // Phase 2: Sort blocks by height (build chain)
    let sorted = sort_blocks_by_height(raw_blocks);

    // Phase 3: Analyze blocks with UTXO tracking
    eprintln!("Analyzing {} blocks...", sorted.len());
    let start = Instant::now();

    // Track which outpoints were created at which height
    let mut utxo_heights: HashMap<OutPoint, u32> = HashMap::new();
    let mut all_stats: Vec<BlockStats> = Vec::with_capacity(sorted.len());

    for (i, (block, height)) in sorted.iter().enumerate() {
        let stats = analyze_block(block, *height, &utxo_heights);

        // Update UTXO set: add outputs, remove inputs
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            for (vout, _) in tx.output.iter().enumerate() {
                let op = OutPoint { txid, vout: vout as u32 };
                utxo_heights.insert(op, *height);
            }
            if !tx.is_coinbase() {
                for input in &tx.input {
                    utxo_heights.remove(&input.previous_output);
                }
            }
        }

        if args.verbose {
            println!("height={} txs={} inputs={} outputs={} intra={} size={}",
                height, stats.tx_count, stats.input_count, stats.output_count,
                stats.intra_block_spends, stats.block_size);
        }

        all_stats.push(stats);

        if (i + 1) % 50000 == 0 {
            eprint!("\r  Analyzed {}/{} blocks...", i + 1, sorted.len());
        }
    }

    let elapsed = start.elapsed();
    eprintln!("\rAnalyzed {} blocks in {:.1}s", all_stats.len(), elapsed.as_secs_f64());
    println!();

    // Phase 4: Aggregate by height ranges
    let ranges: Vec<(u32, u32, &str)> = vec![
        (0, 100_000, "0-100K (2009-2014, tiny blocks)"),
        (100_000, 200_000, "100K-200K (2014-2015)"),
        (200_000, 300_000, "200K-300K (2015-2016)"),
        (300_000, 400_000, "300K-400K (2016-2017)"),
        (400_000, 500_000, "400K-500K (2017-2019, SegWit era)"),
        (500_000, 600_000, "500K-600K (2019-2020)"),
        (600_000, 700_000, "600K-700K (2020-2021)"),
        (700_000, 800_000, "700K-800K (2021-2023)"),
        (800_000, 1_000_000, "800K+ (2023+, Ordinals era)"),
    ];

    let mut overall = RangeStats::default();

    for (lo, hi, label) in &ranges {
        let mut range = RangeStats::default();
        for stats in &all_stats {
            if stats.height >= *lo && stats.height < *hi {
                range.add(stats);
                overall.add(stats);
            }
        }
        range.print(label);
    }

    overall.print("OVERALL");

    // Phase 5: Parallelization analysis
    println!("=== Pre-pass Parallelization Analysis ===");
    println!();

    let total_inputs: u64 = all_stats.iter().map(|s| s.input_count as u64).sum();
    let total_script: u64 = all_stats.iter().map(|s| s.script_bytes_total).sum();
    let total_deser: u64 = all_stats.iter().map(|s| s.deser_us).sum();
    let total_ctx_free: u64 = all_stats.iter().map(|s| s.ctx_free_us).sum();

    println!("Total inputs analyzed:     {:>12}", total_inputs);
    println!("Total script bytes:        {:>12} ({:.1} GB)",
        total_script, total_script as f64 / 1e9);
    println!("Total deser time:          {:>12} us ({:.1}s)",
        total_deser, total_deser as f64 / 1e6);
    println!("Total ctx-free check time: {:>12} us ({:.1}s)",
        total_ctx_free, total_ctx_free as f64 / 1e6);
    println!();
    println!("Phase 1 (deserialize + ctx-free) can be fully parallelized.");
    println!("Phase 2 (speculative UTXO) viability depends on lookahead distance.");
    println!("Phase 3 (script verification) parallelizable for all pre-resolved inputs.");
    println!();

    // Estimate time savings
    let total_connect_us: u64 = all_stats.iter()
        .map(|s| (s.deser_us + s.ctx_free_us) * s.input_count.max(1) as u64)
        .sum();
    println!("Estimated total serial connect time: {:.1}s",
        total_connect_us as f64 / 1e6);

    println!();
    println!("UTXO set size at end: {} entries", utxo_heights.len());
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
        .collect()
}
