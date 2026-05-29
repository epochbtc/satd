//! BDK descriptor-wallet canary for satd's Electrum + Esplora surfaces.
//!
//! This is a real third-party consumer — the Bitcoin Dev Kit
//! (`bdk_wallet` + `bdk_electrum` + `bdk_esplora`) — driving a full
//! descriptor-wallet workflow against a live satd regtest node. It goes
//! deeper than the wire-shape smoke canaries (`esplora-smoke.sh`,
//! `electrum-smoke.sh`) and the in-tree e2e oracles: it exercises the
//! realistic wallet path a downstream actually runs — gap-limit
//! `full_scan`, chain/mempool merge, coinbase-maturity accounting, and
//! transaction broadcast — and cross-checks the two surfaces against
//! each other.
//!
//! Flow (regtest, fixed-seed descriptor wallet):
//!   1. Mine 110 blocks to the wallet's address 0 (chain advancement via
//!      RPC — the test driver's only RPC use; everything else goes
//!      through the surfaces under test).
//!   2. `full_scan` the same descriptor over BOTH Electrum and Esplora
//!      and assert the two surfaces report a byte-identical balance,
//!      with a deterministic total (110 × 50 BTC) and a non-trivial
//!      mature/immature split — proving each surface reports the heights
//!      + coinbase flags BDK needs for maturity accounting.
//!   3. Build + sign a spend, broadcast it via the Esplora `POST /tx`
//!      path, then observe the resulting unconfirmed change over the
//!      Electrum surface — a cross-surface consistency check (broadcast
//!      on one, observed on the other).
//!   4. Confirm the spend (mine 1 block to a non-wallet address) and
//!      assert both surfaces again agree and the change has confirmed.
//!
//! Any failed assertion exits non-zero so the canary job goes red.
//!
//! Config via env (set by `bdk-smoke.sh`):
//!   BDK_ELECTRUM_URL  e.g. tcp://127.0.0.1:18403
//!   BDK_ESPLORA_URL   e.g. http://127.0.0.1:18402
//!   BDK_RPC_URL       e.g. http://127.0.0.1:18400
//!   BDK_RPC_USER / BDK_RPC_PASS

use anyhow::{bail, Context, Result};
use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_esplora::{esplora_client, EsploraExt};
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use std::str::FromStr;

const NETWORK: Network = Network::Regtest;
/// Fixed 32-byte seed → deterministic tprv → deterministic descriptors.
/// Self-contained: the canary owns this key, it never touches real funds.
const SEED: [u8; 32] = [0x21u8; 32];

const STOP_GAP: usize = 20;
const ELECTRUM_BATCH_SIZE: usize = 10;
const ESPLORA_PARALLEL: usize = 1;

/// Blocks mined to the wallet at startup. 110 > COINBASE_MATURITY (100),
/// so the wallet ends with a deterministic mix of mature + immature
/// coinbases. Regtest subsidy is a flat 50 BTC until height 150, so the
/// total is exactly 110 × 50 = 5500 BTC.
const MINE_BLOCKS: u64 = 110;
const SUBSIDY_SAT: u64 = 50 * 100_000_000;
const EXPECTED_TOTAL_SAT: u64 = MINE_BLOCKS * SUBSIDY_SAT;

/// Amount the spend sends to a non-wallet recipient.
const SEND_SAT: u64 = 100_000_000; // 1 BTC
/// Generous fee ceiling: a 1-in/2-out segwit spend at 2 sat/vB is ~300
/// sat. We assert the wallet's total drops by `SEND_SAT` plus at most
/// this — i.e. only the sent amount + a small fee left the wallet.
const MAX_FEE_SAT: u64 = 100_000;
/// A valid regtest P2WPKH that the wallet does NOT own (deterministic
/// P2WPKH from secret [0x11; 32]); shared with the other canaries.
const RECIPIENT_ADDR: &str = "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw";

/// Flat sat view of a `bdk_wallet::Balance` for comparison + printing.
#[derive(Debug, PartialEq, Eq)]
struct BalanceSnapshot {
    immature: u64,
    trusted_pending: u64,
    untrusted_pending: u64,
    confirmed: u64,
    total: u64,
}

impl BalanceSnapshot {
    fn of(b: &bdk_wallet::Balance) -> Self {
        Self {
            immature: b.immature.to_sat(),
            trusted_pending: b.trusted_pending.to_sat(),
            untrusted_pending: b.untrusted_pending.to_sat(),
            confirmed: b.confirmed.to_sat(),
            total: b.total().to_sat(),
        }
    }
}

fn descriptors() -> Result<(String, String)> {
    let xpriv = Xpriv::new_master(NETWORK, &SEED).context("derive master xpriv")?;
    // BIP84 (native segwit) account 0; external = .../0/*, internal = .../1/*.
    let external = format!("wpkh({xpriv}/84h/1h/0h/0/*)");
    let internal = format!("wpkh({xpriv}/84h/1h/0h/1/*)");
    Ok((external, internal))
}

fn new_wallet() -> Result<Wallet> {
    let (external, internal) = descriptors()?;
    Wallet::create(external, internal)
        .network(NETWORK)
        .create_wallet_no_persist()
        .context("create wallet")
}

fn scan_electrum(wallet: &mut Wallet, url: &str) -> Result<()> {
    let client = BdkElectrumClient::new(
        electrum_client::Client::new(url).with_context(|| format!("electrum connect {url}"))?,
    );
    let request = wallet.start_full_scan();
    let update = client
        .full_scan(request, STOP_GAP, ELECTRUM_BATCH_SIZE, true)
        .context("electrum full_scan")?;
    wallet.apply_update(update).context("apply electrum update")?;
    Ok(())
}

fn scan_esplora(wallet: &mut Wallet, url: &str) -> Result<()> {
    let client = esplora_client::Builder::new(url).build_blocking();
    let request = wallet.start_full_scan();
    let update = client
        .full_scan(request, STOP_GAP, ESPLORA_PARALLEL)
        .context("esplora full_scan")?;
    wallet.apply_update(update).context("apply esplora update")?;
    Ok(())
}

/// `generatetoaddress` — the only RPC the canary issues. This is chain
/// advancement (what miners do on mainnet), kept strictly separate from
/// the wallet operations under test.
fn mine(rpc: &RpcClient, blocks: u64, address: &str) -> Result<()> {
    rpc.call::<serde_json::Value>(
        "generatetoaddress",
        &[serde_json::json!(blocks), serde_json::json!(address)],
    )
    .with_context(|| format!("generatetoaddress {blocks} -> {address}"))?;
    Ok(())
}

fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required env var {key}"))
}

fn main() -> Result<()> {
    let electrum_url = env("BDK_ELECTRUM_URL")?;
    let esplora_url = env("BDK_ESPLORA_URL")?;
    let rpc_url = env("BDK_RPC_URL")?;
    let rpc_user = env("BDK_RPC_USER")?;
    let rpc_pass = env("BDK_RPC_PASS")?;

    let rpc = RpcClient::new(&rpc_url, Auth::UserPass(rpc_user, rpc_pass))
        .context("connect bitcoin RPC")?;

    // --- Phase 0: derive the wallet's address 0 (mining target) ---
    let wallet_addr = {
        let wallet = new_wallet()?;
        wallet.peek_address(KeychainKind::External, 0).address.to_string()
    };
    println!("wallet address[0] = {wallet_addr}");

    // --- Phase 1: advance the chain ---
    println!("mining {MINE_BLOCKS} blocks to the wallet address...");
    mine(&rpc, MINE_BLOCKS, &wallet_addr)?;

    // --- Phase 2: full_scan over BOTH surfaces; assert parity ---
    println!("full_scan over Electrum ({electrum_url})...");
    let mut w_electrum = new_wallet()?;
    scan_electrum(&mut w_electrum, &electrum_url)?;
    let bal_electrum = BalanceSnapshot::of(&w_electrum.balance());
    println!("  electrum balance: {bal_electrum:?}");

    println!("full_scan over Esplora ({esplora_url})...");
    let mut w_esplora = new_wallet()?;
    scan_esplora(&mut w_esplora, &esplora_url)?;
    let bal_esplora = BalanceSnapshot::of(&w_esplora.balance());
    println!("  esplora balance:  {bal_esplora:?}");

    if bal_electrum != bal_esplora {
        bail!(
            "surface disagreement after full_scan:\n  electrum = {bal_electrum:?}\n  esplora  = {bal_esplora:?}"
        );
    }
    if bal_electrum.total != EXPECTED_TOTAL_SAT {
        bail!(
            "unexpected total: got {} sat, want {} sat ({} blocks × 50 BTC)",
            bal_electrum.total,
            EXPECTED_TOTAL_SAT,
            MINE_BLOCKS
        );
    }
    if bal_electrum.confirmed == 0 {
        bail!("no confirmed (matured) coinbase — maturity accounting wrong");
    }
    if bal_electrum.immature == 0 {
        bail!("no immature coinbase — maturity accounting wrong (expected ~99 immature)");
    }
    println!("ok: both surfaces agree; total = 5500 BTC; mature/immature split present");

    // --- Phase 3: spend, broadcast via Esplora, observe via Electrum ---
    let recipient = Address::from_str(RECIPIENT_ADDR)
        .context("parse recipient")?
        .require_network(NETWORK)
        .context("recipient network")?;

    let tx = {
        let mut builder = w_electrum.build_tx();
        builder.add_recipient(recipient.script_pubkey(), Amount::from_sat(SEND_SAT));
        // Comfortably above satd's min-relay floor (a real wallet would
        // never broadcast a dust-fee tx); still a few thousand sat, far
        // under MAX_FEE_SAT.
        builder.fee_rate(FeeRate::from_sat_per_vb(25).expect("valid feerate"));
        let mut psbt = builder.finish().context("build spend")?;
        let finalized = w_electrum
            .sign(&mut psbt, SignOptions::default())
            .context("sign spend")?;
        if !finalized {
            bail!("wallet could not fully sign the spend");
        }
        psbt.extract_tx().context("extract signed tx")?
    };
    let txid = tx.compute_txid();
    println!("built + signed spend {txid}; broadcasting via Esplora POST /tx...");

    let esplora = esplora_client::Builder::new(&esplora_url).build_blocking();
    esplora.broadcast(&tx).context("esplora broadcast")?;

    // Observe the unconfirmed spend over the OTHER surface (Electrum).
    println!("observing unconfirmed spend over Electrum...");
    let mut w_observe = new_wallet()?;
    scan_electrum(&mut w_observe, &electrum_url)?;
    let bal_observe = BalanceSnapshot::of(&w_observe.balance());
    println!("  electrum balance (mempool): {bal_observe:?}");

    if bal_observe.trusted_pending == 0 {
        bail!(
            "Electrum did not surface the unconfirmed change from an Esplora-broadcast tx \
             (trusted_pending = 0); cross-surface mempool visibility broken"
        );
    }
    let dropped = EXPECTED_TOTAL_SAT
        .checked_sub(bal_observe.total)
        .context("total grew after spend?")?;
    if !(SEND_SAT..=SEND_SAT + MAX_FEE_SAT).contains(&dropped) {
        bail!(
            "spend moved {dropped} sat out of the wallet; expected {SEND_SAT}..={} (send + fee)",
            SEND_SAT + MAX_FEE_SAT
        );
    }
    println!("ok: Esplora-broadcast spend visible over Electrum as unconfirmed change");

    // --- Phase 4: confirm (mine to a NON-wallet address) and re-verify ---
    println!("confirming spend (mine 1 block to a non-wallet address)...");
    mine(&rpc, 1, RECIPIENT_ADDR)?;

    let mut w_conf_e = new_wallet()?;
    scan_electrum(&mut w_conf_e, &electrum_url)?;
    let bal_conf_e = BalanceSnapshot::of(&w_conf_e.balance());

    let mut w_conf_es = new_wallet()?;
    scan_esplora(&mut w_conf_es, &esplora_url)?;
    let bal_conf_es = BalanceSnapshot::of(&w_conf_es.balance());

    println!("  electrum (confirmed): {bal_conf_e:?}");
    println!("  esplora  (confirmed): {bal_conf_es:?}");

    if bal_conf_e != bal_conf_es {
        bail!(
            "surface disagreement after confirmation:\n  electrum = {bal_conf_e:?}\n  esplora  = {bal_conf_es:?}"
        );
    }
    if bal_conf_e.trusted_pending != 0 {
        bail!(
            "change still unconfirmed after a block ({} sat trusted_pending)",
            bal_conf_e.trusted_pending
        );
    }
    let dropped_conf = EXPECTED_TOTAL_SAT
        .checked_sub(bal_conf_e.total)
        .context("total grew after confirm?")?;
    if !(SEND_SAT..=SEND_SAT + MAX_FEE_SAT).contains(&dropped_conf) {
        bail!("post-confirm wallet total off: dropped {dropped_conf} sat");
    }

    println!("ok: spend confirmed; both surfaces agree post-confirmation");
    println!("bdk canary: PASS");
    Ok(())
}
