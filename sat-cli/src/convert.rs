//! Command-line argument conversion for the raw RPC passthrough, ported from
//! Bitcoin Core v32.1 `src/rpc/client.cpp` (`vRPCConvertParams`,
//! `RPCConvertValues`, `RPCConvertNamedValues`).
//!
//! `bitcoin-cli` parses an argument as JSON only when its `(method, index)` or
//! `(method, name)` is listed in the table, and sends every other argument as
//! the string it was typed as. So `signmessagewithprivkey <wif> 123` signs the
//! text "123", and a hex string that happens to be all digits stays a string.
//!
//! satd's own RPCs are not in Core's table; [`SATD_CONVERT_PARAMS`] lists their
//! non-string arguments, read from their handlers in `node/src/rpc/server.rs`.
//! A method neither Core nor satd registers (an RPC added to a newer server
//! than this client) keeps the old guess: each argument is parsed as JSON and
//! sent as a string if that fails.

use serde_json::Value;

/// Core's `ParamFormat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Must parse as JSON; a parse failure is an error.
    Json,
    /// Always a string. Listed only so `-named` can tell that a positional
    /// string containing `=` is not a `name=value` pair.
    Str,
    /// JSON if it parses, else the raw string (`getblockstats <hash>`).
    JsonOrString,
}
use Format::{Json, JsonOrString, Str};

/// Core's `CRPCConvertParam`.
#[derive(Debug)]
pub struct Param {
    pub method: &'static str,
    pub idx: usize,
    pub name: &'static str,
    pub format: Format,
}

const fn p(method: &'static str, idx: usize, name: &'static str, format: Format) -> Param {
    Param {
        method,
        idx,
        name,
        format,
    }
}

/// Core v32.1 `vRPCConvertParams`, row for row and in Core's order (lookups
/// take the first match, as Core's `std::ranges::find_if` does).
#[rustfmt::skip]
pub static CORE_CONVERT_PARAMS: &[Param] = &[
    p("setmocktime", 0, "timestamp", Json),
    p("mockscheduler", 0, "delta_time", Json),
    p("utxoupdatepsbt", 0, "psbt", Str),
    p("utxoupdatepsbt", 1, "descriptors", Json),
    p("generatetoaddress", 0, "nblocks", Json),
    p("generatetoaddress", 2, "maxtries", Json),
    p("generatetodescriptor", 0, "num_blocks", Json),
    p("generatetodescriptor", 2, "maxtries", Json),
    p("generateblock", 1, "transactions", Json),
    p("generateblock", 2, "submit", Json),
    p("getnetworkhashps", 0, "nblocks", Json),
    p("getnetworkhashps", 1, "height", Json),
    p("sendtoaddress", 0, "address", Str),
    p("sendtoaddress", 1, "amount", Json),
    p("sendtoaddress", 2, "comment", Str),
    p("sendtoaddress", 3, "comment_to", Str),
    p("sendtoaddress", 4, "subtractfeefromamount", Json),
    p("sendtoaddress", 5, "replaceable", Json),
    p("sendtoaddress", 6, "conf_target", Json),
    p("sendtoaddress", 7, "estimate_mode", Str),
    p("sendtoaddress", 8, "avoid_reuse", Json),
    p("sendtoaddress", 9, "fee_rate", Json),
    p("sendtoaddress", 10, "verbose", Json),
    p("getreceivedbyaddress", 1, "minconf", Json),
    p("getreceivedbyaddress", 2, "include_immature_coinbase", Json),
    p("getreceivedbylabel", 0, "label", Str),
    p("getreceivedbylabel", 1, "minconf", Json),
    p("getreceivedbylabel", 2, "include_immature_coinbase", Json),
    p("listreceivedbyaddress", 0, "minconf", Json),
    p("listreceivedbyaddress", 1, "include_empty", Json),
    p("listreceivedbyaddress", 2, "include_watchonly", Json),
    p("listreceivedbyaddress", 4, "include_immature_coinbase", Json),
    p("listreceivedbylabel", 0, "minconf", Json),
    p("listreceivedbylabel", 1, "include_empty", Json),
    p("listreceivedbylabel", 2, "include_watchonly", Json),
    p("listreceivedbylabel", 3, "include_immature_coinbase", Json),
    p("getbalance", 1, "minconf", Json),
    p("getbalance", 2, "include_watchonly", Json),
    p("getbalance", 3, "avoid_reuse", Json),
    p("getblockfrompeer", 1, "peer_id", Json),
    p("getblockhash", 0, "height", Json),
    p("waitforblockheight", 0, "height", Json),
    p("waitforblockheight", 1, "timeout", Json),
    p("waitforblock", 1, "timeout", Json),
    p("waitfornewblock", 0, "timeout", Json),
    p("listtransactions", 0, "label", Str),
    p("listtransactions", 1, "count", Json),
    p("listtransactions", 2, "skip", Json),
    p("listtransactions", 3, "include_watchonly", Json),
    p("walletpassphrase", 0, "passphrase", Str),
    p("walletpassphrase", 1, "timeout", Json),
    p("getblocktemplate", 0, "template_request", Json),
    p("listsinceblock", 0, "blockhash", Str),
    p("listsinceblock", 1, "target_confirmations", Json),
    p("listsinceblock", 2, "include_watchonly", Json),
    p("listsinceblock", 3, "include_removed", Json),
    p("listsinceblock", 4, "include_change", Json),
    p("listsinceblock", 5, "label", Str),
    p("sendmany", 0, "dummy", Str),
    p("sendmany", 1, "amounts", Json),
    p("sendmany", 2, "minconf", Json),
    p("sendmany", 3, "comment", Str),
    p("sendmany", 4, "subtractfeefrom", Json),
    p("sendmany", 5, "replaceable", Json),
    p("sendmany", 6, "conf_target", Json),
    p("sendmany", 7, "estimate_mode", Str),
    p("sendmany", 8, "fee_rate", Json),
    p("sendmany", 9, "verbose", Json),
    p("deriveaddresses", 1, "range", Json),
    p("scanblocks", 1, "scanobjects", Json),
    p("scanblocks", 2, "start_height", Json),
    p("scanblocks", 3, "stop_height", Json),
    p("scanblocks", 5, "options", Json),
    p("scanblocks", 5, "filter_false_positives", Json),
    p("getdescriptoractivity", 0, "blockhashes", Json),
    p("getdescriptoractivity", 1, "scanobjects", Json),
    p("getdescriptoractivity", 2, "include_mempool", Json),
    p("scantxoutset", 1, "scanobjects", Json),
    p("createmultisig", 0, "nrequired", Json),
    p("createmultisig", 1, "keys", Json),
    p("listunspent", 0, "minconf", Json),
    p("listunspent", 1, "maxconf", Json),
    p("listunspent", 2, "addresses", Json),
    p("listunspent", 3, "include_unsafe", Json),
    p("listunspent", 4, "query_options", Json),
    p("listunspent", 4, "minimumAmount", Json),
    p("listunspent", 4, "maximumAmount", Json),
    p("listunspent", 4, "maximumCount", Json),
    p("listunspent", 4, "minimumSumAmount", Json),
    p("listunspent", 4, "include_immature_coinbase", Json),
    p("getblock", 1, "verbosity", Json),
    p("getblock", 1, "verbose", Json),
    p("getblockheader", 1, "verbose", Json),
    p("getchaintxstats", 0, "nblocks", Json),
    p("gettransaction", 1, "include_watchonly", Json),
    p("gettransaction", 2, "verbose", Json),
    p("getrawtransaction", 1, "verbosity", Json),
    p("getrawtransaction", 1, "verbose", Json),
    p("createrawtransaction", 0, "inputs", Json),
    p("createrawtransaction", 1, "outputs", Json),
    p("createrawtransaction", 2, "locktime", Json),
    p("createrawtransaction", 3, "replaceable", Json),
    p("createrawtransaction", 4, "version", Json),
    p("decoderawtransaction", 1, "iswitness", Json),
    p("signrawtransactionwithkey", 1, "privkeys", Json),
    p("signrawtransactionwithkey", 2, "prevtxs", Json),
    p("signrawtransactionwithwallet", 1, "prevtxs", Json),
    p("sendrawtransaction", 1, "maxfeerate", Json),
    p("sendrawtransaction", 2, "maxburnamount", Json),
    p("testmempoolaccept", 0, "rawtxs", Json),
    p("testmempoolaccept", 1, "maxfeerate", Json),
    p("submitpackage", 0, "package", Json),
    p("submitpackage", 1, "maxfeerate", Json),
    p("submitpackage", 2, "maxburnamount", Json),
    p("combinerawtransaction", 0, "txs", Json),
    p("fundrawtransaction", 1, "options", Json),
    p("fundrawtransaction", 1, "add_inputs", Json),
    p("fundrawtransaction", 1, "include_unsafe", Json),
    p("fundrawtransaction", 1, "minconf", Json),
    p("fundrawtransaction", 1, "maxconf", Json),
    p("fundrawtransaction", 1, "changePosition", Json),
    p("fundrawtransaction", 1, "includeWatching", Json),
    p("fundrawtransaction", 1, "lockUnspents", Json),
    p("fundrawtransaction", 1, "fee_rate", Json),
    p("fundrawtransaction", 1, "feeRate", Json),
    p("fundrawtransaction", 1, "subtractFeeFromOutputs", Json),
    p("fundrawtransaction", 1, "input_weights", Json),
    p("fundrawtransaction", 1, "conf_target", Json),
    p("fundrawtransaction", 1, "replaceable", Json),
    p("fundrawtransaction", 1, "solving_data", Json),
    p("fundrawtransaction", 1, "max_tx_weight", Json),
    p("fundrawtransaction", 2, "iswitness", Json),
    p("walletcreatefundedpsbt", 0, "inputs", Json),
    p("walletcreatefundedpsbt", 1, "outputs", Json),
    p("walletcreatefundedpsbt", 2, "locktime", Json),
    p("walletcreatefundedpsbt", 3, "options", Json),
    p("walletcreatefundedpsbt", 3, "add_inputs", Json),
    p("walletcreatefundedpsbt", 3, "include_unsafe", Json),
    p("walletcreatefundedpsbt", 3, "minconf", Json),
    p("walletcreatefundedpsbt", 3, "maxconf", Json),
    p("walletcreatefundedpsbt", 3, "changePosition", Json),
    p("walletcreatefundedpsbt", 3, "includeWatching", Json),
    p("walletcreatefundedpsbt", 3, "lockUnspents", Json),
    p("walletcreatefundedpsbt", 3, "fee_rate", Json),
    p("walletcreatefundedpsbt", 3, "feeRate", Json),
    p("walletcreatefundedpsbt", 3, "subtractFeeFromOutputs", Json),
    p("walletcreatefundedpsbt", 3, "conf_target", Json),
    p("walletcreatefundedpsbt", 3, "replaceable", Json),
    p("walletcreatefundedpsbt", 3, "solving_data", Json),
    p("walletcreatefundedpsbt", 3, "max_tx_weight", Json),
    p("walletcreatefundedpsbt", 4, "bip32derivs", Json),
    p("walletcreatefundedpsbt", 5, "version", Json),
    p("walletcreatefundedpsbt", 6, "psbt_version", Json),
    p("walletprocesspsbt", 0, "psbt", Str),
    p("walletprocesspsbt", 1, "sign", Json),
    p("walletprocesspsbt", 2, "sighashtype", Str),
    p("walletprocesspsbt", 3, "bip32derivs", Json),
    p("walletprocesspsbt", 4, "finalize", Json),
    p("descriptorprocesspsbt", 0, "psbt", Str),
    p("descriptorprocesspsbt", 1, "descriptors", Json),
    p("descriptorprocesspsbt", 2, "sighashtype", Str),
    p("descriptorprocesspsbt", 3, "bip32derivs", Json),
    p("descriptorprocesspsbt", 4, "finalize", Json),
    p("createpsbt", 0, "inputs", Json),
    p("createpsbt", 1, "outputs", Json),
    p("createpsbt", 2, "locktime", Json),
    p("createpsbt", 3, "replaceable", Json),
    p("createpsbt", 4, "version", Json),
    p("createpsbt", 5, "psbt_version", Json),
    p("combinepsbt", 0, "txs", Json),
    p("joinpsbts", 0, "txs", Json),
    p("finalizepsbt", 0, "psbt", Str),
    p("finalizepsbt", 1, "extract", Json),
    p("converttopsbt", 1, "permitsigdata", Json),
    p("converttopsbt", 2, "iswitness", Json),
    p("converttopsbt", 3, "psbt_version", Json),
    p("gettxout", 1, "n", Json),
    p("gettxout", 2, "include_mempool", Json),
    p("gettxoutproof", 0, "txids", Json),
    p("gettxoutsetinfo", 1, "hash_or_height", JsonOrString),
    p("gettxoutsetinfo", 2, "use_index", Json),
    p("dumptxoutset", 0, "path", Str),
    p("dumptxoutset", 1, "type", Str),
    p("dumptxoutset", 2, "options", Json),
    p("dumptxoutset", 2, "rollback", JsonOrString),
    p("dumptxoutset", 2, "in_memory", Json),
    p("lockunspent", 0, "unlock", Json),
    p("lockunspent", 1, "transactions", Json),
    p("lockunspent", 2, "persistent", Json),
    p("send", 0, "outputs", Json),
    p("send", 1, "conf_target", Json),
    p("send", 3, "fee_rate", Json),
    p("send", 4, "options", Json),
    p("send", 4, "add_inputs", Json),
    p("send", 4, "include_unsafe", Json),
    p("send", 4, "minconf", Json),
    p("send", 4, "maxconf", Json),
    p("send", 4, "add_to_wallet", Json),
    p("send", 4, "change_position", Json),
    p("send", 4, "fee_rate", Json),
    p("send", 4, "include_watching", Json),
    p("send", 4, "inputs", Json),
    p("send", 4, "locktime", Json),
    p("send", 4, "lock_unspents", Json),
    p("send", 4, "psbt", Json),
    p("send", 4, "subtract_fee_from_outputs", Json),
    p("send", 4, "conf_target", Json),
    p("send", 4, "replaceable", Json),
    p("send", 4, "solving_data", Json),
    p("send", 4, "max_tx_weight", Json),
    p("send", 5, "version", Json),
    p("sendall", 0, "recipients", Json),
    p("sendall", 1, "conf_target", Json),
    p("sendall", 3, "fee_rate", Json),
    p("sendall", 4, "options", Json),
    p("sendall", 4, "add_to_wallet", Json),
    p("sendall", 4, "fee_rate", Json),
    p("sendall", 4, "include_watching", Json),
    p("sendall", 4, "inputs", Json),
    p("sendall", 4, "locktime", Json),
    p("sendall", 4, "lock_unspents", Json),
    p("sendall", 4, "psbt", Json),
    p("sendall", 4, "send_max", Json),
    p("sendall", 4, "minconf", Json),
    p("sendall", 4, "maxconf", Json),
    p("sendall", 4, "conf_target", Json),
    p("sendall", 4, "replaceable", Json),
    p("sendall", 4, "solving_data", Json),
    p("sendall", 4, "version", Json),
    p("simulaterawtransaction", 0, "rawtxs", Json),
    p("simulaterawtransaction", 1, "options", Json),
    p("simulaterawtransaction", 1, "include_watchonly", Json),
    p("importmempool", 0, "filepath", Str),
    p("importmempool", 1, "options", Json),
    p("importmempool", 1, "apply_fee_delta_priority", Json),
    p("importmempool", 1, "use_current_time", Json),
    p("importmempool", 1, "apply_unbroadcast_set", Json),
    p("importdescriptors", 0, "requests", Json),
    p("listdescriptors", 0, "private", Json),
    p("verifychain", 0, "checklevel", Json),
    p("verifychain", 1, "nblocks", Json),
    p("getblockstats", 0, "hash_or_height", JsonOrString),
    p("getblockstats", 1, "stats", Json),
    p("pruneblockchain", 0, "height", Json),
    p("keypoolrefill", 0, "newsize", Json),
    p("getrawmempool", 0, "verbose", Json),
    p("getrawmempool", 1, "mempool_sequence", Json),
    p("getorphantxs", 0, "verbosity", Json),
    p("estimatesmartfee", 0, "conf_target", Json),
    p("estimatesmartfee", 2, "options", Json),
    p("estimaterawfee", 0, "conf_target", Json),
    p("estimaterawfee", 1, "threshold", Json),
    p("prioritisetransaction", 1, "dummy", Json),
    p("prioritisetransaction", 2, "fee_delta", Json),
    p("setban", 2, "bantime", Json),
    p("setban", 3, "absolute", Json),
    p("setnetworkactive", 0, "state", Json),
    p("setwalletflag", 1, "value", Json),
    p("getmempoolancestors", 1, "verbose", Json),
    p("getmempooldescendants", 1, "verbose", Json),
    p("gettxspendingprevout", 0, "outputs", Json),
    p("gettxspendingprevout", 1, "options", Json),
    p("gettxspendingprevout", 1, "mempool_only", Json),
    p("gettxspendingprevout", 1, "return_spending_tx", Json),
    p("bumpfee", 1, "options", Json),
    p("bumpfee", 1, "conf_target", Json),
    p("bumpfee", 1, "fee_rate", Json),
    p("bumpfee", 1, "replaceable", Json),
    p("bumpfee", 1, "outputs", Json),
    p("bumpfee", 1, "original_change_index", Json),
    p("psbtbumpfee", 1, "options", Json),
    p("psbtbumpfee", 1, "conf_target", Json),
    p("psbtbumpfee", 1, "fee_rate", Json),
    p("psbtbumpfee", 1, "replaceable", Json),
    p("psbtbumpfee", 1, "outputs", Json),
    p("psbtbumpfee", 1, "original_change_index", Json),
    p("psbtbumpfee", 1, "psbt_version", Json),
    p("logging", 0, "include", Json),
    p("logging", 1, "exclude", Json),
    p("disconnectnode", 1, "nodeid", Json),
    p("getopenrpcinfo", 0, "show_hidden", Json),
    p("gethdkeys", 0, "active_only", Json),
    p("gethdkeys", 0, "options", Json),
    p("gethdkeys", 0, "private", Json),
    p("derivehdkey", 1, "options", Json),
    p("derivehdkey", 1, "private", Json),
    p("createwalletdescriptor", 1, "options", Json),
    p("createwalletdescriptor", 1, "internal", Json),
    // Echo with conversion (For testing only)
    p("echojson", 0, "arg0", Json),
    p("echojson", 1, "arg1", Json),
    p("echojson", 2, "arg2", Json),
    p("echojson", 3, "arg3", Json),
    p("echojson", 4, "arg4", Json),
    p("echojson", 5, "arg5", Json),
    p("echojson", 6, "arg6", Json),
    p("echojson", 7, "arg7", Json),
    p("echojson", 8, "arg8", Json),
    p("echojson", 9, "arg9", Json),
    p("rescanblockchain", 0, "start_height", Json),
    p("rescanblockchain", 1, "stop_height", Json),
    p("createwallet", 0, "wallet_name", Str),
    p("createwallet", 1, "disable_private_keys", Json),
    p("createwallet", 2, "blank", Json),
    p("createwallet", 3, "passphrase", Str),
    p("createwallet", 4, "avoid_reuse", Json),
    p("createwallet", 5, "descriptors", Json),
    p("createwallet", 6, "load_on_startup", Json),
    p("createwallet", 7, "external_signer", Json),
    p("restorewallet", 0, "wallet_name", Str),
    p("restorewallet", 1, "backup_file", Str),
    p("restorewallet", 2, "load_on_startup", Json),
    p("loadwallet", 0, "filename", Str),
    p("loadwallet", 1, "load_on_startup", Json),
    p("unloadwallet", 0, "wallet_name", Str),
    p("unloadwallet", 1, "load_on_startup", Json),
    p("getnodeaddresses", 0, "count", Json),
    p("addpeeraddress", 1, "port", Json),
    p("addpeeraddress", 2, "tried", Json),
    p("sendmsgtopeer", 0, "peer_id", Json),
    p("stop", 0, "wait", Json),
    p("addnode", 2, "v2transport", Json),
    p("addconnection", 2, "v2transport", Json),
    p("decodepsbt", 0, "psbt", Str),
    p("analyzepsbt", 0, "psbt", Str),
    p("verifymessage", 1, "signature", Str),
    p("verifymessage", 2, "message", Str),
    p("getnewaddress", 0, "label", Str),
    p("getnewaddress", 1, "address_type", Str),
    p("backupwallet", 0, "destination", Str),
    p("echoipc", 0, "arg", Str),
    p("encryptwallet", 0, "passphrase", Str),
    p("getaddressesbylabel", 0, "label", Str),
    p("loadtxoutset", 0, "path", Str),
    p("migratewallet", 0, "wallet_name", Str),
    p("migratewallet", 1, "passphrase", Str),
    p("migratewallet", 2, "load_wallet", Json),
    p("setlabel", 1, "label", Str),
    p("signmessage", 1, "message", Str),
    p("signmessagewithprivkey", 1, "message", Str),
    p("walletpassphrasechange", 0, "oldpassphrase", Str),
    p("walletpassphrasechange", 1, "newpassphrase", Str),
];

/// satd's additions, for arguments Core's table does not cover. Each row is
/// a non-string argument of a satd-only RPC (or a satd name for a Core slot),
/// taken from the handler's typed read in `node/src/rpc/server.rs`, plus the
/// string arguments that may contain `=` (base64 signatures, free text,
/// paths), listed `Str` as Core does for its own.
#[rustfmt::skip]
pub static SATD_CONVERT_PARAMS: &[Param] = &[
    // `allowquarantined` shares Core's `maxfeerate` slot (positional calls
    // already convert through Core's row); this row is for `-named`.
    p("sendrawtransaction", 1, "allowquarantined", Json),
    // An address string, or an `{"address"|"scripthash": ...}` object.
    p("getaddressbalance", 0, "address", JsonOrString),
    p("getaddresshistory", 0, "address", JsonOrString),
    p("getaddressutxos", 0, "address", JsonOrString),
    p("estimatefees", 0, "targets", Json),
    p("estimatefees", 1, "mode", Str),
    p("getmempoolhistory", 0, "since_secs", Json),
    p("getmempoolsummary", 0, "top_n", Json),
    p("getpeerbehavior", 0, "peer_id", Json),
    p("getreorghistory", 0, "since_secs", Json),
    p("getsilentpaymentblockdata", 0, "blockhash", Str),
    p("getsilentpaymentblockdata", 1, "verbosity", Json),
    p("getsilentpaymentblockdata", 2, "dust_limit", Json),
    p("listquarantine", 0, "rule", Str),
    p("listquarantine", 1, "count", Json),
    p("listquarantine", 2, "skip", Json),
    p("stripopreturns", 0, "blockhash", Str),
    p("stripopreturns", 1, "threshold", Json),
    p("verifybip322", 0, "address", Str),
    p("verifybip322", 1, "signature", Str),
    p("verifybip322", 2, "message", Str),
    p("createnapattestation", 0, "outpoint", Str),
    p("createnapattestation", 1, "key", Str),
    p("createnapattestation", 2, "value", Str),
    p("createnapattestation", 3, "descriptor", Str),
    p("removenapattestation", 0, "outpoint", Str),
    p("removenapattestation", 1, "key", Str),
    p("submitnapattestation", 0, "message", Str),
    p("submitnapattestation", 1, "signature", Str),
    p("exportnapsnapshot", 0, "path", Str),
    p("replaynapsnapshot", 0, "path", Str),
];

/// Every RPC Core v32.1 defines, hidden ones included. A method here whose
/// arguments are not in [`CORE_CONVERT_PARAMS`] takes strings only.
#[rustfmt::skip]
pub static CORE_METHODS: &[&str] = &[
    "abandontransaction", "abortprivatebroadcast", "abortrescan", "addconnection", "addhdkey",
    "addnode", "addpeeraddress", "analyzepsbt", "backupwallet", "bumpfee", "clearbanned",
    "combinepsbt", "combinerawtransaction", "converttopsbt", "createmultisig", "createpsbt",
    "createrawtransaction", "createwallet", "createwalletdescriptor", "decodepsbt",
    "decoderawtransaction", "decodescript", "deriveaddresses", "derivehdkey",
    "descriptorprocesspsbt", "disconnectnode", "dumptxoutset", "echo", "echoipc", "echojson",
    "encryptwallet", "enumeratesigners", "estimaterawfee", "estimatesmartfee", "exportasmap",
    "exportwatchonlywallet", "finalizepsbt", "fundrawtransaction", "generate", "generateblock",
    "generatetoaddress", "generatetodescriptor", "getaddednodeinfo", "getaddressesbylabel",
    "getaddressinfo", "getaddrmaninfo", "getbalance", "getbalances", "getbestblockhash",
    "getblock", "getblockchaininfo", "getblockcount", "getblockfilter", "getblockfrompeer",
    "getblockhash", "getblockheader", "getblockstats", "getblocktemplate", "getchainstates",
    "getchaintips", "getchaintxstats", "getconnectioncount", "getdeploymentinfo",
    "getdescriptoractivity", "getdescriptorinfo", "getdifficulty", "gethdkeys", "getindexinfo",
    "getmemoryinfo", "getmempoolancestors", "getmempoolcluster", "getmempooldescendants",
    "getmempoolentry", "getmempoolfeeratediagram", "getmempoolinfo", "getmininginfo",
    "getnettotals", "getnetworkhashps", "getnetworkinfo", "getnewaddress", "getnodeaddresses",
    "getopenrpcinfo", "getorphantxs", "getpeerinfo", "getprioritisedtransactions",
    "getprivatebroadcastinfo", "getrawaddrman", "getrawchangeaddress", "getrawmempool",
    "getrawtransaction", "getreceivedbyaddress", "getreceivedbylabel", "getrpcinfo",
    "gettransaction", "gettxout", "gettxoutproof", "gettxoutsetinfo", "gettxspendingprevout",
    "getwalletinfo", "getzmqnotifications", "help", "importdescriptors", "importmempool",
    "importprunedfunds", "invalidateblock", "joinpsbts", "keypoolrefill", "listaddressgroupings",
    "listbanned", "listdescriptors", "listlabels", "listlockunspent", "listreceivedbyaddress",
    "listreceivedbylabel", "listsinceblock", "listtransactions", "listunspent", "listwalletdir",
    "listwallets", "loadtxoutset", "loadwallet", "lockunspent", "logging", "method", "method_name",
    "migratewallet", "mockscheduler", "ping", "preciousblock", "prioritisetransaction",
    "pruneblockchain", "psbtbumpfee", "reconsiderblock", "removeprunedfunds", "rescanblockchain",
    "restorewallet", "rpc.discover", "savemempool", "scanblocks", "scantxoutset", "send",
    "sendall", "sendmany", "sendmsgtopeer", "sendrawtransaction", "sendtoaddress", "setban",
    "setlabel", "setmocktime", "setnetworkactive", "setwalletflag", "signmessage",
    "signmessagewithprivkey", "signrawtransactionwithkey", "signrawtransactionwithwallet",
    "simulaterawtransaction", "stop", "submitblock", "submitheader", "submitpackage",
    "syncwithvalidationinterfacequeue", "testmempoolaccept", "unloadwallet", "uptime",
    "utxoupdatepsbt", "validateaddress", "verifychain", "verifymessage", "verifytxoutproof",
    "waitforblock", "waitforblockheight", "waitfornewblock", "walletcreatefundedpsbt",
    "walletdisplayaddress", "walletlock", "walletpassphrase", "walletpassphrasechange",
    "walletprocesspsbt",
];

/// satd's own RPCs (registered in `node/src/rpc/server.rs`, absent from
/// Core). Those not in [`SATD_CONVERT_PARAMS`] take strings only, or nothing:
/// `backfillindex`, `cancelindex`, `pauseindex`, `resumeindex`
/// (`index_name`), `getquarantineentry` (`txid`), `policytest` (`rawtx`).
#[rustfmt::skip]
pub static SATD_METHODS: &[&str] = &[
    "backfillindex", "cancelindex", "createnapattestation", "estimatefees", "exportnapsnapshot",
    "getaddressbalance", "getaddresshistory", "getaddressutxos", "getblockfileaudit", "getconfig",
    "getibdprogress", "getmempoolhistory", "getmempoolsummary", "getnapreport",
    "getopreturnpruneinfo", "getorphaninfo", "getpeerbehavior", "getpolicyinfo", "getquarantineentry",
    "getquarantineinfo", "getreorghistory", "getsatdindexinfo", "getserverstatus",
    "getsilentpaymentblockdata", "getstoragefootprint", "getstratuminfo", "getsysteminfo",
    "getwarnings", "listnapaggregate", "listnapattestations", "listquarantine", "pauseindex",
    "policytest", "removenapattestation", "replaynapsnapshot", "resumeindex", "stripopreturns",
    "submitnapattestation", "subscribemempool", "unsubscribemempool", "verifybip322",
];

/// Whether this client knows the method's argument types. An unknown method
/// falls back to guessing each argument's type from its text.
fn known(method: &str) -> bool {
    CORE_METHODS.contains(&method) || SATD_METHODS.contains(&method)
}

fn rows() -> impl Iterator<Item = &'static Param> {
    CORE_CONVERT_PARAMS.iter().chain(SATD_CONVERT_PARAMS)
}

/// Core's `rpc_convert::FromPosition`. For an unknown method, every slot is
/// `JsonOrString`: the pre-table guess.
fn from_position(method: &str, pos: usize) -> Option<Format> {
    if !known(method) {
        return Some(JsonOrString);
    }
    rows().find(|p| p.method == method && p.idx == pos).map(|p| p.format)
}

/// Core's `rpc_convert::FromName`.
fn from_name(method: &str, name: &str) -> Option<Format> {
    if !known(method) {
        return Some(JsonOrString);
    }
    rows().find(|p| p.method == method && p.name == name).map(|p| p.format)
}

/// Core's `Parse`: JSON, or for `JsonOrString` the raw string if it does not
/// parse. The error text is Core's.
fn parse(raw: &str, format: Format) -> Result<Value, String> {
    match serde_json::from_str::<Value>(raw) {
        Ok(v) => Ok(v),
        Err(_) if format == JsonOrString => Ok(Value::String(raw.to_string())),
        Err(_) => Err(format!("Error parsing JSON: {raw}")),
    }
}

/// Core's `ParseParam`: only listed `Json`/`JsonOrString` arguments are
/// parsed; everything else is the string as typed.
fn parse_param(format: Option<Format>, raw: &str) -> Result<Value, String> {
    match format {
        Some(f @ (Json | JsonOrString)) => parse(raw, f),
        _ => Ok(Value::String(raw.to_string())),
    }
}

/// Core's `RPCConvertValues`: positional arguments to a params array.
pub fn convert_values(method: &str, args: &[String]) -> Result<Value, String> {
    let mut params = Vec::with_capacity(args.len());
    for s in args {
        params.push(parse_param(from_position(method, params.len()), s)?);
    }
    Ok(Value::Array(params))
}

/// Core's `RPCConvertNamedValues`: `-named` arguments to a params object,
/// returned as serialized JSON.
///
/// An argument without `=` is positional and goes, in order, into the
/// reserved `args` key. One with `=` is `name=value`, except that when the
/// name is not one the method declares and the next positional slot takes a
/// string (or JSON, and the whole argument parses), the whole argument fills
/// that slot instead: `createwallet my=wallet`. A repeated name keeps its
/// first position and takes the later value.
///
/// Returned as text rather than a `Value` because Core appends the implicit
/// `args` with `pushKVEnd`, which does not replace an explicit `args=` given
/// on the command line: the request then carries both keys and the server
/// decides. A JSON map cannot hold a key twice.
pub fn convert_named_values(method: &str, args: &[String]) -> Result<String, String> {
    let mut params: Vec<(String, Value)> = Vec::new();
    let mut positional: Vec<Value> = Vec::new();

    for s in args {
        let Some((name, value)) = s.split_once('=') else {
            positional.push(parse_param(from_position(method, positional.len()), s)?);
            continue;
        };

        let named = from_name(method, name);
        if named.is_none() {
            match from_position(method, positional.len()) {
                Some(Json) => {
                    if let Ok(v) = serde_json::from_str::<Value>(s) {
                        positional.push(v);
                        continue;
                    }
                }
                Some(Str) => {
                    positional.push(Value::String(s.clone()));
                    continue;
                }
                _ => {}
            }
        }

        // Core's `pushKV`: a later value for a name overwrites the earlier
        // one in place.
        let v = parse_param(named, value)?;
        match params.iter_mut().find(|(k, _)| k == name) {
            Some(slot) => slot.1 = v,
            None => params.push((name.to_string(), v)),
        }
    }

    if !positional.is_empty() {
        params.push(("args".to_string(), Value::Array(positional)));
    }

    let mut out = String::from("{");
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&Value::String(k.clone()).to_string());
        out.push(':');
        out.push_str(&v.to_string());
    }
    out.push('}');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn positional(method: &str, a: &[&str]) -> Value {
        convert_values(method, &args(a)).unwrap()
    }

    /// The serialized `-named` params, compared as text: Core's request can
    /// carry `args` twice, which a parsed `Value` would hide.
    fn named(method: &str, a: &[&str]) -> String {
        convert_named_values(method, &args(a)).unwrap()
    }

    // Every expectation below is the `params` that `bitcoin-cli` v32.1 sent
    // for the same command line, captured from its HTTP request.

    #[test]
    fn unlisted_arguments_stay_strings() {
        // #1268: the message was sent as the number 123 and the node
        // answered -3.
        assert_eq!(
            positional("signmessagewithprivkey", &["cVpF924E", "123"]),
            json!(["cVpF924E", "123"])
        );
        assert_eq!(positional("signmessagewithprivkey", &["k", "true"]), json!(["k", "true"]));
        assert_eq!(positional("signmessagewithprivkey", &["k", "null"]), json!(["k", "null"]));
        assert_eq!(positional("verifymessage", &["a", "s", "true"]), json!(["a", "s", "true"]));
        // A hex string that happens to be all digits.
        assert_eq!(positional("decodescript", &["5151"]), json!(["5151"]));
        assert_eq!(positional("getrawtransaction", &["ab", "1", "00cd"]), json!(["ab", 1, "00cd"]));
        // Core's `echo` has no conversion; `echojson` converts everything.
        assert_eq!(
            positional("echo", &["1", "true", "null", r#"{"a":1}"#, "", " 1 "]),
            json!(["1", "true", "null", r#"{"a":1}"#, "", " 1 "])
        );
    }

    #[test]
    fn listed_arguments_convert() {
        assert_eq!(positional("getblockhash", &["100"]), json!([100]));
        assert_eq!(positional("getblock", &["00ab", "2"]), json!(["00ab", 2]));
        assert_eq!(positional("getblockheader", &["ab", "false"]), json!(["ab", false]));
        assert_eq!(positional("decoderawtransaction", &["0100", "true"]), json!(["0100", true]));
        assert_eq!(
            positional("createrawtransaction", &["[]", r#"{"data":"00"}"#, "0", "true"]),
            json!([[], {"data": "00"}, 0, true])
        );
        assert_eq!(
            positional("setban", &["1.2.3.4", "add", "100", "true"]),
            json!(["1.2.3.4", "add", 100, true])
        );
        assert_eq!(positional("testmempoolaccept", &[r#"["00"]"#, "0.1"]), json!([["00"], 0.1]));
        assert_eq!(positional("estimatesmartfee", &["6", "economical"]), json!([6, "economical"]));
        assert_eq!(
            positional("getblocktemplate", &[r#"{"rules":["segwit"]}"#]),
            json!([{"rules": ["segwit"]}])
        );
        assert_eq!(
            positional("echojson", &["1", "true", "null", r#"{"a":1}"#]),
            json!([1, true, null, {"a": 1}])
        );
        // Amounts keep their digits (serde_json's `arbitrary_precision`).
        assert_eq!(
            positional("sendrawtransaction", &["00", "0.10000000"]).to_string(),
            r#"["00",0.10000000]"#
        );
    }

    #[test]
    fn json_or_string_falls_back() {
        assert_eq!(positional("getblockstats", &["100"]), json!([100]));
        assert_eq!(positional("getblockstats", &["0000abcd"]), json!(["0000abcd"]));
        assert_eq!(positional("getblockstats", &[r#""0000abcd""#]), json!(["0000abcd"]));
        assert_eq!(positional("gettxoutsetinfo", &["muhash", "100"]), json!(["muhash", 100]));
    }

    #[test]
    fn listed_json_that_does_not_parse_is_an_error() {
        let err = convert_values("createrawtransaction", &args(&["[]", "notjson"])).unwrap_err();
        assert_eq!(err, "Error parsing JSON: notjson");
        assert_eq!(
            convert_values("sendrawtransaction", &args(&["00", ""])).unwrap_err(),
            "Error parsing JSON: "
        );
        assert_eq!(
            convert_named_values("getblock", &args(&["blockhash=00ab", "verbosity=x"]))
                .unwrap_err(),
            "Error parsing JSON: x"
        );
    }

    #[test]
    fn named_values_convert_by_name() {
        // #1268: `label=123` was sent as a number.
        assert_eq!(named("getnewaddress", &["label=123"]), r#"{"label":"123"}"#);
        assert_eq!(
            named("signmessagewithprivkey", &["privkey=k", "message=123"]),
            r#"{"privkey":"k","message":"123"}"#
        );
        assert_eq!(
            named("getblock", &["blockhash=00ab", "verbosity=2"]),
            r#"{"blockhash":"00ab","verbosity":2}"#
        );
        // The alias row converts too.
        assert_eq!(
            named("getblock", &["blockhash=00ab", "verbose=true"]),
            r#"{"blockhash":"00ab","verbose":true}"#
        );
        assert_eq!(
            named("getnetworkhashps", &["nblocks=120", "height=-1"]),
            r#"{"nblocks":120,"height":-1}"#
        );
        assert_eq!(
            named("getblocktemplate", &[r#"template_request={"rules":["segwit"]}"#]),
            r#"{"template_request":{"rules":["segwit"]}}"#
        );
        assert_eq!(named("echo", &["arg0=1", "arg1=true"]), r#"{"arg0":"1","arg1":"true"}"#);
        assert_eq!(named("echo", &["a=b=c"]), r#"{"a":"b=c"}"#);
        assert_eq!(named("echo", &["=x"]), r#"{"":"x"}"#);
    }

    #[test]
    fn named_positionals_go_to_args() {
        assert_eq!(named("getnewaddress", &["123"]), r#"{"args":["123"]}"#);
        assert_eq!(named("getblock", &["00ab"]), r#"{"args":["00ab"]}"#);
        assert_eq!(named("echojson", &["x=1", "2"]), r#"{"x":"1","args":[2]}"#);
        // An unknown name before a string slot is the whole positional string.
        assert_eq!(named("getnewaddress", &["a=b"]), r#"{"args":["a=b"]}"#);
        assert_eq!(named("createwallet", &["my=wallet"]), r#"{"args":["my=wallet"]}"#);
        // ...and before a JSON slot, if the whole argument parses.
        assert_eq!(
            named("createrawtransaction", &[r#"[{"txid":"a=b"}]"#]),
            r#"{"args":[[{"txid":"a=b"}]]}"#
        );
    }

    #[test]
    fn named_repeats_overwrite_and_explicit_args_is_kept() {
        assert_eq!(
            named("getblock", &["00ab", "verbosity=1", "verbosity=2"]),
            r#"{"verbosity":2,"args":["00ab"]}"#
        );
        // Core's `pushKVEnd`: both keys go to the server.
        assert_eq!(
            named("getblock", &["00ab", r#"args=["x"]"#]),
            r#"{"args":"[\"x\"]","args":["00ab"]}"#
        );
    }

    #[test]
    fn satd_rpcs_convert_by_their_own_rows() {
        assert_eq!(positional("getreorghistory", &["3600"]), json!([3600]));
        assert_eq!(positional("listquarantine", &["123", "5", "0"]), json!(["123", 5, 0]));
        assert_eq!(positional("estimatefees", &["[1,6]", "economy"]), json!([[1, 6], "economy"]));
        assert_eq!(positional("getaddressbalance", &["bcrt1qxyz"]), json!(["bcrt1qxyz"]));
        assert_eq!(
            positional("getaddressbalance", &[r#"{"scripthash":"00"}"#]),
            json!([{"scripthash": "00"}])
        );
        assert_eq!(
            positional("verifybip322", &["a", "AkcwRA==", "123"]),
            json!(["a", "AkcwRA==", "123"])
        );
        // A satd RPC with string arguments only.
        assert_eq!(positional("getquarantineentry", &["0011"]), json!(["0011"]));
        // The Operator Manual's `sendrawtransaction hexstring allowquarantined=true`.
        assert_eq!(
            named("sendrawtransaction", &["hexstring=00", "allowquarantined=true"]),
            r#"{"hexstring":"00","allowquarantined":true}"#
        );
        // A base64 signature with `=` padding is not split (the Operator
        // Manual's example).
        assert_eq!(
            named("verifybip322", &["addr", "AkcwRA==", "message=hi"]),
            r#"{"message":"hi","args":["addr","AkcwRA=="]}"#
        );
        assert_eq!(
            named("submitnapattestation", &["00", "AkcwRA=="]),
            r#"{"args":["00","AkcwRA=="]}"#
        );
    }

    #[test]
    fn unknown_methods_keep_the_guess() {
        assert_eq!(positional("notarealrpc", &["1", "true", "x"]), json!([1, true, "x"]));
        assert_eq!(named("notarealrpc", &["a=1", "b=x", "5"]), r#"{"a":1,"b":"x","args":[5]}"#);
    }

    #[test]
    fn tables_are_consistent() {
        for p in CORE_CONVERT_PARAMS {
            assert!(
                CORE_METHODS.contains(&p.method),
                "{} has a Core row but is not a Core method",
                p.method
            );
        }
        for p in SATD_CONVERT_PARAMS {
            assert!(known(p.method), "{} has a satd row but is not a known method", p.method);
        }
        for m in SATD_METHODS {
            assert!(!CORE_METHODS.contains(m), "{m} is listed as satd-only but Core has it");
        }
    }

    /// The server's named-parameter table, `node/src/rpc/named_params.rs`,
    /// lists every RPC satd registers (a startup audit enforces it). Each must
    /// be known here, or `sat-cli` would guess its argument types.
    fn named_params_source() -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/rpc/named_params.rs");
        std::fs::read_to_string(path).unwrap()
    }

    fn quoted(s: &str) -> Vec<&str> {
        s.split('"').skip(1).step_by(2).collect()
    }

    #[test]
    fn every_satd_rpc_is_known() {
        let src = named_params_source();
        let start = src
            .find("const ALL_METHODS: &[&str] = &[")
            .expect("ALL_METHODS in named_params.rs");
        let block = &src[start..];
        let block = &block[..block.find("];").unwrap()];
        let methods = quoted(block);
        assert!(methods.len() > 100, "parsed only {} methods", methods.len());
        let unknown: Vec<_> = methods.into_iter().filter(|m| !known(m)).collect();
        assert!(
            unknown.is_empty(),
            "add these to SATD_METHODS (and their non-string arguments to \
             SATD_CONVERT_PARAMS): {unknown:?}"
        );
    }

    /// A satd row's index and name must match the server's own table, or a
    /// positional and a named call would convert different arguments.
    #[test]
    fn satd_rows_match_the_server_names() {
        let src = named_params_source();
        for p in SATD_CONVERT_PARAMS {
            let key = format!("\"{}\" => &[", p.method);
            let at = src
                .find(&key)
                .unwrap_or_else(|| panic!("{} missing from named_params.rs", p.method));
            let row = &src[at + key.len()..];
            let row = &row[..row.find("],").unwrap()];
            let names = quoted(row);
            let declared = names
                .get(p.idx)
                .unwrap_or_else(|| panic!("{} has no slot {}", p.method, p.idx));
            assert!(
                declared.split('|').any(|n| n == p.name),
                "{} slot {} is {declared:?} on the server, {:?} here",
                p.method,
                p.idx,
                p.name
            );
        }
    }
}
