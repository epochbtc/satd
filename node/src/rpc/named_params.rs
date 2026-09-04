//! Core-compatible named JSON-RPC parameters.
//!
//! Bitcoin Core accepts a JSON *object* as a request's `params` and maps it
//! onto the method's declared positional arguments. satd's handlers all read
//! `params.sequence()` / `params.one()`, which require an array, so without a
//! translation step an object `params` fails on **every** method — including
//! for clients that have no positional option. Core's own functional-test
//! framework is one of those clients: `authproxy` sends an object the moment
//! any keyword argument is used, so the very first thing it does (building the
//! shared 199-block chain via `generatetoaddress(nblocks=…, address=…)`)
//! cannot run against satd at all.
//!
//! This module rewrites object `params` into the positional array the handlers
//! expect, before dispatch, so the handlers stay untouched.
//!
//! ## Fidelity
//!
//! [`named_to_positional`] is a direct port of Core's
//! `transformNamedArguments` (`src/rpc/server.cpp`), including the parts that
//! are easy to miss:
//!
//! * **Aliases.** A declared name may carry `|`-separated alternatives
//!   (`verbosity|verbose`); the first one present wins, and a second spelling
//!   of the same argument is then reported as unknown, exactly as Core does.
//! * **Holes.** Arguments left unspecified *before* a specified one become
//!   explicit JSON nulls; trailing ones are simply not emitted, because many
//!   handlers branch on how many arguments arrived.
//! * **Named-only arguments.** An `OBJ_NAMED_PARAMS` argument contributes one
//!   entry per *field*, marked named-only, ahead of an ordinary entry for the
//!   container. Callers name the fields at the top level and Core gathers them
//!   into an options object occupying the container's position — or names the
//!   container directly, which is why supplying both is a reported conflict.
//! * **The `args` escape hatch.** A client may mix forms by passing an `args`
//!   array of leading positional values alongside named ones.
//!
//! ## The table is the risk
//!
//! A wrong or missing name does not fail loudly — it binds a value to the
//! wrong position, which is worse than today's outright rejection. So the
//! table below is *generated* from Core's own `RPCHelpMan` argument
//! declarations at the pinned release rather than transcribed by hand, and
//! cross-checked against the independent `(method, index, name)` triples in
//! Core's `src/rpc/client.cpp`. satd-only methods take the parameter names the
//! Operator Manual already documents for them.
//!
//! `contrib/core-functional/gen-named-params.py` is the generator;
//! `--check` fails if this table has drifted from the pinned Core, and CI runs
//! it, so a pin bump that reorders an argument breaks the build rather than
//! quietly binding values to the wrong positions.
//!
//! Every registered method has a row, including the ones that take no
//! arguments: an empty row is what produces Core's "Unknown named parameter"
//! for a method that accepts none. A startup audit in
//! [`crate::rpc::server::start`] fails debug builds if a registered method is
//! missing from the table.
//!
//! An empty row therefore has to mean "takes no arguments", never "we did not
//! look". Seven satd-only RPCs that each take one required argument shipped
//! with `&[]` because the generator defaulted any method Core did not declare,
//! and every guard agreed: `--check` compared the generated `[]` against the
//! committed `[]`, and the startup audit only asserts a row *exists*. Their
//! named form was unusable, with no name that worked. The generator now fails
//! on a satd-registered method that is in neither Core nor its own
//! `SATD_ONLY` list, so an empty row is a decision someone made rather than a
//! default nobody saw.

use std::future::Future;

use jsonrpsee::server::middleware::rpc::{Batch, BatchEntry, Notification, RpcServiceT};
use jsonrpsee::server::{BatchResponseBuilder, MethodResponse};
use jsonrpsee::types::{ErrorObjectOwned, Request};
use serde_json::{Map, Value};

use crate::rpc::readonly::RESPONSE_BODY_LIMIT;

/// Core's `RPC_INVALID_PARAMETER`. Every failure in this module is a
/// caller-side naming mistake, which is the code Core reports for all of them.
const RPC_INVALID_PARAMETER: i32 = -8;

/// A declared parameter: its name pattern (`|`-separated aliases, spelled as
/// Core spells them) and whether it is named-only (`OBJ_NAMED_PARAMS`).
pub type ArgSpec = (&'static str, bool);

fn invalid(msg: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(RPC_INVALID_PARAMETER, msg, None::<()>)
}

/// Declared arguments for `method`, or `None` if satd does not register it.
///
/// `None` means "not ours" and the request is passed through untouched so
/// jsonrpsee can answer with its own method-not-found.
/// Names satd adds as an alias on a Core argument slot, from the generator's
/// `SATD_SLOT_ALIASES` (`contrib/core-functional/gen-named-params.py`), which is
/// the source of truth. Core has no behaviour to match for these names, so a
/// collision with the Core spelling is reported as a conflict rather than as an
/// unknown parameter. `satd_slot_aliases_are_really_aliases` keeps this honest.
const SATD_SLOT_ALIASES: &[&str] = &["allowquarantined"];

pub fn arg_names(method: &str) -> Option<&'static [ArgSpec]> {
    let args: &'static [ArgSpec] = match method {
        "addnode" => &[("node", false), ("command", false), ("v2transport", false)],
        "analyzepsbt" => &[("psbt", false)],
        "backfillindex" => &[("index_name", false)],
        "cancelindex" => &[("index_name", false)],
        "clearbanned" => &[],
        "combinepsbt" => &[("txs", false)],
        "combinerawtransaction" => &[("txs", false)],
        "converttopsbt" => &[("hexstring", false), ("permitsigdata", false), ("iswitness", false)],
        "createpsbt" => &[("inputs", false), ("outputs", false), ("locktime", false), ("replaceable", false), ("version", false)],
        "createrawtransaction" => &[("inputs", false), ("outputs", false), ("locktime", false), ("replaceable", false), ("version", false)],
        "decodepsbt" => &[("psbt", false)],
        "decoderawtransaction" => &[("hexstring", false), ("iswitness", false)],
        "decodescript" => &[("hexstring", false)],
        "disconnectnode" => &[("address", false), ("nodeid", false)],
        "dumptxoutset" => &[("path", false), ("type", false), ("rollback", true), ("options", false)],
        "echo" => &[("arg0", false), ("arg1", false), ("arg2", false), ("arg3", false), ("arg4", false), ("arg5", false), ("arg6", false), ("arg7", false), ("arg8", false), ("arg9", false)],
        "echojson" => &[("arg0", false), ("arg1", false), ("arg2", false), ("arg3", false), ("arg4", false), ("arg5", false), ("arg6", false), ("arg7", false), ("arg8", false), ("arg9", false)],
        "estimatefees" => &[("targets", false), ("mode", false)],
        "estimatesmartfee" => &[("conf_target", false), ("estimate_mode", false)],
        "finalizepsbt" => &[("psbt", false), ("extract", false)],
        "generate" => &[],
        "generateblock" => &[("output", false), ("transactions", false), ("submit", false)],
        "generatetoaddress" => &[("nblocks", false), ("address", false), ("maxtries", false)],
        "generatetodescriptor" => &[("num_blocks", false), ("descriptor", false), ("maxtries", false)],
        "getaddednodeinfo" => &[("node", false)],
        "getaddressbalance" => &[("address", false)],
        "getaddresshistory" => &[("address", false)],
        "getaddressutxos" => &[("address", false)],
        "getbestblockhash" => &[],
        "getblock" => &[("blockhash", false), ("verbosity|verbose", false)],
        "getblockchaininfo" => &[],
        "getblockcount" => &[],
        "getblockfileaudit" => &[],
        "getblockfilter" => &[("blockhash", false), ("filtertype", false)],
        "getblockfrompeer" => &[("blockhash", false), ("peer_id", false)],
        "getblockhash" => &[("height", false)],
        "getblockheader" => &[("blockhash", false), ("verbose", false)],
        "getblockstats" => &[("hash_or_height", false), ("stats", false)],
        "getblocktemplate" => &[("template_request", false)],
        "getchainstates" => &[],
        "getchaintips" => &[],
        "getchaintxstats" => &[("nblocks", false), ("blockhash", false)],
        "getconfig" => &[],
        "getconnectioncount" => &[],
        "getdeploymentinfo" => &[("blockhash", false)],
        "getdifficulty" => &[],
        "getibdprogress" => &[],
        "getindexinfo" => &[("index_name", false)],
        "getmemoryinfo" => &[("mode", false)],
        "getmempoolancestors" => &[("txid", false), ("verbose", false)],
        "getmempooldescendants" => &[("txid", false), ("verbose", false)],
        "getmempoolentry" => &[("txid", false)],
        "getmempoolhistory" => &[("since_secs", false)],
        "getmempoolinfo" => &[],
        "getmininginfo" => &[],
        "getnettotals" => &[],
        "getnetworkhashps" => &[("nblocks", false), ("height", false)],
        "getnetworkinfo" => &[],
        "getorphaninfo" => &[],
        "getpeerinfo" => &[],
        "getpolicyinfo" => &[],
        "getprioritisedtransactions" => &[],
        "getquarantineentry" => &[("txid", false)],
        "getquarantineinfo" => &[],
        "getrawmempool" => &[("verbose", false), ("mempool_sequence", false)],
        "getrawtransaction" => &[("txid", false), ("verbosity|verbose", false), ("blockhash", false)],
        "getreorghistory" => &[("since_secs", false)],
        "getrpcinfo" => &[],
        "getserverstatus" => &[],
        "getsilentpaymentblockdata" => &[("blockhash", false), ("verbosity", false), ("dust_limit", false)],
        "getsysteminfo" => &[],
        "gettxout" => &[("txid", false), ("n", false), ("include_mempool", false)],
        "gettxoutproof" => &[("txids", false), ("blockhash", false)],
        "gettxoutsetinfo" => &[("hash_type", false), ("hash_or_height", false), ("use_index", false)],
        "getwarnings" => &[],
        "help" => &[("command", false)],
        "invalidateblock" => &[("blockhash", false)],
        "joinpsbts" => &[("txs", false)],
        "listbanned" => &[],
        "listquarantine" => &[("rule", false), ("count", false), ("skip", false)],
        "loadtxoutset" => &[("path", false)],
        "logging" => &[("include", false), ("exclude", false)],
        "pauseindex" => &[("index_name", false)],
        "ping" => &[],
        "policytest" => &[("rawtx", false)],
        "preciousblock" => &[("blockhash", false)],
        "prioritisetransaction" => &[("txid", false), ("dummy", false), ("fee_delta", false)],
        "reconsiderblock" => &[("blockhash", false)],
        "resumeindex" => &[("index_name", false)],
        "savemempool" => &[],
        "scantxoutset" => &[("action", false), ("scanobjects", false)],
        "sendrawtransaction" => &[("hexstring", false), ("maxfeerate|allowquarantined", false), ("maxburnamount", false)],
        "setban" => &[("subnet", false), ("command", false), ("bantime", false), ("absolute", false)],
        "setmocktime" => &[("timestamp", false)],
        "setnetworkactive" => &[("state", false)],
        "signrawtransactionwithkey" => &[("hexstring", false), ("privkeys", false), ("prevtxs", false), ("sighashtype", false)],
        "stop" => &[("wait", false)],
        "submitblock" => &[("hexdata", false), ("dummy", false)],
        "submitheader" => &[("hexdata", false)],
        "submitpackage" => &[("package", false), ("maxfeerate", false), ("maxburnamount", false)],
        "subscribemempool" => &[],
        "syncwithvalidationinterfacequeue" => &[],
        "testmempoolaccept" => &[("rawtxs", false), ("maxfeerate", false)],
        "unsubscribemempool" => &[],
        "uptime" => &[],
        "utxoupdatepsbt" => &[("psbt", false), ("descriptors", false)],
        "validateaddress" => &[("address", false)],
        "verifychain" => &[("checklevel", false), ("nblocks", false)],
        "verifytxoutproof" => &[("proof", false)],
        "waitforblock" => &[("blockhash", false), ("timeout", false)],
        "waitforblockheight" => &[("height", false), ("timeout", false)],
        "waitfornewblock" => &[("timeout", false), ("current_tip", false)],
        _ => return None,
    };
    Some(args)
}

/// Map an object `params` onto `method`'s positional arguments.
///
/// A direct port of Core's `transformNamedArguments`; see the module docs for
/// the behaviours being preserved. Returns the positional array, or the same
/// `-8` error Core would return for an unknown, conflicting or doubly-supplied
/// name.
///
/// One knowing divergence: Core reports `Parameter x specified multiple times`
/// for a JSON object that repeats a key, because UniValue retains duplicates.
/// `serde_json` collapses them on parse (last value wins), so that particular
/// message is unreachable here. Both implementations accept the request; only
/// the reading of a malformed object differs.
pub fn named_to_positional(
    specs: &[ArgSpec],
    params: Map<String, Value>,
) -> Result<Vec<Value>, ErrorObjectOwned> {
    // By value: both callers own the map and drop it immediately after, so a
    // clone here only doubled peak memory. `max_request_body_size` is 10 MiB by
    // default, and a body of nothing but array elements expands to an order of
    // magnitude more `Value` tree than that -- duplicated, once per concurrent
    // connection, for nothing.
    let mut args_in = params;
    let mut out: Vec<Value> = Vec::with_capacity(specs.len());

    // Unspecified arguments sitting *before* a specified one have to be
    // materialised as nulls to keep later arguments at the right index.
    // `hole` counts how many are pending; they are only flushed once
    // something after them turns up, so trailing gaps stay absent.
    let mut hole: usize = 0;
    let mut initial_hole_size: usize = 0;
    let mut initial_param: Option<&str> = None;
    let mut options = Map::new();

    for (pattern, named_only) in specs {
        // First alias that the caller actually used.
        let key = pattern
            .split('|')
            .find(|alias| args_in.contains_key(*alias))
            .map(str::to_string);

        // A pattern's aliases are alternative spellings of ONE slot, so two of
        // them cannot both be honoured; rejecting is right either way. What
        // differs is the message.
        //
        // For two *Core* spellings, Core resolves the first and leaves the
        // other to fall out below as "Unknown named parameter". That is Core's
        // observable behaviour and satd matches it exactly.
        //
        // A satd extension sharing a Core slot is a different case: the name
        // does not exist in Core, so there is no behaviour to match, and
        // "unknown parameter" would send an operator hunting for a spelling
        // that works when the real problem is that `maxfeerate` and
        // `allowquarantined` are one argument.
        if let Some(chosen) = &key
            && let Some(other) = pattern
                .split('|')
                .find(|a| a != chosen && args_in.contains_key(*a))
            && (SATD_SLOT_ALIASES.contains(&other) || SATD_SLOT_ALIASES.contains(&chosen.as_str()))
        {
            return Err(invalid(format!(
                "Parameter {other} conflicts with parameter {chosen}: satd's \
                 {other} and Core's {chosen} are the same argument"
            )));
        }

        if *named_only {
            // Not addressable itself: its fields were lifted to the top level
            // and are re-gathered into an options object below.
            if let Some(k) = key {
                let v = args_in.remove(&k).expect("key came from args_in");
                if options.insert(k.clone(), v).is_some() {
                    return Err(invalid(format!("Parameter {k} specified multiple times")));
                }
            }
            continue;
        }

        if !options.is_empty() || key.is_some() {
            for _ in 0..hole {
                out.push(Value::Null);
            }
            hole = 0;
            if initial_param.is_none() {
                initial_param = Some(pattern);
            }
        } else {
            hole += 1;
            if out.is_empty() {
                initial_hole_size = hole;
            }
        }

        if let Some(k) = &key {
            if let Some(first) = options.keys().next() {
                return Err(invalid(format!(
                    "Parameter {k} conflicts with parameter {first}"
                )));
            }
            out.push(args_in.remove(k).expect("key came from args_in"));
        }
        if !options.is_empty() {
            out.push(Value::Object(std::mem::take(&mut options)));
        }
    }

    // `args` supplies leading positional values that named ones follow. Core
    // removes the key whatever its type, so a non-array `args` is dropped
    // rather than reported as unknown; mirror that.
    // `remove` runs whatever the value's type, so a non-array `args` is
    // dropped by this match rather than falling through to the unknown-name
    // check below -- which is what Core does with it too.
    if let Some(Value::Array(positional)) = args_in.remove("args") {
        if initial_hole_size < positional.len()
            && let Some(dup) = initial_param
        {
            return Err(invalid(format!(
                "Parameter {dup} specified twice both as positional and named argument"
            )));
        }
        let named = out;
        out = positional;
        for v in named.into_iter().skip(out.len()) {
            out.push(v);
        }
    }

    if let Some(unknown) = args_in.keys().next() {
        return Err(invalid(format!("Unknown named parameter {unknown}")));
    }

    Ok(out)
}

/// Rewrite a request's `params` in place when it arrived as an object.
///
/// Leaves array (and absent) params untouched, and leaves unknown methods
/// alone so jsonrpsee still answers method-not-found rather than this layer
/// inventing an argument error for a method that does not exist.
fn rewrite(
    method: &str,
    params: &mut Option<std::borrow::Cow<'_, serde_json::value::RawValue>>,
) -> Result<(), ErrorObjectOwned> {
    let Some(raw) = params.as_ref() else {
        return Ok(());
    };
    // Cheap reject first: only an object needs translating, and the vast
    // majority of traffic is positional.
    if !raw.get().trim_start().starts_with('{') {
        return Ok(());
    }
    let Some(specs) = arg_names(method) else {
        return Ok(());
    };
    let obj: Map<String, Value> = serde_json::from_str(raw.get())
        .map_err(|e| invalid(format!("Invalid named parameters: {e}")))?;
    let positional = named_to_positional(specs, obj)?;
    let rewritten = serde_json::value::to_raw_value(&Value::Array(positional))
        .map_err(|e| invalid(format!("Could not encode parameters: {e}")))?;
    *params = Some(std::borrow::Cow::Owned(rewritten));
    Ok(())
}

/// Layer that translates object `params` into positional `params` before
/// dispatch, so every handler can keep reading a sequence.
///
/// Applied to both RPC listeners. It is a no-op for positional requests.
#[derive(Clone, Copy, Debug, Default)]
pub struct NamedParamsLayer;

impl NamedParamsLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> tower::Layer<S> for NamedParamsLayer {
    type Service = NamedParams<S>;

    fn layer(&self, inner: S) -> Self::Service {
        NamedParams { inner }
    }
}

/// The wrapped service produced by [`NamedParamsLayer`].
#[derive(Clone, Debug)]
pub struct NamedParams<S> {
    inner: S,
}

impl<S> RpcServiceT for NamedParams<S>
where
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            BatchResponse = MethodResponse,
            NotificationResponse = MethodResponse,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = MethodResponse;
    type BatchResponse = MethodResponse;
    type NotificationResponse = MethodResponse;

    fn call<'a>(&self, mut req: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        async move {
            // Borrow method and params together so the common positional
            // request costs no allocation.
            let outcome = {
                let Request { method, params, .. } = &mut req;
                rewrite(method, params)
            };
            if let Err(err) = outcome {
                return MethodResponse::error(req.id.clone(), err)
                    .with_extensions(req.extensions.clone());
            }
            inner.call(req).await
        }
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        // Per-entry translation, mirroring jsonrpsee's own batch loop: one
        // entry naming a parameter wrongly must not fail its neighbours.
        let inner = self.inner.clone();
        async move {
            let mut builder = BatchResponseBuilder::new_with_limit(RESPONSE_BODY_LIMIT);
            let mut got_notification = false;

            for entry in batch.into_iter() {
                match entry {
                    Ok(BatchEntry::Call(mut req)) => {
                        let outcome = {
                            let Request { method, params, .. } = &mut req;
                            rewrite(method, params)
                        };
                        let rp = match outcome {
                            Ok(()) => inner.call(req).await,
                            Err(err) => MethodResponse::error(req.id.clone(), err)
                                .with_extensions(req.extensions.clone()),
                        };
                        if let Err(too_big) = builder.append(rp) {
                            return too_big;
                        }
                    }
                    Ok(BatchEntry::Notification(mut n)) => {
                        got_notification = true;
                        // A notification expects no reply, so a naming error
                        // has nowhere to go: drop it, as jsonrpsee drops any
                        // other unanswerable notification.
                        let outcome = {
                            let Notification { method, params, .. } = &mut n;
                            rewrite(method, params)
                        };
                        if outcome.is_ok() {
                            inner.notification(n).await;
                        }
                    }
                    Err(err) => {
                        let (err, id) = err.into_parts();
                        let rp = MethodResponse::error(id, err);
                        if let Err(too_big) = builder.append(rp) {
                            return too_big;
                        }
                    }
                }
            }

            if builder.is_empty() && got_notification {
                MethodResponse::notification()
            } else {
                MethodResponse::from_batch(builder.finish())
            }
        }
    }

    fn notification<'a>(
        &self,
        mut n: Notification<'a>,
    ) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        async move {
            let outcome = {
                let Notification { method, params, .. } = &mut n;
                rewrite(method, params)
            };
            if outcome.is_err() {
                // No response channel for a notification; preserve extensions
                // so transport-level headers still propagate.
                return MethodResponse::notification().with_extensions(n.extensions.clone());
            }
            inner.notification(n).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Run the transform for a registered method, as the layer would.
    fn map(method: &str, params: Value) -> Result<Vec<Value>, String> {
        let specs = arg_names(method).expect("method is registered");
        let obj = params.as_object().expect("object params").clone();
        named_to_positional(specs, obj).map_err(|e| e.message().to_string())
    }

    /// Two spellings of one slot cannot both be honoured, so rejecting is
    /// right -- but the caller has to be told *why*. Core leaves the loser in
    /// the map and it falls out as "Unknown named parameter", which sends an
    /// operator looking for a name that does not exist. satd shares Core's
    /// `maxfeerate` slot with its own `allowquarantined`, so the two names
    /// mean different things and a Core-shaped client can easily send both.
    #[test]
    fn colliding_aliases_name_the_conflict_rather_than_the_parameter() {
        let err = map(
            "sendrawtransaction",
            json!({"hexstring": "0200", "maxfeerate": 0, "allowquarantined": true}),
        )
        .unwrap_err();
        assert!(err.contains("conflicts"), "{err}");
        assert!(err.contains("allowquarantined"), "{err}");
        assert!(err.contains("maxfeerate"), "{err}");
        assert!(
            !err.contains("Unknown named parameter"),
            "the name is known, it collides: {err}"
        );

        // Either name alone still resolves to the shared slot.
        assert_eq!(
            map("sendrawtransaction", json!({"hexstring": "0200", "maxfeerate": 0})).unwrap(),
            vec![json!("0200"), json!(0)]
        );
        assert_eq!(
            map("sendrawtransaction", json!({"hexstring": "0200", "allowquarantined": true}))
                .unwrap(),
            vec![json!("0200"), json!(true)]
        );
    }

    /// Mirrors the generator's `SATD_SLOT_ALIASES`. Two invariants: the alias
    /// is really on a slot (or the conflict branch above is unreachable and
    /// silently does nothing), and Core's spelling is listed *first* so it is
    /// the one that resolves -- a satd extension must never win a slot over
    /// the Core name for it.
    #[test]
    fn satd_slot_aliases_ride_behind_cores_own_name() {
        // Mirrors the generator's SATD_SLOT_ALIASES; grows with it.
        const PAIRS: &[(&str, &str, &str)] =
            &[("sendrawtransaction", "maxfeerate", "allowquarantined")];
        for &(method, core_name, satd_name) in PAIRS {
            assert!(
                SATD_SLOT_ALIASES.contains(&satd_name),
                "{satd_name} missing from SATD_SLOT_ALIASES"
            );
            let specs = arg_names(method).expect("method is registered");
            let pattern = specs
                .iter()
                .map(|(p, _)| *p)
                .find(|p| p.split('|').any(|a| a == satd_name))
                .unwrap_or_else(|| panic!("{satd_name} is on no {method} slot"));
            let mut aliases = pattern.split('|');
            assert_eq!(
                aliases.next(),
                Some(core_name),
                "Core's name must resolve first"
            );
            assert!(aliases.any(|a| a == satd_name));
        }
    }

    #[test]
    fn named_args_become_positional_in_declaration_order() {
        // The call Core's framework makes first, and the reason none of the
        // cache-dependent tests could run: keywords in the caller's order,
        // which is not the declaration order.
        assert_eq!(
            map(
                "generatetoaddress",
                json!({"address": "bcrt1qxyz", "nblocks": 25})
            )
            .unwrap(),
            vec![json!(25), json!("bcrt1qxyz")]
        );
    }

    #[test]
    fn either_alias_of_a_renamed_arg_is_accepted() {
        for alias in ["verbosity", "verbose"] {
            assert_eq!(
                map("getblock", json!({"blockhash": "ab", alias: 2})).unwrap(),
                vec![json!("ab"), json!(2)],
                "{alias} should bind to the same position"
            );
        }
    }

    #[test]
    fn using_both_spellings_of_one_arg_reports_the_second_as_unknown() {
        // Core resolves the first alias present and leaves the other in the
        // map, so it falls out of the unknown-parameter check.
        let err = map("getblock", json!({"blockhash": "ab", "verbosity": 1, "verbose": 2}))
            .unwrap_err();
        assert_eq!(err, "Unknown named parameter verbose");
    }

    #[test]
    fn gaps_before_a_named_arg_become_explicit_nulls() {
        // Naming only the third argument has to push the first two out as
        // nulls, or `blockhash` would arrive as `verbosity`.
        assert_eq!(
            map("getrawtransaction", json!({"txid": "ff", "blockhash": "aa"})).unwrap(),
            vec![json!("ff"), Value::Null, json!("aa")]
        );
    }

    #[test]
    fn trailing_unspecified_args_are_omitted_not_nulled() {
        // Handlers branch on how many arguments arrived, so a trailing null is
        // not the same as an absent argument.
        assert_eq!(
            map("getblock", json!({"blockhash": "ab"})).unwrap(),
            vec![json!("ab")]
        );
    }

    #[test]
    fn named_only_fields_are_gathered_into_an_options_object() {
        // `options` is OBJ_NAMED_PARAMS: its *fields* are named at the top
        // level and Core re-assembles them into the positional slot.
        assert_eq!(
            map(
                "dumptxoutset",
                json!({"path": "/tmp/x", "rollback": 800000})
            )
            .unwrap(),
            vec![json!("/tmp/x"), Value::Null, json!({"rollback": 800000})]
        );
    }

    #[test]
    fn args_array_supplies_leading_positional_values() {
        // The documented mixed form: positional prefix plus named remainder.
        assert_eq!(
            map("getblock", json!({"args": ["ab"], "verbosity": 3})).unwrap(),
            vec![json!("ab"), json!(3)]
        );
    }

    #[test]
    fn an_arg_given_both_positionally_and_by_name_is_refused() {
        let err = map("getblock", json!({"args": ["ab"], "blockhash": "cd"})).unwrap_err();
        assert_eq!(
            err,
            "Parameter blockhash specified twice both as positional and named argument"
        );
    }

    #[test]
    fn unknown_names_are_rejected_rather_than_ignored() {
        // Silently dropping a misspelled name would run the call with a
        // default the caller did not ask for.
        let err = map("getblock", json!({"blockhash": "ab", "verbosityy": 2})).unwrap_err();
        assert_eq!(err, "Unknown named parameter verbosityy");
    }

    #[test]
    fn a_method_that_takes_no_arguments_rejects_any_name() {
        let err = map("getblockcount", json!({"height": 1})).unwrap_err();
        assert_eq!(err, "Unknown named parameter height");
    }

    #[test]
    fn every_registered_method_has_a_row() {
        // The layer passes unknown methods through, so a missing row is a
        // silent Core-compat gap rather than an error. Spot-check the
        // generated table has not lost its Core-derived entries.
        for m in ["getblock", "sendrawtransaction", "createrawtransaction", "addnode"] {
            assert!(arg_names(m).is_some_and(|a| !a.is_empty()), "{m} lost its args");
        }
        // satd-only methods take the names the Operator Manual documents.
        assert_eq!(
            arg_names("listquarantine").unwrap(),
            &[("rule", false), ("count", false), ("skip", false)]
        );
    }

    #[test]
    fn satd_only_methods_with_arguments_are_nameable() {
        // These take a required argument and shipped with an empty row, so
        // every named call was rejected with no name that worked. An empty row
        // must mean "takes none", not "nobody filled it in".
        for (m, name) in [
            ("getaddressbalance", "address"),
            ("getaddresshistory", "address"),
            ("getaddressutxos", "address"),
            ("backfillindex", "index_name"),
            ("cancelindex", "index_name"),
            ("pauseindex", "index_name"),
            ("resumeindex", "index_name"),
        ] {
            assert_eq!(
                arg_names(m).unwrap(),
                &[(name, false)],
                "{m} must be callable by name"
            );
        }
        // And a method that genuinely takes none keeps its empty row, so the
        // unknown-name rejection still fires for it.
        assert_eq!(arg_names("getwarnings").unwrap(), &[] as &[(&str, bool)]);
    }

    #[test]
    fn a_satd_extension_sharing_a_core_slot_is_nameable_under_both_names() {
        // `allowquarantined` rides in Core's `maxfeerate` slot, and the Operator
        // Manual tells operators to pass it by name. Without the alias that call
        // is rejected as an unknown parameter and the transaction is not sent.
        assert_eq!(
            map("sendrawtransaction", json!({"hexstring": "0200", "allowquarantined": true}))
                .unwrap(),
            vec![json!("0200"), json!(true)]
        );
        // Core's own name still binds the same slot, so Core clients are
        // unaffected.
        assert_eq!(
            map("sendrawtransaction", json!({"hexstring": "0200", "maxfeerate": 0.1})).unwrap(),
            vec![json!("0200"), json!(0.1)]
        );
    }

    #[test]
    fn an_explicit_null_holds_its_slot() {
        // Core distinguishes "argument omitted" from "argument given as null"
        // only by position: an explicit null still occupies its slot, so a
        // later argument is not silently promoted into it. `contains_key`
        // rather than `is_null` is what keeps that true.
        assert_eq!(
            map("getblock", json!({"blockhash": "ab", "verbosity": Value::Null})).unwrap(),
            vec![json!("ab"), Value::Null]
        );
    }

    #[test]
    fn an_empty_object_yields_no_arguments() {
        // `{}` on a method with a required argument is not an error here — the
        // handler reports the missing argument, exactly as it does for `[]`.
        // The transform's job is the mapping, not arity enforcement.
        assert_eq!(map("getblock", json!({})).unwrap(), Vec::<Value>::new());
    }

    #[test]
    fn a_non_array_args_is_left_for_the_handler_to_reject() {
        // Core removes `args` unconditionally but only splices it when it is an
        // array; a scalar `args` must not be reported as an unknown name, or
        // the error tells the caller the wrong thing.
        assert_eq!(
            map("getblock", json!({"args": 5, "blockhash": "ab"})).unwrap(),
            vec![json!("ab")]
        );
    }

    #[test]
    fn args_alone_needs_no_named_remainder() {
        assert_eq!(
            map("getblock", json!({"args": ["ab", 2]})).unwrap(),
            vec![json!("ab"), json!(2)]
        );
    }

    #[test]
    fn positional_and_absent_params_are_left_alone() {
        let mut p = Some(std::borrow::Cow::Owned(
            serde_json::value::to_raw_value(&json!([1, 2])).unwrap(),
        ));
        rewrite("getblock", &mut p).unwrap();
        assert_eq!(p.unwrap().get(), "[1,2]");

        let mut none = None;
        rewrite("getblock", &mut none).unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn an_unregistered_method_is_passed_through_untouched() {
        // Otherwise this layer would answer "Unknown named parameter" for a
        // method that does not exist, hiding jsonrpsee's method-not-found.
        let mut p = Some(std::borrow::Cow::Owned(
            serde_json::value::to_raw_value(&json!({"anything": 1})).unwrap(),
        ));
        rewrite("no_such_method", &mut p).unwrap();
        assert_eq!(p.unwrap().get(), r#"{"anything":1}"#);
    }
}
