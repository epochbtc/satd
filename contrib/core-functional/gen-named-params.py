#!/usr/bin/env python3
"""Regenerate the named-parameter table in node/src/rpc/named_params.rs.

Bitcoin Core maps an object `params` onto a method's declared positional
arguments. satd reproduces that in `node/src/rpc/named_params.rs`, which needs
each method's argument names, in order, exactly as Core declares them. A wrong
name does not fail loudly -- it binds a value to the wrong position -- so the
table is generated from Core's own `RPCHelpMan` declarations rather than
transcribed.

Usage, against a Core checkout at the tag in PIN:

    ./gen-named-params.py --emit-rust ~/path/to/bitcoin > /tmp/table.rs

then splice the emitted match arms into `arg_names()`. Verify with
`--cross-check`, which replays Core's independent `(method, index, name)`
triples from `src/rpc/client.cpp` against the extracted table; satd-registered
methods must show zero disagreements.

What this mirrors, from `RPCHelpMan::GetArgNames` (`src/rpc/util.cpp`):

  * an `OBJ_NAMED_PARAMS` argument contributes one named-only entry per inner
    field, emitted *before* an ordinary entry for the container itself;
  * `.hidden` suppresses an argument from help output only -- it stays
    nameable, so `stop(wait=...)` works;
  * an argument's name may carry `|`-separated aliases (`verbosity|verbose`).

Two Core spellings need resolving rather than reading literally: an argument
given as a bare identifier (`scan_action_arg_desc`) and a whole argument vector
given as a call (`CreateTxDoc()`). Both are followed here, because silently
skipping either shifts every position after it.
"""
import argparse, os, re, sys

def strip_comments_and_index(src):
    """Return src with comments blanked (positions preserved) and a mask of string-literal spans."""
    out=list(src); n=len(src); i=0; instr=False; spans=[]; start=None
    while i<n:
        c=src[i]
        if instr:
            if c=='\\': i+=2; continue
            if c=='"': instr=False; spans.append((start,i)); i+=1; continue
            i+=1; continue
        if c=='"': instr=True; start=i; i+=1; continue
        if c=="'":  # char literal
            j=i+1
            while j<n and src[j]!="'":
                if src[j]=='\\': j+=1
                j+=1
            i=j+1; continue
        if src.startswith('//',i):
            j=src.find('\n',i); j=n if j<0 else j
            for k in range(i,j): out[k]=' '
            i=j; continue
        if src.startswith('/*',i):
            j=src.find('*/',i); j=n if j<0 else j+2
            for k in range(i,j):
                if src[k]!='\n': out[k]=' '
            i=j; continue
        i+=1
    return ''.join(out), spans

def inner_names(entry):
    """Top-level field names of an OBJ_NAMED_PARAMS entry's inner vector."""
    # entry is "{ \"options\", Type::OBJ_NAMED_PARAMS, fallback, \"desc\", { ... }, opts }"
    depth=0; i=0; start=None
    # find the first brace-group element at depth 1 (the inner vector)
    while i<len(entry):
        c=entry[i]
        if c=='{':
            depth+=1
            if depth==2: start=i; break
        elif c=='}': depth-=1
        i+=1
    if start is None: return []
    d=0; j=start; end=None
    while j<len(entry):
        if entry[j]=='{': d+=1
        elif entry[j]=='}':
            d-=1
            if d==0: end=j; break
        j+=1
    if end is None: return []
    body=entry[start+1:end]
    names=[]; d=0; seg=[]
    segs=[]; cur=''
    for ch in body:
        if ch in '{([': d+=1
        elif ch in '})]': d-=1
        if ch==',' and d==0: segs.append(cur); cur=''
        else: cur+=ch
    segs.append(cur)
    for seg in segs:
        m=re.search(r'"([A-Za-z0-9_|]+)"', seg)
        if m: names.append(m.group(1))
    return names

IDENT_ARGS={}
UNRESOLVED=set()
EMPTY_INNER=set()

def collect_idents(path):
    src=open(path,errors='replace').read()
    clean,spans=strip_comments_and_index(src)
    for m in re.finditer(r'\b(?:static\s+)?const\s+auto\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*RPCArg\{', clean):
        ident=m.group(1); p=m.end()-1
        d=0; i=p; end=None
        while i<len(clean):
            if clean[i]=='{': d+=1
            elif clean[i]=='}':
                d-=1
                if d==0: end=i; break
            i+=1
        if end is None: continue
        nm=next(((a,b) for a,b in spans if p<=a<=end), None)
        if nm: IDENT_ARGS[ident]=(src[nm[0]+1:nm[1]], clean[p:end+1])

FN_ARGVECS={}

def collect_argvec_fns(path):
    """`std::vector<RPCArg> CreateTxDoc()` style helpers used *as* an args vector."""
    src=open(path,errors='replace').read()
    clean,spans=strip_comments_and_index(src)
    for m in re.finditer(r'std::vector<RPCArg>\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{', clean):
        fn=m.group(1); p=m.end()-1
        d=0; i=p; end=None
        while i<len(clean):
            if clean[i]=='{': d+=1
            elif clean[i]=='}':
                d-=1
                if d==0: end=i; break
            i+=1
        if end is None: continue
        body=clean[p:end+1]
        r=body.find('return')
        if r<0: continue
        b=body.find('{', r)
        if b<0: continue
        FN_ARGVECS[fn]=(p+b, path)

def parse_file(path):
    src=open(path,errors='replace').read()
    clean,spans=strip_comments_and_index(src)
    instr=[False]*len(clean)
    for a,b in spans:
        for k in range(a,b+1): instr[k]=True
    res={}
    for m in re.finditer(r'RPCHelpMan\{', clean):
        p=m.end()
        # first string literal = method name
        name_span=next(((a,b) for a,b in spans if a>=p), None)
        if not name_span: continue
        method=src[name_span[0]+1:name_span[1]]
        if not re.fullmatch(r'[a-z0-9_]+', method): continue
        # walk to the first '{' at depth 0 relative to RPCHelpMan's body -> args vector
        depth=0; i=p; argstart=None
        while i<len(clean):
            if instr[i]: i+=1; continue
            c=clean[i]
            if c=='{':
                if depth==0: argstart=i; break
                depth+=1
            elif c=='}':
                if depth==0: break
                depth-=1
            elif c=='(': depth+=1
            elif c==')': depth-=1
            i+=1
        # The args slot may be a call returning std::vector<RPCArg>
        # (Core's CreateTxDoc()). That reaches the brace-walk as a plain
        # call, so the walk lands on RPCResult's brace instead -- check the
        # span before it and redirect into the helper body.
        head_txt = clean[p:argstart] if argstart is not None else clean[p:p+4000]
        call=re.search(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*,\s*$', head_txt.rstrip()+' ')
        if not call:
            call=re.search(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*,', head_txt)
        if call and call.group(1) in FN_ARGVECS:
            off,src_path=FN_ARGVECS[call.group(1)]
            if src_path!=path: continue
            argstart=off
        if argstart is None: continue
        # find matching close of args vector
        depth=0; i=argstart; argend=None
        while i<len(clean):
            if not instr[i]:
                if clean[i]=='{': depth+=1
                elif clean[i]=='}':
                    depth-=1
                    if depth==0: argend=i; break
            i+=1
        if argend is None: continue
        # Split the args vector into top-level, comma-separated elements. An
        # element is either an inline brace-init or a bare identifier naming a
        # `static const auto ..._arg_desc = RPCArg{...}` defined elsewhere;
        # Core uses both, and dropping the identifiers silently shifts every
        # position after them.
        elems=[]; d=0; start=argstart+1; i=argstart+1
        while i<argend:
            if instr[i]: i+=1; continue
            c=clean[i]
            if c in '{([': d+=1
            elif c in '})]': d-=1
            elif c==',' and d==0:
                elems.append((start,i)); start=i+1
            i+=1
        elems.append((start,argend))
        args=[]
        for (a,b) in elems:
            frag_clean=clean[a:b]; 
            if not frag_clean.strip(): continue
            if '{' in frag_clean:
                nm=next(((x,y) for x,y in spans if a<=x<b), None)
                if not nm: continue
                names=src[nm[0]+1:nm[1]]
                head=frag_clean
            else:
                ident=frag_clean.strip()
                if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_:]*', ident): continue
                resolved=IDENT_ARGS.get(ident)
                if resolved is None:
                    UNRESOLVED.add((method, ident)); continue
                names, head = resolved
            t=re.search(r'RPCArg::Type::([A-Z_]+)', head)
            typ=t.group(1) if t else ''
            # `.hidden` only suppresses an arg from help output; GetArgNames
            # still emits it, so `stop(wait=...)` is nameable. Do not skip.
            if typ=='OBJ_NAMED_PARAMS':
                # RPCHelpMan::GetArgNames emits every inner field as a
                # named-only entry FIRST, then the container itself as an
                # ordinary positional entry.
                got=inner_names(head)
                if not got: EMPTY_INNER.add(method)
                for inner in got:
                    args.append([inner, True])
            args.append([names, False])
        res[method]=args
    return res

# ---------------------------------------------------------------- satd side

# satd's own RPCs, which Core does not declare. These take the parameter names
# the Operator Manual already documents for them.
# satd extensions that ride in a Core argument slot. The name is added as an
# alias on that slot, so both Core's name and satd's resolve to it. Keyed by
# method, then by zero-based slot index.
SATD_SLOT_ALIASES = {
    # `allowquarantined` (satd) shares Core's `maxfeerate` slot, which satd does
    # not enforce; a numeric maxfeerate there fails satd's bool parse and reads
    # as "not set", so Core clients are unaffected. Without the alias the
    # Operator Manual's own documented call --
    # `sendrawtransaction hexstring allowquarantined=true` -- is rejected as an
    # unknown named parameter.
    "sendrawtransaction": {1: "allowquarantined"},
}

SATD_ONLY = {
    # satd-only RPCs that take arguments. Core has no row for these, so without
    # an entry here the table would give them `[]` and every named call would be
    # rejected with "Unknown named parameter" and no name that works. See the
    # exhaustiveness check in build_table().
    "backfillindex": [["index_name", False]],
    "cancelindex": [["index_name", False]],
    "pauseindex": [["index_name", False]],
    "resumeindex": [["index_name", False]],
    "getaddressbalance": [["address", False]],
    "getaddresshistory": [["address", False]],
    "getaddressutxos": [["address", False]],
    # satd-only status/diagnostic RPCs that take no arguments. Listed
    # explicitly rather than defaulted, so the exhaustiveness check stays
    # meaningful and a future argument cannot be added without a row.
    "getblockfileaudit": [],
    "getconfig": [],
    "getibdprogress": [],
    "getorphaninfo": [],
    "getpolicyinfo": [],
    "getquarantineinfo": [],
    "getserverstatus": [],
    "getsysteminfo": [],
    "getwarnings": [],
    "estimatefees": [["targets", False], ["mode", False]],
    "getmempoolhistory": [["since_secs", False]],
    "getquarantineentry": [["txid", False]],
    "getreorghistory": [["since_secs", False]],
    "getsilentpaymentblockdata": [
        ["blockhash", False], ["verbosity", False], ["dust_limit", False],
    ],
    "listquarantine": [["rule", False], ["count", False], ["skip", False]],
    "policytest": [["rawtx", False]],
    # Subscription pair: jsonrpsee owns the subscription-id argument and Core
    # has no equivalent, so neither declares a nameable parameter.
    "subscribemempool": [],
    "unsubscribemempool": [],
}


def satd_methods(repo_root):
    """Every method name registered in node/src/rpc/server.rs."""
    src = open(os.path.join(repo_root, "node/src/rpc/server.rs"), errors="replace").read()
    names = set(re.findall(r'register_(?:async_)?method\(\s*"([a-z0-9_]+)"', src))
    # register_subscription("sub", "notif", "unsub", ...) registers two methods.
    for sub, _notif, unsub in re.findall(
        r'register_subscription\(\s*"([a-z0-9_]+)"\s*,\s*"([a-z0-9_]+)"\s*,\s*"([a-z0-9_]+)"', src
    ):
        names.add(sub)
        names.add(unsub)
    return sorted(names)


def core_sources(bitcoin_dir):
    import glob
    paths = sorted(glob.glob(os.path.join(bitcoin_dir, "src/rpc/*.cpp")))
    paths += sorted(glob.glob(os.path.join(bitcoin_dir, "src/wallet/rpc/*.cpp")))
    if not paths:
        sys.exit(f"no Core RPC sources under {bitcoin_dir}/src/rpc")
    return paths


def build(bitcoin_dir, repo_root):
    paths = core_sources(bitcoin_dir)
    for path in paths:
        collect_idents(path)
        collect_argvec_fns(path)
    core = {}
    for path in paths:
        core.update(parse_file(path))
    if EMPTY_INNER:
        print(f"WARNING: unreadable OBJ_NAMED_PARAMS inner vectors: {sorted(EMPTY_INNER)}",
              file=sys.stderr)
    if UNRESOLVED:
        sys.exit(f"unresolved identifier args: {sorted(UNRESOLVED)}")
    table = {}
    unknown = []
    for m in satd_methods(repo_root):
        if m in SATD_ONLY:
            table[m] = SATD_ONLY[m]
        elif m in core:
            row = [list(a) for a in core[m]]
            for idx, alias in SATD_SLOT_ALIASES.get(m, {}).items():
                if idx >= len(row):
                    sys.exit(f"{m}: alias slot {idx} is beyond Core's arity")
                row[idx][0] = f"{row[idx][0]}|{alias}"
            table[m] = row
        else:
            # Neither Core nor SATD_ONLY knows this method. Defaulting to `[]`
            # here is how seven satd-only RPCs shipped with no nameable
            # argument at all: `--check` compared the generated `[]` against
            # the committed `[]` and passed, and the presence assertion in
            # server.rs only checks that a row exists, not that it is right.
            # Every layer reported green. Fail instead.
            unknown.append(m)
            table[m] = []
    if unknown:
        sys.exit(
            "methods registered in satd but absent from Core and from SATD_ONLY: "
            + ", ".join(sorted(unknown))
            + "\nAdd each to SATD_ONLY with its argument names (use [] if it "
            "genuinely takes none)."
        )
    return core, table


def cross_check(bitcoin_dir, table):
    """Replay Core's independent (method, index, name) triples from client.cpp.

    client.cpp exists for a different purpose (which bitcoin-cli arguments need
    JSON conversion), so it is a genuinely independent witness to argument
    names and positions -- a parser bug is unlikely to agree with it by chance.
    """
    src = open(os.path.join(bitcoin_dir, "src/rpc/client.cpp"), errors="replace").read()
    triples = re.findall(
        r'\{\s*"([a-z0-9_]+)"\s*,\s*(-?\d+)\s*,\s*"([A-Za-z0-9_|]+)"\s*\}', src)
    exact = field = 0
    bad = []
    for meth, idx, name in triples:
        if meth not in table:
            continue          # not registered by satd
        args = table[meth]
        positional = [a for a in args if not a[1]]
        named_only = {a[0] for a in args if a[1]}
        idx = int(idx)
        if name in named_only:
            field += 1
        elif idx < len(positional) and name in positional[idx][0].split("|"):
            exact += 1
        else:
            bad.append((meth, idx, name, [p[0] for p in positional]))
    print(f"cross-check over satd-registered methods: {exact} exact, "
          f"{field} options-field, {len(bad)} disagreements", file=sys.stderr)
    for b in bad:
        print(f"  DISAGREE {b}", file=sys.stderr)
    return not bad


def emit_rust(table):
    for row in generated_rows(table):
        print(row)


TABLE_START = "    let args: &'static [ArgSpec] = match method {\n"
TABLE_END = "        _ => return None,\n"


def committed_rows(repo_root):
    path = os.path.join(repo_root, "node/src/rpc/named_params.rs")
    src = open(path, errors="replace").read()
    i = src.index(TABLE_START) + len(TABLE_START)
    j = src.index(TABLE_END, i)
    return [l for l in src[i:j].split("\n") if l.strip().startswith('"')]


def generated_rows(table):
    rows = []
    for m in sorted(table):
        args = table[m]
        if not args:
            rows.append(f'        "{m}" => &[],')
        else:
            inner = ", ".join(
                f'("{n}", {"true" if no else "false"})' for n, no in args)
            rows.append(f'        "{m}" => &[{inner}],')
    return rows


def check(repo_root, table):
    """Fail if the committed table has drifted from what Core now declares.

    This is the check that matters on a pin bump: a renamed argument costs
    compatibility, but a *reordered* one silently binds values to the wrong
    positions, and nothing else in the build would notice.
    """
    want = generated_rows(table)
    have = committed_rows(repo_root)
    if want == have:
        print(f"named-parameter table is current ({len(have)} methods)", file=sys.stderr)
        return True
    missing = [l for l in want if l not in have]
    extra = [l for l in have if l not in want]
    print("named-parameter table is STALE -- regenerate with --emit-rust and "
          "splice into node/src/rpc/named_params.rs", file=sys.stderr)
    for l in missing:
        print(f"  Core declares, table lacks: {l.strip()}", file=sys.stderr)
    for l in extra:
        print(f"  table has, Core does not:   {l.strip()}", file=sys.stderr)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bitcoin_dir", help="path to a Bitcoin Core checkout at the tag in PIN")
    ap.add_argument("--emit-rust", action="store_true",
                    help="print the match arms for arg_names()")
    ap.add_argument("--cross-check", action="store_true",
                    help="validate against Core's client.cpp triples")
    ap.add_argument("--check", action="store_true",
                    help="fail if node/src/rpc/named_params.rs has drifted from Core")
    args = ap.parse_args()
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    _core, table = build(args.bitcoin_dir, repo_root)
    ok = True
    if args.cross_check or not (args.emit_rust or args.check):
        ok = cross_check(args.bitcoin_dir, table) and ok
    if args.check:
        ok = check(repo_root, table) and ok
    if args.emit_rust:
        emit_rust(table)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
