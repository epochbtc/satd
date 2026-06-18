//! Runtime values and the three closed enumerations the language knows about.
//!
//! The type universe is tiny and fixed (§4.2): `Bool`, `Int` (i128, saturating),
//! `Bytes` (borrowed), and three closed enums. There are no floats, no string
//! type, and no user-defined types.

/// Output / prevout script classification (§4.2). `nonstandard` is the catch-all
/// for anything the node could not classify into a known template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptType {
    P2pk,
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
    /// Pay-to-anchor (BIP-0xx ephemeral anchor; intentionally dust, used for
    /// L2/Lightning CPFP fee-bumping — must never be swept up by dust filters).
    P2a,
    OpReturn,
    BareMultisig,
    /// A witness program of an unknown (future) version.
    WitnessUnknown,
    Nonstandard,
}

/// Which network the node is on (`node.network`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}

/// How a transaction reached the node (`tx.source`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    P2p,
    Rpc,
    Electrum,
    Esplora,
    Mcp,
    /// Re-evaluation of an already-resident transaction during a policy reload.
    Reload,
}

/// The three closed enumerations, used by the typechecker to give each enum
/// literal a type without needing comparison context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnumKind {
    ScriptType,
    Network,
    Source,
}

impl EnumKind {
    pub fn name(self) -> &'static str {
        match self {
            EnumKind::ScriptType => "ScriptType",
            EnumKind::Network => "Network",
            EnumKind::Source => "Source",
        }
    }
}

/// A resolved enum literal: its kind plus a discriminant code. Two enum values
/// compare equal iff they have the same kind and code; cross-enum comparison is
/// a type error caught at load time (§4.2 "Enum values compare only against
/// their own enum literals").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnumVal {
    pub kind: EnumKind,
    pub code: u8,
}

impl EnumVal {
    /// The canonical literal name of this enum value — the inverse of
    /// [`enum_literal`]. Used by tooling that renders the AST back to text
    /// (`policylint --explain`, the L2-shape advisory, `getpolicyinfo`).
    pub fn name(self) -> &'static str {
        match self.kind {
            EnumKind::ScriptType => match self.code {
                c if c == ScriptType::P2pk as u8 => "p2pk",
                c if c == ScriptType::P2pkh as u8 => "p2pkh",
                c if c == ScriptType::P2sh as u8 => "p2sh",
                c if c == ScriptType::P2wpkh as u8 => "p2wpkh",
                c if c == ScriptType::P2wsh as u8 => "p2wsh",
                c if c == ScriptType::P2tr as u8 => "p2tr",
                c if c == ScriptType::P2a as u8 => "p2a",
                c if c == ScriptType::OpReturn as u8 => "op_return",
                c if c == ScriptType::BareMultisig as u8 => "bare_multisig",
                c if c == ScriptType::WitnessUnknown as u8 => "witness_unknown",
                _ => "nonstandard",
            },
            EnumKind::Network => match self.code {
                c if c == Network::Mainnet as u8 => "mainnet",
                c if c == Network::Testnet as u8 => "testnet",
                c if c == Network::Testnet4 as u8 => "testnet4",
                c if c == Network::Signet as u8 => "signet",
                _ => "regtest",
            },
            EnumKind::Source => match self.code {
                c if c == Source::P2p as u8 => "p2p",
                c if c == Source::Rpc as u8 => "rpc",
                c if c == Source::Electrum as u8 => "electrum",
                c if c == Source::Esplora as u8 => "esplora",
                c if c == Source::Mcp as u8 => "mcp",
                _ => "reload",
            },
        }
    }
}

impl ScriptType {
    fn code(self) -> u8 {
        self as u8
    }
}
impl Network {
    fn code(self) -> u8 {
        self as u8
    }
}
impl Source {
    fn code(self) -> u8 {
        self as u8
    }
}

impl From<ScriptType> for EnumVal {
    fn from(s: ScriptType) -> Self {
        EnumVal {
            kind: EnumKind::ScriptType,
            code: s.code(),
        }
    }
}
impl From<Network> for EnumVal {
    fn from(n: Network) -> Self {
        EnumVal {
            kind: EnumKind::Network,
            code: n.code(),
        }
    }
}
impl From<Source> for EnumVal {
    fn from(s: Source) -> Self {
        EnumVal {
            kind: EnumKind::Source,
            code: s.code(),
        }
    }
}

/// Resolve a bare identifier to an enum literal. The value names are globally
/// unique across the three enums, so no comparison context is needed (§4.2).
/// Returns `None` for identifiers that are not enum literals.
pub fn enum_literal(name: &str) -> Option<EnumVal> {
    Some(match name {
        // ScriptType
        "p2pk" => ScriptType::P2pk.into(),
        "p2pkh" => ScriptType::P2pkh.into(),
        "p2sh" => ScriptType::P2sh.into(),
        "p2wpkh" => ScriptType::P2wpkh.into(),
        "p2wsh" => ScriptType::P2wsh.into(),
        "p2tr" => ScriptType::P2tr.into(),
        "p2a" => ScriptType::P2a.into(),
        "op_return" => ScriptType::OpReturn.into(),
        "bare_multisig" => ScriptType::BareMultisig.into(),
        "witness_unknown" => ScriptType::WitnessUnknown.into(),
        "nonstandard" => ScriptType::Nonstandard.into(),
        // Network
        "mainnet" => Network::Mainnet.into(),
        "testnet" => Network::Testnet.into(),
        "testnet4" => Network::Testnet4.into(),
        "signet" => Network::Signet.into(),
        "regtest" => Network::Regtest.into(),
        // Source
        "p2p" => Source::P2p.into(),
        "rpc" => Source::Rpc.into(),
        "electrum" => Source::Electrum.into(),
        "esplora" => Source::Esplora.into(),
        "mcp" => Source::Mcp.into(),
        "reload" => Source::Reload.into(),
        _ => return None,
    })
}

/// A runtime value produced by evaluating a sub-expression. Bytes borrow from
/// the [`crate::view::TxView`] so script/witness data is never copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    Bool(bool),
    Int(i128),
    Bytes(&'a [u8]),
    Enum(EnumVal),
}

impl<'a> Value<'a> {
    /// Coerce to bool; non-bool values are a type error caught before eval, so
    /// this only ever sees `Bool` in practice. Defaults to `false` defensively.
    pub fn as_bool(self) -> bool {
        match self {
            Value::Bool(b) => b,
            _ => false,
        }
    }

    pub fn as_int(self) -> i128 {
        match self {
            Value::Int(i) => i,
            _ => 0,
        }
    }
}
