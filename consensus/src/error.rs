/// Script error types matching Bitcoin Core's ScriptError_t enum 1:1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptError {
    Ok,
    UnknownError,
    EvalFalse,
    OpReturn,
    ScriptNum,

    // Size constraints
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,

    // Failed verify operations
    Verify,
    EqualVerify,
    CheckMultiSigVerify,
    CheckSigVerify,
    NumEqualVerify,

    // Logical/Format/Canonical errors
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,

    // CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY
    NegativeLocktime,
    UnsatisfiedLocktime,

    // Malleability
    SigHashtype,
    SigDer,
    MinimalData,
    SigPushOnly,
    SigHighS,
    SigNullDummy,
    PubkeyType,
    CleanStack,
    MinimalIf,
    SigNullFail,

    // Softfork safeness
    DiscourageUpgradableNops,
    DiscourageUpgradableWitnessProgram,
    DiscourageUpgradableTaprootVersion,
    DiscourageOpSuccess,
    DiscourageUpgradablePubkeyType,

    // Segregated witness
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2sh,
    WitnessUnexpected,
    WitnessPubkeyType,

    // Taproot
    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TaprootWrongControlSize,
    TapscriptValidationWeight,
    TapscriptCheckMultiSig,
    TapscriptMinimalIf,
    TapscriptEmptyPubkey,

    // Constant scriptCode
    OpCodeSeparator,
    SigFindAndDelete,
}

impl ScriptError {
    /// Returns the string name matching Bitcoin Core's ScriptErrorString().
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "No error",
            Self::UnknownError => "unknown error",
            Self::EvalFalse => "Script evaluated without error but finished with a false/empty top stack element",
            Self::OpReturn => "OP_RETURN was encountered",
            Self::ScriptNum => "Script number overflow",
            Self::ScriptSize => "Script is too big",
            Self::PushSize => "Push value size limit exceeded",
            Self::OpCount => "Operation limit exceeded",
            Self::StackSize => "Stack size limit exceeded",
            Self::SigCount => "Signature count negative or greater than pubkey count",
            Self::PubkeyCount => "Pubkey count negative or limit exceeded",
            Self::Verify => "Script failed an OP_VERIFY operation",
            Self::EqualVerify => "Script failed an OP_EQUALVERIFY operation",
            Self::CheckMultiSigVerify => "Script failed an OP_CHECKMULTISIGVERIFY operation",
            Self::CheckSigVerify => "Script failed an OP_CHECKSIGVERIFY operation",
            Self::NumEqualVerify => "Script failed an OP_NUMEQUALVERIFY operation",
            Self::BadOpcode => "Opcode missing or not understood",
            Self::DisabledOpcode => "Attempted to use a disabled opcode",
            Self::InvalidStackOperation => "Operation not valid with the current stack size",
            Self::InvalidAltstackOperation => "Operation not valid with the current altstack size",
            Self::UnbalancedConditional => "Invalid OP_IF construction",
            Self::NegativeLocktime => "Negative locktime",
            Self::UnsatisfiedLocktime => "Locktime requirement not satisfied",
            Self::SigHashtype => "Signature hash type missing or not understood",
            Self::SigDer => "Non-canonical DER signature",
            Self::MinimalData => "Data push larger than necessary",
            Self::SigPushOnly => "Only push operators allowed in signatures",
            Self::SigHighS => "Non-canonical signature: S value is unnecessarily high",
            Self::SigNullDummy => "Dummy CHECKMULTISIG argument must be zero",
            Self::PubkeyType => "Public key is neither compressed or uncompressed",
            Self::CleanStack => "Stack size must be exactly one after execution",
            Self::MinimalIf => "OP_IF/NOTIF argument must be minimal",
            Self::SigNullFail => "Signature must be zero for failed CHECK(MULTI)SIG operation",
            Self::DiscourageUpgradableNops => "NOPx reserved for soft-fork upgrades",
            Self::DiscourageUpgradableWitnessProgram => "Witness version reserved for soft-fork upgrades",
            Self::DiscourageUpgradableTaprootVersion => "Taproot version reserved for soft-fork upgrades",
            Self::DiscourageOpSuccess => "OP_SUCCESSx reserved for soft-fork upgrades",
            Self::DiscourageUpgradablePubkeyType => "Public key version reserved for soft-fork upgrades",
            Self::WitnessProgramWrongLength => "Witness program has incorrect length",
            Self::WitnessProgramWitnessEmpty => "Witness program was passed an empty witness",
            Self::WitnessProgramMismatch => "Witness program hash mismatch",
            Self::WitnessMalleated => "Witness requires empty scriptSig",
            Self::WitnessMalleatedP2sh => "Witness requires only-redeemscript scriptSig",
            Self::WitnessUnexpected => "Witness provided for non-witness script",
            Self::WitnessPubkeyType => "Using non-compressed keys in segwit",
            Self::SchnorrSigSize => "Invalid Schnorr signature size",
            Self::SchnorrSigHashtype => "Invalid Schnorr signature hash type",
            Self::SchnorrSig => "Invalid Schnorr signature",
            Self::TaprootWrongControlSize => "Invalid Taproot control block size",
            Self::TapscriptValidationWeight => "Too much signature validation relative to witness weight",
            Self::TapscriptCheckMultiSig => "OP_CHECKMULTISIG(VERIFY) is not available in tapscript",
            Self::TapscriptMinimalIf => "OP_IF/NOTIF argument must be minimal in tapscript",
            Self::TapscriptEmptyPubkey => "Public key is empty in tapscript",
            Self::OpCodeSeparator => "Using OP_CODESEPARATOR in non-witness script",
            Self::SigFindAndDelete => "Signature is found in scriptCode",
        }
    }

    /// Parse from Bitcoin Core test vector error name string.
    pub fn from_test_name(name: &str) -> Option<Self> {
        match name {
            "OK" => Some(Self::Ok),
            "UNKNOWN_ERROR" => Some(Self::UnknownError),
            "EVAL_FALSE" => Some(Self::EvalFalse),
            "OP_RETURN" => Some(Self::OpReturn),
            "SCRIPTNUM" | "SCRIPTNUM_OVERFLOW" => Some(Self::ScriptNum),
            "SCRIPT_SIZE" => Some(Self::ScriptSize),
            "PUSH_SIZE" => Some(Self::PushSize),
            "OP_COUNT" => Some(Self::OpCount),
            "STACK_SIZE" => Some(Self::StackSize),
            "SIG_COUNT" => Some(Self::SigCount),
            "PUBKEY_COUNT" => Some(Self::PubkeyCount),
            "VERIFY" => Some(Self::Verify),
            "EQUALVERIFY" => Some(Self::EqualVerify),
            "CHECKMULTISIGVERIFY" => Some(Self::CheckMultiSigVerify),
            "CHECKSIGVERIFY" => Some(Self::CheckSigVerify),
            "NUMEQUALVERIFY" => Some(Self::NumEqualVerify),
            "BAD_OPCODE" => Some(Self::BadOpcode),
            "DISABLED_OPCODE" => Some(Self::DisabledOpcode),
            "INVALID_STACK_OPERATION" => Some(Self::InvalidStackOperation),
            "INVALID_ALTSTACK_OPERATION" => Some(Self::InvalidAltstackOperation),
            "UNBALANCED_CONDITIONAL" => Some(Self::UnbalancedConditional),
            "NEGATIVE_LOCKTIME" => Some(Self::NegativeLocktime),
            "UNSATISFIED_LOCKTIME" => Some(Self::UnsatisfiedLocktime),
            "SIG_HASHTYPE" => Some(Self::SigHashtype),
            "SIG_DER" => Some(Self::SigDer),
            "MINIMALDATA" => Some(Self::MinimalData),
            "SIG_PUSHONLY" => Some(Self::SigPushOnly),
            "SIG_HIGH_S" => Some(Self::SigHighS),
            "SIG_NULLDUMMY" | "NULLDUMMY" => Some(Self::SigNullDummy),
            "PUBKEYTYPE" => Some(Self::PubkeyType),
            "CLEANSTACK" => Some(Self::CleanStack),
            "MINIMALIF" => Some(Self::MinimalIf),
            "SIG_NULLFAIL" | "NULLFAIL" => Some(Self::SigNullFail),
            "DISCOURAGE_UPGRADABLE_NOPS" => Some(Self::DiscourageUpgradableNops),
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => Some(Self::DiscourageUpgradableWitnessProgram),
            "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => Some(Self::DiscourageUpgradableTaprootVersion),
            "DISCOURAGE_OP_SUCCESS" => Some(Self::DiscourageOpSuccess),
            "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => Some(Self::DiscourageUpgradablePubkeyType),
            "WITNESS_PROGRAM_WRONG_LENGTH" => Some(Self::WitnessProgramWrongLength),
            "WITNESS_PROGRAM_WITNESS_EMPTY" => Some(Self::WitnessProgramWitnessEmpty),
            "WITNESS_PROGRAM_MISMATCH" => Some(Self::WitnessProgramMismatch),
            "WITNESS_MALLEATED" => Some(Self::WitnessMalleated),
            "WITNESS_MALLEATED_P2SH" => Some(Self::WitnessMalleatedP2sh),
            "WITNESS_UNEXPECTED" => Some(Self::WitnessUnexpected),
            "WITNESS_PUBKEYTYPE" => Some(Self::WitnessPubkeyType),
            "SCHNORR_SIG_SIZE" => Some(Self::SchnorrSigSize),
            "SCHNORR_SIG_HASHTYPE" => Some(Self::SchnorrSigHashtype),
            "SCHNORR_SIG" => Some(Self::SchnorrSig),
            "TAPROOT_WRONG_CONTROL_SIZE" => Some(Self::TaprootWrongControlSize),
            "TAPSCRIPT_VALIDATION_WEIGHT" => Some(Self::TapscriptValidationWeight),
            "TAPSCRIPT_CHECKMULTISIG" => Some(Self::TapscriptCheckMultiSig),
            "TAPSCRIPT_MINIMALIF" => Some(Self::TapscriptMinimalIf),
            "TAPSCRIPT_EMPTY_PUBKEY" => Some(Self::TapscriptEmptyPubkey),
            "OP_CODESEPARATOR" => Some(Self::OpCodeSeparator),
            "SIG_FINDANDDELETE" => Some(Self::SigFindAndDelete),
            _ => None,
        }
    }
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
