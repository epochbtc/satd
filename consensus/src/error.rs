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

    /// The error's identifier in Bitcoin Core's tests: the name in the
    /// `script_errors[]` table of `src/test/script_tests.cpp` where it has
    /// one, otherwise the `SCRIPT_ERR_` enumerator without its prefix. The
    /// two differ only for `SCRIPT_ERR_SIG_NULLFAIL`, which the table calls
    /// `NULLFAIL`. The inverse of [`Self::from_test_name`].
    pub fn test_name(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::UnknownError => "UNKNOWN_ERROR",
            Self::EvalFalse => "EVAL_FALSE",
            Self::OpReturn => "OP_RETURN",
            Self::ScriptNum => "SCRIPTNUM",
            Self::ScriptSize => "SCRIPT_SIZE",
            Self::PushSize => "PUSH_SIZE",
            Self::OpCount => "OP_COUNT",
            Self::StackSize => "STACK_SIZE",
            Self::SigCount => "SIG_COUNT",
            Self::PubkeyCount => "PUBKEY_COUNT",
            Self::Verify => "VERIFY",
            Self::EqualVerify => "EQUALVERIFY",
            Self::CheckMultiSigVerify => "CHECKMULTISIGVERIFY",
            Self::CheckSigVerify => "CHECKSIGVERIFY",
            Self::NumEqualVerify => "NUMEQUALVERIFY",
            Self::BadOpcode => "BAD_OPCODE",
            Self::DisabledOpcode => "DISABLED_OPCODE",
            Self::InvalidStackOperation => "INVALID_STACK_OPERATION",
            Self::InvalidAltstackOperation => "INVALID_ALTSTACK_OPERATION",
            Self::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            Self::NegativeLocktime => "NEGATIVE_LOCKTIME",
            Self::UnsatisfiedLocktime => "UNSATISFIED_LOCKTIME",
            Self::SigHashtype => "SIG_HASHTYPE",
            Self::SigDer => "SIG_DER",
            Self::MinimalData => "MINIMALDATA",
            Self::SigPushOnly => "SIG_PUSHONLY",
            Self::SigHighS => "SIG_HIGH_S",
            Self::SigNullDummy => "SIG_NULLDUMMY",
            Self::PubkeyType => "PUBKEYTYPE",
            Self::CleanStack => "CLEANSTACK",
            Self::MinimalIf => "MINIMALIF",
            Self::SigNullFail => "NULLFAIL",
            Self::DiscourageUpgradableNops => "DISCOURAGE_UPGRADABLE_NOPS",
            Self::DiscourageUpgradableWitnessProgram => "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            Self::DiscourageUpgradableTaprootVersion => "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
            Self::DiscourageOpSuccess => "DISCOURAGE_OP_SUCCESS",
            Self::DiscourageUpgradablePubkeyType => "DISCOURAGE_UPGRADABLE_PUBKEYTYPE",
            Self::WitnessProgramWrongLength => "WITNESS_PROGRAM_WRONG_LENGTH",
            Self::WitnessProgramWitnessEmpty => "WITNESS_PROGRAM_WITNESS_EMPTY",
            Self::WitnessProgramMismatch => "WITNESS_PROGRAM_MISMATCH",
            Self::WitnessMalleated => "WITNESS_MALLEATED",
            Self::WitnessMalleatedP2sh => "WITNESS_MALLEATED_P2SH",
            Self::WitnessUnexpected => "WITNESS_UNEXPECTED",
            Self::WitnessPubkeyType => "WITNESS_PUBKEYTYPE",
            Self::SchnorrSigSize => "SCHNORR_SIG_SIZE",
            Self::SchnorrSigHashtype => "SCHNORR_SIG_HASHTYPE",
            Self::SchnorrSig => "SCHNORR_SIG",
            Self::TaprootWrongControlSize => "TAPROOT_WRONG_CONTROL_SIZE",
            Self::TapscriptValidationWeight => "TAPSCRIPT_VALIDATION_WEIGHT",
            Self::TapscriptCheckMultiSig => "TAPSCRIPT_CHECKMULTISIG",
            Self::TapscriptMinimalIf => "TAPSCRIPT_MINIMALIF",
            Self::TapscriptEmptyPubkey => "TAPSCRIPT_EMPTY_PUBKEY",
            Self::OpCodeSeparator => "OP_CODESEPARATOR",
            Self::SigFindAndDelete => "SIG_FINDANDDELETE",
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

#[cfg(test)]
mod tests {
    use super::ScriptError;

    /// `test_name` is the inverse of `from_test_name` on canonical names: the
    /// names of Core's `script_errors[]` table, plus the enumerator names for
    /// the errors the table lacks. `test_name`'s match is exhaustive, so
    /// every variant has a name; this checks each name parses back to it.
    #[test]
    fn test_name_round_trips_through_from_test_name() {
        let names = [
            "OK", "UNKNOWN_ERROR", "EVAL_FALSE", "OP_RETURN", "SCRIPTNUM", "SCRIPT_SIZE", "PUSH_SIZE",
            "OP_COUNT", "STACK_SIZE", "SIG_COUNT", "PUBKEY_COUNT", "VERIFY", "EQUALVERIFY",
            "CHECKMULTISIGVERIFY", "CHECKSIGVERIFY", "NUMEQUALVERIFY", "BAD_OPCODE", "DISABLED_OPCODE",
            "INVALID_STACK_OPERATION", "INVALID_ALTSTACK_OPERATION", "UNBALANCED_CONDITIONAL",
            "NEGATIVE_LOCKTIME", "UNSATISFIED_LOCKTIME", "SIG_HASHTYPE", "SIG_DER", "MINIMALDATA",
            "SIG_PUSHONLY", "SIG_HIGH_S", "SIG_NULLDUMMY", "PUBKEYTYPE", "CLEANSTACK", "MINIMALIF",
            "NULLFAIL", "DISCOURAGE_UPGRADABLE_NOPS", "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION", "DISCOURAGE_OP_SUCCESS",
            "DISCOURAGE_UPGRADABLE_PUBKEYTYPE", "WITNESS_PROGRAM_WRONG_LENGTH",
            "WITNESS_PROGRAM_WITNESS_EMPTY", "WITNESS_PROGRAM_MISMATCH", "WITNESS_MALLEATED",
            "WITNESS_MALLEATED_P2SH", "WITNESS_UNEXPECTED", "WITNESS_PUBKEYTYPE", "SCHNORR_SIG_SIZE",
            "SCHNORR_SIG_HASHTYPE", "SCHNORR_SIG", "TAPROOT_WRONG_CONTROL_SIZE",
            "TAPSCRIPT_VALIDATION_WEIGHT", "TAPSCRIPT_CHECKMULTISIG", "TAPSCRIPT_MINIMALIF",
            "TAPSCRIPT_EMPTY_PUBKEY", "OP_CODESEPARATOR", "SIG_FINDANDDELETE",
        ];
        for name in names {
            let err = ScriptError::from_test_name(name).unwrap_or_else(|| panic!("{name} does not parse"));
            assert_eq!(err.test_name(), name);
        }
    }
}
