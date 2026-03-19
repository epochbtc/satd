use bitcoin::Transaction;
use std::collections::HashSet;

use crate::validation::ValidationError;

/// Maximum money supply: 21 million BTC in satoshis.
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Context-free transaction validation (CheckTransaction in Bitcoin Core).
pub fn check_transaction(tx: &Transaction) -> Result<(), ValidationError> {
    // Must have at least one input
    if tx.input.is_empty() {
        return Err(ValidationError::BadTxNoInputs);
    }

    // Must have at least one output
    if tx.output.is_empty() {
        return Err(ValidationError::BadTxNoOutputs);
    }

    // Check output values
    let mut total_out: u64 = 0;
    for output in &tx.output {
        let value = output.value.to_sat();
        if value > MAX_MONEY {
            return Err(ValidationError::BadTxOutputValue);
        }
        total_out = total_out
            .checked_add(value)
            .ok_or(ValidationError::BadTxOutputValue)?;
        if total_out > MAX_MONEY {
            return Err(ValidationError::BadTxOutputValue);
        }
    }

    // Check for duplicate inputs
    let mut seen = HashSet::new();
    for input in &tx.input {
        if !seen.insert(input.previous_output) {
            return Err(ValidationError::BadTxDuplicateInput);
        }
    }

    if tx.is_coinbase() {
        // Coinbase scriptSig must be between 2 and 100 bytes
        let sig_len = tx.input[0].script_sig.len();
        if !(2..=100).contains(&sig_len) {
            return Err(ValidationError::BadTxCoinbaseSize);
        }
    } else {
        // Non-coinbase inputs must not reference null outpoint
        for input in &tx.input {
            if input.previous_output.is_null() {
                return Err(ValidationError::BadTxNullInput);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_genesis_coinbase_passes() {
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let coinbase = &genesis.txdata[0];
        assert!(check_transaction(coinbase).is_ok());
    }

    #[test]
    fn test_mainnet_genesis_coinbase_passes() {
        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin);
        let coinbase = &genesis.txdata[0];
        assert!(check_transaction(coinbase).is_ok());
    }

    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use bitcoin::hashes::Hash as _;

    #[test]
    fn test_no_inputs_rejected() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(ValidationError::BadTxNoInputs)
        ));
    }

    #[test]
    fn test_no_outputs_rejected() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![],
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(ValidationError::BadTxNoOutputs)
        ));
    }

    #[test]
    fn test_output_exceeds_max_money() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                // 21_000_001 BTC in satoshis — exceeds MAX_MONEY
                value: Amount::from_sat(21_000_001 * 100_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(ValidationError::BadTxOutputValue)
        ));
    }

    #[test]
    fn test_total_output_overflow() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(u64::MAX / 2),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::from_sat(u64::MAX / 2),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
            ],
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(ValidationError::BadTxOutputValue)
        ));
    }

    #[test]
    fn test_total_output_exceeds_max_money() {
        // Each output is below MAX_MONEY individually, but their sum exceeds it
        let tx = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(21_000_000 * 100_000_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
            ],
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(ValidationError::BadTxOutputValue)
        ));
    }

    #[test]
    fn test_duplicate_inputs_rejected() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        let tx = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
                TxIn {
                    previous_output: outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(ValidationError::BadTxDuplicateInput)
        ));
    }

    #[test]
    fn test_coinbase_scriptsig_too_short() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from(vec![0xff]), // 1 byte — too short
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(ValidationError::BadTxCoinbaseSize)
        ));
    }

    #[test]
    fn test_coinbase_scriptsig_too_long() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from(vec![0xff; 101]), // 101 bytes — too long
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(ValidationError::BadTxCoinbaseSize)
        ));
    }

    #[test]
    fn test_non_coinbase_null_input() {
        // Non-coinbase tx (has two inputs, one is null outpoint — triggers BadTxNullInput)
        let tx = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([0xab; 32]),
                        vout: 0,
                    },
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        assert!(matches!(
            check_transaction(&tx),
            Err(ValidationError::BadTxNullInput)
        ));
    }

    #[test]
    fn test_valid_spending_tx_passes() {
        let tx = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::from(vec![0x00; 20]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        assert!(check_transaction(&tx).is_ok());
    }
}
