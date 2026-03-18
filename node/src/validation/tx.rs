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
}
