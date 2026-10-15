//! ESP transfer to a service. Not built.
//!
//! Entry point for when the ESP mint's transfer lands (see the esp-mint README,
//! "Transfer to the service"). The shape it will have: an app hands ESP notes to
//! the service, and with them each note's spend secret. The service builds a
//! request with fresh blinded outputs of its own, signs it with its DID key, and
//! sends it to the mint, which swaps each note for a fresh note only the service
//! controls. Only then does the service issue FSP.

use crate::error::WalletError;
use crate::store::Wallet;

impl Wallet {
    /// Hand ESP notes to a service. Not built.
    pub fn transfer_esp(&mut self) -> Result<(), WalletError> {
        Err(WalletError::NotBuilt(
            "ESP transfer (waits on the ESP mint's /transfer)",
        ))
    }
}
