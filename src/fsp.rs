//! FSP: Fast Service Points issued by a service. Not built.
//!
//! Entry point for when fsp-mint accepts ESP and issues FSP (see the fsp-mint
//! README). FSP is one-for-one with ESP, and a service prices in whole units.
//! Notes of this kind are stored with `Kind::Fsp`.

use crate::error::WalletError;
use crate::store::Wallet;

impl Wallet {
    /// Get FSP from a service for ESP it has accepted. Not built.
    pub fn get_fsp(&mut self) -> Result<(), WalletError> {
        Err(WalletError::NotBuilt("FSP (waits on fsp-mint accepting ESP)"))
    }

    /// Spend FSP at a service. Not built.
    pub fn spend_fsp(&mut self) -> Result<(), WalletError> {
        Err(WalletError::NotBuilt("FSP (waits on fsp-mint's spend path)"))
    }
}
