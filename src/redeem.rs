//! ESP redemption by a service. Not built.
//!
//! Entry point for when the ESP mint's redemption lands (see the esp-mint README,
//! "Redemption"). The shape it will have: the service's DID key signs a request
//! naming the notes it holds, a payout memo, and two lists of fresh blinded
//! outputs (for a declined payout, and for a refund when the fee must come out of
//! rejected notes). The mint accepts or rejects each note and replies for every
//! one.

use crate::error::WalletError;
use crate::store::Wallet;

impl Wallet {
    /// Redeem ESP notes for a service. Not built.
    pub fn redeem_esp(&mut self) -> Result<(), WalletError> {
        Err(WalletError::NotBuilt(
            "ESP redemption (waits on the ESP mint's /redeem)",
        ))
    }
}
