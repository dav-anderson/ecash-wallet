//! ESP note sizes are powers of two.
//!
//! The ESP mint refuses any amount that is not a power of two, on every route
//! that signs ESP (the same rule as PSP and FSP), so that notes of one size look
//! alike. The wallet therefore splits every total it asks the mint to sign into
//! powers of two: one note for each bit that is set, largest first. A `u64` holds
//! at most 2^63, so a total above that is several notes of 2^63.

use crate::error::WalletError;

/// The most notes one split may make. A total large enough to need more than
/// this is refused rather than allocated.
const MAX_NOTES: u128 = 1_000_000;

/// Check that `amount` is an ESP note size: a power of two.
pub fn check_denomination(amount: u64) -> Result<(), WalletError> {
    if amount == 0 || !amount.is_power_of_two() {
        return Err(WalletError::Invalid(format!(
            "{amount} is not an ESP note size: use a power of two"
        )));
    }
    Ok(())
}

/// The fewest notes that add up to `total`, each a power of two, largest first.
/// Zero is no notes.
pub fn split(total: u128) -> Result<Vec<u64>, WalletError> {
    let top = 1u128 << 63;
    let whole = total / top;
    let rest = total % top;
    if whole + u128::from(rest.count_ones()) > MAX_NOTES {
        return Err(WalletError::Invalid(format!(
            "{total} ESP units is too much to split into notes"
        )));
    }
    let mut notes = vec![1u64 << 63; whole as usize];
    notes.extend(
        (0..63)
            .rev()
            .map(|bit| 1u64 << bit)
            .filter(|p| rest & u128::from(*p) != 0),
    );
    Ok(notes)
}

/// Exactly `n` notes that add up to `total`, each a power of two, largest first:
/// the fewest, with the largest note halved until there are `n`. `None` when
/// that cannot be done (fewer than the fewest, or more than `total`).
pub fn split_into(total: u128, n: usize) -> Option<Vec<u64>> {
    let mut notes = split(total).ok()?;
    if n < notes.len() || n as u128 > total {
        return None;
    }
    while notes.len() < n {
        let i = notes.iter().position(|&a| a > 1)?;
        let half = notes[i] / 2;
        notes[i] = half;
        notes.insert(i + 1, half);
    }
    Some(notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_total_splits_into_one_note_for_each_bit() {
        assert_eq!(split(0).unwrap(), Vec::<u64>::new());
        assert_eq!(split(1).unwrap(), vec![1]);
        assert_eq!(split(8).unwrap(), vec![8]);
        assert_eq!(split(13).unwrap(), vec![8, 4, 1]);
        // 1 PSP is 10^11 ESP units: 15 notes
        let one_psp = split(100_000_000_000).unwrap();
        assert_eq!(one_psp.len(), 15);
        assert_eq!(
            one_psp.iter().map(|&a| u128::from(a)).sum::<u128>(),
            100_000_000_000
        );
        assert!(one_psp.iter().all(|a| a.is_power_of_two()));
    }

    #[test]
    fn a_total_above_one_note_is_several_of_the_largest() {
        let top = 1u64 << 63;
        assert_eq!(split(1u128 << 63).unwrap(), vec![top]);
        assert_eq!(split((1u128 << 64) + 1).unwrap(), vec![top, top, 1]);
        assert!(split(u128::MAX).is_err());
    }

    #[test]
    fn a_split_into_n_halves_the_largest_until_there_are_n() {
        assert_eq!(split_into(13, 3).unwrap(), vec![8, 4, 1]);
        assert_eq!(split_into(13, 4).unwrap(), vec![4, 4, 4, 1]);
        assert_eq!(split_into(13, 13).unwrap(), vec![1; 13]);
        assert!(split_into(13, 2).is_none());
        assert!(split_into(13, 14).is_none());
        for n in 15..=100 {
            let notes = split_into(100_000_000_000, n).unwrap();
            assert_eq!(notes.len(), n);
            assert_eq!(
                notes.iter().map(|&a| u128::from(a)).sum::<u128>(),
                100_000_000_000
            );
            assert!(notes.iter().all(|a| a.is_power_of_two()));
        }
    }

    #[test]
    fn only_powers_of_two_are_note_sizes() {
        assert!(check_denomination(1).is_ok());
        assert!(check_denomination(1 << 63).is_ok());
        for bad in [0, 3, 6, 100, u64::MAX] {
            let e = check_denomination(bad).unwrap_err().to_string();
            assert!(e.contains("not an ESP note size"), "{e}");
        }
    }
}
