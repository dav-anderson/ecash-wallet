//! Records from before the PSP handoff had its own reclaim: the tokens that
//! `send-psp` kept as "pending-sent" (wallet 0.4.0 and earlier).
//!
//! `send-psp`, `receive-psp`, `sent` and the `psp1` token are gone. What stays
//! is the record they left in a wallet file (`sent`), because the notes in it
//! are still owed to the wallet that sent them. **They are migrated, not kept
//! as a second kind of record:** when a wallet file is opened (and when two
//! copies are merged), every [`SentToken`] becomes an
//! [`OutgoingHandoff`](crate::handoff::OutgoingHandoff) with the token's id, and
//! `handoff check ID` and `handoff reclaim ID` work on it like on any PSP
//! handoff. The file is rewritten without `sent` on the next save. Nothing here
//! reads or writes a token string.
//!
//! The mapping, state by state:
//!
//! | `sent` state | becomes |
//! |---|---|
//! | `pending` | a pending handoff holding the notes |
//! | `reclaiming` (a swap back is stored) | a pending handoff holding the notes, with that swap as its reclaim; the stored swap (`reclaim\|<id>`) is sent again as before |
//! | `received` | a done handoff |
//! | `conflict` with notes left | a pending handoff holding the rest, with the count of notes spent elsewhere |
//! | `conflict` with none left | a done handoff |
//! | `reclaimed` | a reclaimed handoff |
//!
//! A swap that `receive-psp` stored and did not get to send (`receive|<id>`) is
//! also still sent again at the next sync, as before. Those notes were never in
//! the wallet (it holds only the signed request, not their secrets), so they
//! are not in the balance until the swap goes through;
//! [`Wallet::legacy_receive_psp`](crate::Wallet::legacy_receive_psp) says how
//! much is waiting.

use serde::{Deserialize, Serialize};

use crate::handoff::{HandoffKind, HandoffState, OutgoingHandoff};
use crate::store::StoredNote;

/// The tag of a swap that `receive-psp` stored (`receive|<token id>`).
pub(crate) const RECEIVE_TAG: &str = "receive|";

/// Where an exported token stood, as far as the sender knew.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum SentState {
    /// Exported; the mint had not seen any of its notes spent.
    Pending,
    /// Being swapped back to this wallet by the stored request `rollover`.
    Reclaiming { rollover: String },
    /// Every note was spent at the mint: received (final).
    Received,
    /// Some notes were spent elsewhere. The unspent ones are still here.
    Conflict { spent_elsewhere: usize },
    /// Swapped back to this wallet (final).
    Reclaimed,
}

/// An exported token, kept by the sender until it was settled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentToken {
    pub id: String,
    pub mint: String,
    pub amount: u128,
    /// The notes still unsettled. Emptied once the token was final.
    pub notes: Vec<StoredNote>,
    #[serde(flatten)]
    pub state: SentState,
}

impl SentToken {
    /// This record as a PSP handoff record (see the module documentation).
    pub fn into_handoff(self) -> OutgoingHandoff {
        let SentToken {
            id,
            mint,
            amount,
            mut notes,
            state,
        } = self;
        let note_count = notes.len();
        let (state, reclaim, spent_elsewhere) = match state {
            SentState::Pending => (HandoffState::Pending, None, 0),
            SentState::Reclaiming { rollover } => (HandoffState::Pending, Some(rollover), 0),
            SentState::Received => (HandoffState::Done, None, 0),
            SentState::Conflict { spent_elsewhere } if notes.is_empty() => {
                (HandoffState::Done, None, spent_elsewhere)
            }
            SentState::Conflict { spent_elsewhere } => {
                (HandoffState::Pending, None, spent_elsewhere)
            }
            SentState::Reclaimed => (HandoffState::Reclaimed, None, 0),
        };
        if state != HandoffState::Pending {
            notes.clear();
        }
        OutgoingHandoff {
            id,
            state,
            kind: HandoffKind::Psp,
            psp_units: amount,
            fsp_units: 0,
            note_count,
            with_did_key: false,
            notes,
            mint,
            reclaim,
            spent_elsewhere,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stored_shape_still_reads() {
        let pending: SentToken = serde_json::from_str(
            r#"{"id":"ab","mint":"http://m","amount":5,"notes":[],"state":"pending"}"#,
        )
        .unwrap();
        assert_eq!(pending.state, SentState::Pending);
        let reclaiming: SentToken = serde_json::from_str(
            r#"{"id":"ab","mint":"http://m","amount":5,"notes":[],"state":"reclaiming","rollover":"r1"}"#,
        )
        .unwrap();
        assert_eq!(
            reclaiming.state,
            SentState::Reclaiming {
                rollover: "r1".into()
            }
        );
        let conflict: SentToken = serde_json::from_str(
            r#"{"id":"ab","mint":"http://m","amount":5,"notes":[],"state":"conflict","spent_elsewhere":2}"#,
        )
        .unwrap();
        assert_eq!(conflict.state, SentState::Conflict { spent_elsewhere: 2 });
    }

    #[test]
    fn every_state_maps_to_a_handoff_state() {
        let token = |state| SentToken {
            id: "ab".into(),
            mint: "http://m".into(),
            amount: 5,
            notes: vec![],
            state,
        };
        let map = |s| token(s).into_handoff();
        assert_eq!(map(SentState::Pending).state, HandoffState::Pending);
        let r = map(SentState::Reclaiming {
            rollover: "r1".into(),
        });
        assert_eq!(
            (r.state, r.reclaim.as_deref()),
            (HandoffState::Pending, Some("r1"))
        );
        assert_eq!(map(SentState::Received).state, HandoffState::Done);
        let c = map(SentState::Conflict { spent_elsewhere: 3 });
        assert_eq!((c.state, c.spent_elsewhere), (HandoffState::Done, 3));
        assert_eq!(map(SentState::Reclaimed).state, HandoffState::Reclaimed);
        let h = map(SentState::Pending);
        assert_eq!(
            (h.kind, h.mint.as_str(), h.psp_units),
            (HandoffKind::Psp, "http://m", 5)
        );
    }
}
