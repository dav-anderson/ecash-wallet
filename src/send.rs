//! PSP handed from one wallet to another (a developer to its app's user),
//! always settled at psp-mint.
//!
//! The sender exports chosen PSP notes as a token and keeps them as
//! pending-sent. The receiver imports the token and at once swaps every note
//! at psp-mint (`POST /rollover`: the same amounts, no fee) for notes only it
//! knows. That swap is what makes the receive final. If the mint finds any
//! note spent it refuses the whole swap, nothing is burned and the receiver
//! keeps nothing. The sender learns the outcome from the mint (`/check-state`):
//! all spent means received; none spent means it can be reclaimed (swapped
//! back by the sender); some spent means a conflict (the notes were used
//! elsewhere, so the receiver's swap was refused), and the rest can be
//! reclaimed.
//!
//! The swap request is stored in the wallet file before it is sent, keyed by
//! its request hash, so a crash between import and swap is finished by
//! sending the same request again; the mint answers a repeat from its record.

use secp256k1::{Keypair, SECP256K1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::blind::PendingOutput;
use crate::rotate::PendingRollover;
use crate::store::{Kind, StoredNote};
use crate::{Wallet, WalletError};

/// Every token starts with this.
pub const TOKEN_PREFIX: &str = "psp1";

/// One note in a token: what the receiver needs to spend it once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenNote {
    pub amount: u64,
    pub note: mint_types::Note,
    pub spend_secret: SecretKey,
    /// The keyset that signed the note, which the receiver's swap names.
    /// Empty in a token from before keysets were recorded.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keyset: String,
}

/// What a token carries: the mint and the notes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub mint: String,
    pub notes: Vec<TokenNote>,
}

impl Token {
    pub fn encode(&self) -> String {
        format!(
            "{TOKEN_PREFIX}{}",
            hex::encode(serde_json::to_vec(self).expect("serialisable"))
        )
    }
    pub fn decode(s: &str) -> Result<Token, WalletError> {
        let body = s
            .trim()
            .strip_prefix(TOKEN_PREFIX)
            .ok_or_else(|| WalletError::Invalid("not a PSP token".into()))?;
        let bytes = hex::decode(body).map_err(|e| WalletError::Invalid(format!("token: {e}")))?;
        let t: Token = serde_json::from_slice(&bytes)
            .map_err(|e| WalletError::Invalid(format!("token: {e}")))?;
        if t.notes.is_empty() {
            return Err(WalletError::Invalid("the token has no notes".into()));
        }
        if t.notes.len() > 1000 {
            return Err(WalletError::Invalid(
                "a token holds at most 1000 notes".into(),
            ));
        }
        Ok(t)
    }
    /// The token's id: a hash of its contents. The sender and the receiver
    /// both know it.
    pub fn id(&self) -> String {
        hex::encode(&Sha256::digest(self.encode().as_bytes())[..16])
    }
    pub fn total(&self) -> u128 {
        self.notes.iter().map(|n| n.amount as u128).sum()
    }
}

/// Where an exported token stands, as far as the sender knows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum SentState {
    /// Exported; the mint has not seen any of its notes spent.
    Pending,
    /// Being swapped back to this wallet by the stored request `rollover`.
    Reclaiming { rollover: String },
    /// Every note is spent at the mint: received (final).
    Received,
    /// Some notes were spent elsewhere, so the receiver's swap was refused.
    /// The unspent ones are still here and can be reclaimed.
    Conflict { spent_elsewhere: usize },
    /// Swapped back to this wallet (final).
    Reclaimed,
}

/// An exported token, kept by the sender until it is settled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentToken {
    pub id: String,
    pub mint: String,
    pub amount: u128,
    /// The notes still unsettled. Emptied once the token is final.
    pub notes: Vec<StoredNote>,
    #[serde(flatten)]
    pub state: SentState,
}

/// What an import ended in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Received {
    /// The swap went through: the new notes are in the wallet.
    Final { amount: u128 },
    /// The mint refused the swap (a note was spent): nothing was kept.
    Rejected { why: String },
}

pub(crate) fn receive_tag(token_id: &str) -> String {
    format!("receive|{token_id}")
}
pub(crate) fn reclaim_tag(token_id: &str) -> String {
    format!("reclaim|{token_id}")
}

/// Build (not send) a psp-mint swap of `notes` for fresh notes of the same
/// amounts. The inputs are not taken from the wallet's own notes.
pub(crate) fn build_psp_swap(
    url: &str,
    notes: &[TokenNote],
    tag: String,
    current: &str,
) -> Result<PendingRollover, WalletError> {
    let outputs: Vec<PendingOutput> = notes.iter().map(|n| PendingOutput::new(n.amount)).collect();
    let mint_outputs: Vec<_> = outputs.iter().map(|o| o.mint_output()).collect();
    let mut inputs: Vec<mint_types::MintInput> = notes
        .iter()
        .map(|n| mint_types::MintInput {
            amount: mint_types::Amount::from_units(n.amount),
            note: n.note,
            spend_signature: secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).expect("64"),
        })
        .collect();
    let h = mint_types::transaction_sighash(&inputs, &mint_outputs);
    for (i, n) in inputs.iter_mut().zip(notes) {
        i.spend_signature =
            SECP256K1.sign_schnorr(&h, &Keypair::from_secret_key(SECP256K1, &n.spend_secret));
    }
    let r = sp_wire::psp::RolloverRequest {
        input_keysets: notes
            .iter()
            .map(|n| {
                if n.keyset.is_empty() {
                    Err(WalletError::Invalid(
                        "a note in the token names no keyset; it is refused (ask the sender for a token that names each note's keyset)".into(),
                    ))
                } else {
                    Ok(n.keyset.clone())
                }
            })
            .collect::<Result<_, _>>()?,
        inputs,
        keyset: current.to_string(),
        outputs: mint_outputs,
    };
    Ok(PendingRollover {
        id: r.hash(),
        kind: Kind::Psp,
        url: url.to_string(),
        body: serde_json::to_value(&r).map_err(|e| WalletError::Invalid(e.to_string()))?,
        inputs: notes
            .iter()
            .map(|n| hex::encode(n.note.nonce.0.serialize()))
            .collect(),
        outputs,
        terms: None,
        schedule: tag,
    })
}

fn token_note(n: &StoredNote, keyset: Option<&String>) -> TokenNote {
    TokenNote {
        amount: n.amount,
        note: n.note,
        spend_secret: n.spend_secret,
        keyset: keyset.cloned().unwrap_or_default(),
    }
}

/// The keyset a swap at `url` asks its outputs to be signed with: the mint's
/// current keyset as last seen, or, if this wallet has not seen it yet, the
/// first note's (the mint signs with any live keyset named, and refuses one
/// that is retired or unknown).
pub(crate) fn swap_keyset(live: Option<&(String, Option<String>)>, notes: &[TokenNote]) -> String {
    live.map(|(c, _)| c.clone())
        .or_else(|| {
            notes
                .iter()
                .map(|n| n.keyset.clone())
                .find(|k| !k.is_empty())
        })
        .unwrap_or_default()
}

impl Wallet {
    /// Export PSP notes by id as a token, and move them to pending-sent in the
    /// same write. Notes reserved by another request cannot be sent.
    pub fn export_psp(&mut self, mint: &str, ids: &[String]) -> Result<String, WalletError> {
        let picked: Vec<StoredNote> = self
            .notes()
            .iter()
            .filter(|n| ids.contains(&n.id()))
            .cloned()
            .collect();
        if picked.is_empty() || picked.len() != ids.len() {
            return Err(WalletError::Invalid(
                "some of those notes are not in this wallet".into(),
            ));
        }
        if let Some(n) = picked
            .iter()
            .find(|n| n.kind != Kind::Psp || n.reserved_by.is_some())
        {
            return Err(WalletError::Invalid(format!(
                "note {} is not a free PSP note",
                n.id()
            )));
        }
        let token = Token {
            mint: mint.to_string(),
            notes: picked
                .iter()
                .map(|n| token_note(n, self.data().keysets.get(&n.id())))
                .collect(),
        };
        let id = token.id();
        let amount = token.total();
        self.update(|d| {
            d.notes.retain(|n| !ids.contains(&n.id()));
            d.sent.push(SentToken {
                id,
                mint: mint.to_string(),
                amount,
                notes: picked,
                state: SentState::Pending,
            });
            Ok(())
        })?;
        Ok(token.encode())
    }

    /// Export free PSP notes adding up to exactly `amount` (largest first).
    pub fn export_psp_amount(&mut self, mint: &str, amount: u128) -> Result<String, WalletError> {
        let mut free: Vec<&StoredNote> = self
            .notes()
            .iter()
            .filter(|n| n.kind == Kind::Psp && n.reserved_by.is_none())
            .collect();
        free.sort_by(|a, b| b.amount.cmp(&a.amount));
        let (mut left, mut ids) = (amount, Vec::new());
        for n in free {
            if n.amount as u128 <= left {
                left -= n.amount as u128;
                ids.push(n.id());
            }
        }
        if left != 0 || ids.is_empty() {
            return Err(WalletError::Invalid(format!(
                "no free PSP notes add up to exactly {amount}; swap for smaller notes first"
            )));
        }
        self.export_psp(mint, &ids)
    }

    pub fn sent_tokens(&self) -> &[SentToken] {
        &self.data().sent
    }

    /// Store the swap for an imported token, before anything is sent. A token
    /// imported twice gives the same stored swap.
    pub fn begin_receive(&mut self, token: &Token) -> Result<String, WalletError> {
        let tag = receive_tag(&token.id());
        if let Some(p) = self.pending_rollovers().iter().find(|p| p.schedule == tag) {
            return Ok(p.id.clone());
        }
        let current = swap_keyset(self.data().live_keysets.get(&token.mint), &token.notes);
        let p = build_psp_swap(&token.mint, &token.notes, tag, &current)?;
        let id = p.id.clone();
        self.update(|d| {
            d.pending_rollovers.push(p);
            Ok(())
        })?;
        Ok(id)
    }

    /// The mint's answer for a sent token's notes (`spent[i]` for `notes[i]`).
    pub fn settle_sent(
        &mut self,
        token_id: &str,
        spent: &[bool],
    ) -> Result<SentState, WalletError> {
        self.update(|d| {
            let t = d
                .sent
                .iter_mut()
                .find(|t| t.id == token_id)
                .ok_or_else(|| WalletError::Invalid(format!("no sent token {token_id}")))?;
            if spent.len() != t.notes.len() {
                return Err(WalletError::Mint(
                    "check-state does not fit the token".into(),
                ));
            }
            let n = spent.iter().filter(|s| **s).count();
            t.state = if n == 0 {
                SentState::Pending
            } else if n == spent.len() {
                t.notes.clear();
                if matches!(t.state, SentState::Conflict { .. }) {
                    t.state.clone()
                } else {
                    SentState::Received
                }
            } else {
                let prev = match t.state {
                    SentState::Conflict { spent_elsewhere } => spent_elsewhere,
                    _ => 0,
                };
                let mut k = 0;
                t.notes.retain(|_| {
                    let keep = !spent[k];
                    k += 1;
                    keep
                });
                SentState::Conflict {
                    spent_elsewhere: prev + n,
                }
            };
            Ok(t.state.clone())
        })
    }

    /// Store a swap of a sent token's notes back to this wallet.
    pub fn begin_reclaim(&mut self, token_id: &str) -> Result<String, WalletError> {
        let t = self
            .sent_tokens()
            .iter()
            .find(|t| t.id == token_id)
            .cloned()
            .ok_or_else(|| WalletError::Invalid(format!("no sent token {token_id}")))?;
        if let SentState::Reclaiming { rollover } = &t.state {
            return Ok(rollover.clone());
        }
        if t.notes.is_empty() {
            return Err(WalletError::Invalid("nothing is left to reclaim".into()));
        }
        let notes: Vec<TokenNote> = t
            .notes
            .iter()
            .map(|n| token_note(n, self.data().keysets.get(&n.id())))
            .collect();
        let current = swap_keyset(self.data().live_keysets.get(&t.mint), &notes);
        let p = build_psp_swap(&t.mint, &notes, reclaim_tag(token_id), &current)?;
        let id = p.id.clone();
        self.update(|d| {
            d.pending_rollovers.push(p);
            if let Some(t) = d.sent.iter_mut().find(|t| t.id == token_id) {
                t.state = SentState::Reclaiming {
                    rollover: id.clone(),
                };
            }
            Ok(())
        })?;
        Ok(id)
    }

    /// After a stored swap was answered: a reclaim that went through makes the
    /// token final as reclaimed; one that was refused puts it back to pending
    /// so the mint is asked again.
    pub(crate) fn after_swap(&mut self, tag: &str, ok: bool) -> Result<(), WalletError> {
        let Some(token_id) = tag.strip_prefix("reclaim|") else {
            return Ok(());
        };
        self.update(|d| {
            if let Some(t) = d.sent.iter_mut().find(|t| t.id == token_id) {
                if ok {
                    t.notes.clear();
                    t.state = SentState::Reclaimed;
                } else {
                    t.state = SentState::Pending;
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_round_trips_and_garbage_is_refused() {
        let kp = Keypair::new(SECP256K1, &mut rand::rngs::OsRng);
        let t = Token {
            mint: "http://m".into(),
            notes: vec![TokenNote {
                amount: 4,
                note: mint_types::Note {
                    nonce: mint_types::Nonce(kp.public_key()),
                    signature: kp.public_key(),
                },
                spend_secret: kp.secret_key(),
                keyset: "0123456789abcdef".into(),
            }],
        };
        let s = t.encode();
        assert!(s.starts_with("psp1"));
        assert_eq!(Token::decode(&s).unwrap(), t);
        assert!(Token::decode("psp1zz").is_err());
        assert!(Token::decode(&s[4..]).is_err());
    }
}
