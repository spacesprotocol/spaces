//! Resolve SIP-7 fallback payloads by scanning indexed block metadata for TXT `handle=…`.

use spaces_nums::TxChangeSet as NumTxChangeSet;
use spaces_protocol::bitcoin::BlockHash;
use spaces_protocol::{validate::TxChangeSet as SpaceTxChangeSet, Covenant};
use sip7::Record;

use crate::client::{BlockMeta, NumBlockMeta};
use crate::store::chain::Chain;

/// True if the SIP-7 payload parses and contains a TXT record with key `handle` whose value
/// equals `needle` (exact UTF-8; any chunk in a multi-value TXT matches).
pub fn sip7_handle_matches(data: &[u8], needle: &str) -> bool {
    let rs = sip7::RecordSet::new(data.to_vec());
    let Ok(records) = rs.unpack() else {
        return false;
    };
    for r in records {
        if let Record::Txt { key, value } = r {
            if key == "handle" && value.iter().any(|v| v == needle) {
                return true;
            }
        }
    }
    false
}

fn transfer_data_from_space_changeset(changeset: &SpaceTxChangeSet) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for c in &changeset.creates {
        if let Some(space) = &c.space {
            if let Covenant::Transfer { data: Some(b), .. } = &space.covenant {
                out.push(b.clone().to_vec());
            }
        }
    }
    for u in &changeset.updates {
        if let Some(space) = &u.output.spaceout.space {
            if let Covenant::Transfer { data: Some(b), .. } = &space.covenant {
                out.push(b.clone().to_vec());
            }
        }
    }
    out
}

fn data_from_num_changeset(changeset: &NumTxChangeSet) -> Vec<Vec<u8>> {
    changeset
        .creates
        .iter()
        .filter_map(|n| n.num.data.as_ref().map(|b| b.clone().to_vec()))
        .collect()
}

fn space_events_for_block(meta: &BlockMeta) -> Vec<(u32, Vec<u8>)> {
    let mut out = Vec::new();
    for tx in &meta.tx_meta {
        let pos = tx.tx.as_ref().map(|t| t.position).unwrap_or(u32::MAX);
        for pl in transfer_data_from_space_changeset(&tx.changeset) {
            out.push((pos, pl));
        }
    }
    out
}

fn num_events_for_block(meta: &NumBlockMeta) -> Vec<(u32, Vec<u8>)> {
    let mut out = Vec::new();
    for tx in &meta.tx_meta {
        let pos = tx.tx.as_ref().map(|t| t.position).unwrap_or(u32::MAX);
        for pl in data_from_num_changeset(&tx.changeset) {
            out.push((pos, pl));
        }
    }
    out
}

/// Latest matching raw SIP-7 bytes in chain order (height, then block tx index when known).
pub(crate) fn merge_scan_fallback(
    spaces_rows: &[(u32, BlockHash, BlockMeta)],
    nums_rows: &[(u32, BlockHash, NumBlockMeta)],
    needle: &str,
) -> Option<Vec<u8>> {
    let mut i = 0usize;
    let mut j = 0usize;
    let mut best: Option<(u32, u32, Vec<u8>)> = None;

    loop {
        let h_sp = spaces_rows.get(i).map(|r| r.0);
        let h_nm = nums_rows.get(j).map(|r| r.0);
        let h = match (h_sp, h_nm) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => break,
        };

        let mut events = Vec::new();
        if h_sp == Some(h) {
            events.extend(space_events_for_block(&spaces_rows[i].2));
            i += 1;
        }
        if h_nm == Some(h) {
            events.extend(num_events_for_block(&nums_rows[j].2));
            j += 1;
        }

        events.sort_by_key(|(pos, _)| *pos);
        for (pos, pl) in events {
            if sip7_handle_matches(&pl, needle) {
                best = Some((h, pos, pl));
            }
        }
    }

    best.map(|(_, _, v)| v)
}

/// Latest matching raw SIP-7 bytes in chain order (height, then block tx index when known).
pub fn find_fallback_payload_by_handle(chain: &Chain, needle: &str) -> anyhow::Result<Option<Vec<u8>>> {
    if !chain.has_spaces_index() {
        anyhow::bail!(
            "handle lookup requires the spaces block index; run spaced with --block-index"
        );
    }

    let spaces_rows = chain.list_spaces_blocks_merged()?;
    let nums_rows = if chain.has_nums_index() {
        chain.list_nums_blocks_merged()?
    } else {
        Vec::new()
    };

    Ok(merge_scan_fallback(&spaces_rows, &nums_rows, needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use spaces_protocol::bitcoin::hashes::Hash as _;
    use spaces_protocol::bitcoin::{Amount, BlockHash, ScriptBuf, Txid};
    use spaces_protocol::slabel::SLabel;
    use spaces_protocol::validate::TxChangeSet;
    use spaces_protocol::{Bytes, Space, SpaceOut};
    use std::str::FromStr as _;

    use crate::client::{BlockMeta, TxData, TxEntry};

    fn sample_payload(handle: &str) -> Vec<u8> {
        sip7::RecordSet::pack(vec![
            sip7::Record::seq(1),
            sip7::Record::txt("handle", &[handle]),
        ])
        .expect("pack")
        .to_bytes()
    }

    fn tx_entry_with_payload(height: u32, tx_pos: u32, payload: Vec<u8>) -> TxEntry {
        let space_out = SpaceOut {
            n: 0,
            space: Some(Space {
                name: SLabel::from_str("@test").expect("label"),
                covenant: Covenant::Transfer {
                    expire_height: height + 1000,
                    data: Some(Bytes::new(payload)),
                },
            }),
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        };
        let cs = TxChangeSet {
            txid: Txid::all_zeros(),
            spends: vec![],
            creates: vec![space_out],
            updates: vec![],
        };
        TxEntry {
            changeset: cs,
            tx: Some(TxData {
                position: tx_pos,
                raw: Bytes::new(Vec::new()),
            }),
        }
    }

    #[test]
    fn sip7_handle_matches_respects_key_and_value() {
        let pl = sample_payload("dictionary@mad");
        assert!(sip7_handle_matches(&pl, "dictionary@mad"));
        assert!(!sip7_handle_matches(&pl, "other@mad"));
    }

    #[test]
    fn merge_scan_picks_latest_height() {
        let h = BlockHash::all_zeros();
        let want = sample_payload("dictionary@mad");
        let older = BlockMeta {
            height: 10,
            tx_meta: vec![tx_entry_with_payload(10, 0, want.clone())],
        };
        let newer = BlockMeta {
            height: 20,
            tx_meta: vec![tx_entry_with_payload(20, 0, want.clone())],
        };
        let rows = vec![(10, h, older), (20, h, newer)];
        let got = merge_scan_fallback(&rows, &[], "dictionary@mad").expect("match");
        assert_eq!(got, want);
    }

    #[test]
    fn merge_scan_picks_later_tx_position_same_block() {
        let h = BlockHash::all_zeros();
        let want = sample_payload("dictionary@mad");
        let meta = BlockMeta {
            height: 10,
            tx_meta: vec![
                tx_entry_with_payload(10, 1, sample_payload("wrong@x")),
                tx_entry_with_payload(10, 3, want.clone()),
            ],
        };
        let rows = vec![(10, h, meta)];
        let got = merge_scan_fallback(&rows, &[], "dictionary@mad").expect("match");
        assert_eq!(got, want);
    }
}
