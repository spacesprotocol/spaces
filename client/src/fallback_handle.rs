//! Resolve SIP-7 fallback payloads by scanning indexed block metadata for TXT `handle=…`
//! or by wildcard pattern matching across spaces and handles.

use std::collections::BTreeMap;
use spaces_nums::TxChangeSet as NumTxChangeSet;
use spaces_protocol::bitcoin::BlockHash;
use spaces_protocol::{validate::TxChangeSet as SpaceTxChangeSet, Covenant};
use sip7::Record;

use crate::client::{BlockMeta, NumBlockMeta};
use crate::store::chain::Chain;

/// Simple glob match supporting `*` (zero or more chars) and `?` (exactly one char).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_impl(&p, &t)
}

fn glob_impl(p: &[char], t: &[char]) -> bool {
    match (p.first(), t.first()) {
        (None, None) => true,
        (Some(&'*'), _) => {
            glob_impl(&p[1..], t) || (!t.is_empty() && glob_impl(p, &t[1..]))
        }
        (Some(&'?'), Some(_)) => glob_impl(&p[1..], &t[1..]),
        (Some(&a), Some(&b)) if a == b => glob_impl(&p[1..], &t[1..]),
        _ => false,
    }
}

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

/// Extract all values of TXT records with the given `txt_key` from a SIP-7 payload.
fn sip7_txt_values(data: &[u8], txt_key: &str) -> Vec<String> {
    let rs = sip7::RecordSet::new(data.to_vec());
    let Ok(records) = rs.unpack() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for r in records {
        if let Record::Txt { key, value } = r {
            if key == txt_key {
                out.extend(value.into_iter());
            }
        }
    }
    out
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

/// True if `pattern` is a space-name pattern (starts with `@` or contains no `@`).
/// Patterns with content before `@` (e.g. `*@mad`) are handle patterns.
fn is_space_pattern(pattern: &str) -> bool {
    match pattern.find('@') {
        Some(0) => true,   // @* or @m?d
        Some(_) => false,  // *@mad, dict*@*
        None => true,      // * or m?d (no @, treated as space)
    }
}

/// Scan all indexed payloads for SIP-7 TXT records with the given `txt_key`, returning
/// `BTreeMap<matched_value, raw_payload>` for values matching `pattern` (latest per value wins).
pub(crate) fn merge_scan_txt_wildcard(
    spaces_rows: &[(u32, BlockHash, BlockMeta)],
    nums_rows: &[(u32, BlockHash, NumBlockMeta)],
    txt_key: &str,
    pattern: &str,
) -> BTreeMap<String, Vec<u8>> {
    let mut latest: BTreeMap<String, (u32, u32, Vec<u8>)> = BTreeMap::new();

    let mut i = 0usize;
    let mut j = 0usize;

    loop {
        let h_sp = spaces_rows.get(i).map(|r| r.0);
        let h_nm = nums_rows.get(j).map(|r| r.0);
        let h = match (h_sp, h_nm) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => break,
        };

        let mut events: Vec<(u32, Vec<u8>)> = Vec::new();
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
            for val in sip7_txt_values(&pl, txt_key) {
                if glob_match(pattern, &val) {
                    let entry = latest.entry(val).or_insert((0, 0, Vec::new()));
                    if (h, pos) >= (entry.0, entry.1) {
                        *entry = (h, pos, pl.clone());
                    }
                }
            }
        }
    }

    latest
        .into_iter()
        .map(|(k, (_, _, payload))| (k, payload))
        .collect()
}

/// Search for fallback payloads matching a wildcard pattern.
/// Space patterns (`@*`, `@m?d`) match TXT records with key `"space"`.
/// Handle patterns (`*@mad`, `*@*`) match TXT records with key `"handle"`.
pub fn search_fallback_by_pattern(
    chain: &Chain,
    pattern: &str,
) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    if !chain.has_spaces_index() {
        anyhow::bail!(
            "wildcard lookup requires the spaces block index; run spaced with --block-index"
        );
    }

    let spaces_rows = chain.list_spaces_blocks_merged()?;
    let nums_rows = if chain.has_nums_index() {
        chain.list_nums_blocks_merged()?
    } else {
        Vec::new()
    };

    let txt_key = if is_space_pattern(pattern) { "space" } else { "handle" };
    Ok(merge_scan_txt_wildcard(&spaces_rows, &nums_rows, txt_key, pattern))
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

    fn sample_handle_payload(handle: &str) -> Vec<u8> {
        sip7::RecordSet::pack(vec![
            sip7::Record::seq(1),
            sip7::Record::txt("handle", &[handle]),
        ])
        .expect("pack")
        .to_bytes()
    }

    fn sample_space_payload(space: &str) -> Vec<u8> {
        sip7::RecordSet::pack(vec![
            sip7::Record::seq(1),
            sip7::Record::txt("space", &[space]),
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
        let pl = sample_handle_payload("dictionary@mad");
        assert!(sip7_handle_matches(&pl, "dictionary@mad"));
        assert!(!sip7_handle_matches(&pl, "other@mad"));
    }

    #[test]
    fn merge_scan_picks_latest_height() {
        let h = BlockHash::all_zeros();
        let want = sample_handle_payload("dictionary@mad");
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
        let want = sample_handle_payload("dictionary@mad");
        let meta = BlockMeta {
            height: 10,
            tx_meta: vec![
                tx_entry_with_payload(10, 1, sample_handle_payload("wrong@x")),
                tx_entry_with_payload(10, 3, want.clone()),
            ],
        };
        let rows = vec![(10, h, meta)];
        let got = merge_scan_fallback(&rows, &[], "dictionary@mad").expect("match");
        assert_eq!(got, want);
    }

    // --- glob matcher tests ---

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("@mad", "@mad"));
        assert!(!glob_match("@mad", "@bad"));
    }

    #[test]
    fn glob_match_star() {
        assert!(glob_match("*@mad", "dictionary@mad"));
        assert!(glob_match("*@mad", "x@mad"));
        assert!(glob_match("*@mad", "@mad"));
        assert!(!glob_match("*@mad", "dictionary@bad"));
    }

    #[test]
    fn glob_match_star_at_star() {
        assert!(glob_match("*@*", "dictionary@mad"));
        assert!(glob_match("*@*", "a@b"));
        assert!(!glob_match("*@*", "noatsign"));
    }

    #[test]
    fn glob_match_question() {
        assert!(glob_match("d?ct@mad", "dict@mad"));
        assert!(glob_match("d?ct@mad", "duct@mad"));
        assert!(!glob_match("d?ct@mad", "dct@mad"));
        assert!(!glob_match("d?ct@mad", "dabct@mad"));
    }

    #[test]
    fn glob_match_at_star_spaces() {
        assert!(glob_match("@*", "@mad"));
        assert!(glob_match("@*", "@bitcoin"));
        assert!(!glob_match("@*", "mad"));
    }

    // --- space-pattern wildcard scan tests (txt key="space") ---

    #[test]
    fn space_wildcard_returns_matching_space_txt() {
        let h = BlockHash::all_zeros();
        let mad_pl = sample_space_payload("@mad");
        let btc_pl = sample_space_payload("@bitcoin");
        let meta = BlockMeta {
            height: 10,
            tx_meta: vec![
                tx_entry_with_payload(10, 0, mad_pl.clone()),
                tx_entry_with_payload(10, 1, btc_pl.clone()),
            ],
        };
        let rows = vec![(10, h, meta)];
        let result = merge_scan_txt_wildcard(&rows, &[], "space", "@*");
        assert_eq!(result.len(), 2);
        assert_eq!(result["@mad"], mad_pl);
        assert_eq!(result["@bitcoin"], btc_pl);
    }

    #[test]
    fn space_wildcard_filters_by_pattern() {
        let h = BlockHash::all_zeros();
        let mad_pl = sample_space_payload("@mad");
        let btc_pl = sample_space_payload("@bitcoin");
        let meta = BlockMeta {
            height: 10,
            tx_meta: vec![
                tx_entry_with_payload(10, 0, mad_pl.clone()),
                tx_entry_with_payload(10, 1, btc_pl),
            ],
        };
        let rows = vec![(10, h, meta)];
        let result = merge_scan_txt_wildcard(&rows, &[], "space", "@m*");
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("@mad"));
    }

    #[test]
    fn space_wildcard_latest_overwrites() {
        let h = BlockHash::all_zeros();
        let old_pl = sample_space_payload("@mad");
        let new_pl = sample_space_payload("@mad");
        let block1 = BlockMeta {
            height: 10,
            tx_meta: vec![tx_entry_with_payload(10, 0, old_pl)],
        };
        let block2 = BlockMeta {
            height: 20,
            tx_meta: vec![tx_entry_with_payload(20, 0, new_pl.clone())],
        };
        let rows = vec![(10, h, block1), (20, h, block2)];
        let result = merge_scan_txt_wildcard(&rows, &[], "space", "@*");
        assert_eq!(result["@mad"], new_pl);
    }

    #[test]
    fn space_wildcard_ignores_handle_key() {
        let h = BlockHash::all_zeros();
        let handle_pl = sample_handle_payload("@mad");
        let meta = BlockMeta {
            height: 10,
            tx_meta: vec![tx_entry_with_payload(10, 0, handle_pl)],
        };
        let rows = vec![(10, h, meta)];
        let result = merge_scan_txt_wildcard(&rows, &[], "space", "@*");
        assert!(result.is_empty(), "handle-keyed records should not match a space pattern");
    }

    // --- handle-pattern wildcard scan tests (txt key="handle") ---

    #[test]
    fn handle_wildcard_returns_matching_handles() {
        let h = BlockHash::all_zeros();
        let meta = BlockMeta {
            height: 10,
            tx_meta: vec![
                tx_entry_with_payload(10, 0, sample_handle_payload("dictionary@mad")),
                tx_entry_with_payload(10, 1, sample_handle_payload("other@mad")),
                tx_entry_with_payload(10, 2, sample_handle_payload("foo@bar")),
            ],
        };
        let rows = vec![(10, h, meta)];
        let result = merge_scan_txt_wildcard(&rows, &[], "handle", "*@mad");
        assert_eq!(result.len(), 2);
        assert!(result.contains_key("dictionary@mad"));
        assert!(result.contains_key("other@mad"));
        assert!(!result.contains_key("foo@bar"));
    }

    #[test]
    fn handle_wildcard_star_at_star_returns_all() {
        let h = BlockHash::all_zeros();
        let meta = BlockMeta {
            height: 10,
            tx_meta: vec![
                tx_entry_with_payload(10, 0, sample_handle_payload("dictionary@mad")),
                tx_entry_with_payload(10, 1, sample_handle_payload("foo@bar")),
            ],
        };
        let rows = vec![(10, h, meta)];
        let result = merge_scan_txt_wildcard(&rows, &[], "handle", "*@*");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn handle_wildcard_latest_per_handle() {
        let h = BlockHash::all_zeros();
        let old_pl = sample_handle_payload("dictionary@mad");
        let new_pl = sample_handle_payload("dictionary@mad");
        let block1 = BlockMeta {
            height: 10,
            tx_meta: vec![tx_entry_with_payload(10, 0, old_pl)],
        };
        let block2 = BlockMeta {
            height: 20,
            tx_meta: vec![tx_entry_with_payload(20, 0, new_pl.clone())],
        };
        let rows = vec![(10, h, block1), (20, h, block2)];
        let result = merge_scan_txt_wildcard(&rows, &[], "handle", "*@*");
        assert_eq!(result.len(), 1);
        assert_eq!(result["dictionary@mad"], new_pl);
    }

    #[test]
    fn handle_wildcard_ignores_space_key() {
        let h = BlockHash::all_zeros();
        let space_pl = sample_space_payload("dictionary@mad");
        let meta = BlockMeta {
            height: 10,
            tx_meta: vec![tx_entry_with_payload(10, 0, space_pl)],
        };
        let rows = vec![(10, h, meta)];
        let result = merge_scan_txt_wildcard(&rows, &[], "handle", "*@*");
        assert!(result.is_empty(), "space-keyed records should not match a handle pattern");
    }

    // --- is_space_pattern tests ---

    #[test]
    fn pattern_classification() {
        assert!(is_space_pattern("@*"));
        assert!(is_space_pattern("@m?d"));
        assert!(is_space_pattern("*"));
        assert!(is_space_pattern("m?d"));
        assert!(!is_space_pattern("*@mad"));
        assert!(!is_space_pattern("*@*"));
        assert!(!is_space_pattern("dict*@mad"));
    }
}
