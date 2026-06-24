//! Consensus edge-case tests for the nums validator, run against
//! `Validator::process` directly with a mock `NumSource`. These pin behavior
//! that the regtest integration suite can't easily reach: successor-claim
//! collisions, the mint/revival opt-in gates, value-dispatched intent
//! (77 mint / 88 revive), and the independence of identity and rebind slots.

use std::collections::HashMap;

use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use spaces_nums::num_id::NumId;
use spaces_nums::snumeric::SNumeric;
use spaces_nums::{
    Num, NumOut, NumSource, RebindData, RebindKey, TxChangeSet, TxContext, Validator,
};
use spaces_protocol::hasher::KeyHasher;
use spaces_protocol::SpaceOut;

const HEIGHT: u32 = 100;
const TX_POS: u16 = 3;

struct TestHasher;

impl KeyHasher for TestHasher {
    fn hash(data: &[u8]) -> spaces_protocol::hasher::Hash {
        sha256::Hash::hash(data).to_byte_array()
    }
}

#[derive(Default)]
struct MockSrc {
    numouts: HashMap<OutPoint, NumOut>,
    identities: HashMap<NumId, OutPoint>,
    rebinds: HashMap<RebindKey, RebindData>,
}

impl NumSource for MockSrc {
    fn get_num_outpoint_by_id(
        &mut self,
        id: &NumId,
    ) -> spaces_protocol::errors::Result<Option<OutPoint>> {
        Ok(self.identities.get(id).copied())
    }

    fn get_num_rebind(
        &mut self,
        key: &RebindKey,
    ) -> spaces_protocol::errors::Result<Option<RebindData>> {
        Ok(self.rebinds.get(key).cloned())
    }

    fn get_commitment(
        &mut self,
        _key: &spaces_nums::CommitmentKey,
    ) -> spaces_protocol::errors::Result<Option<spaces_nums::Commitment>> {
        Ok(None)
    }

    fn get_commitments_tip(
        &mut self,
        _key: &spaces_nums::CommitmentTipKey,
    ) -> spaces_protocol::errors::Result<Option<spaces_protocol::hasher::Hash>> {
        Ok(None)
    }

    fn get_delegator(
        &mut self,
        _key: &spaces_nums::DelegatorKey,
    ) -> spaces_protocol::errors::Result<Option<spaces_protocol::slabel::SLabel>> {
        Ok(None)
    }

    fn get_numout(
        &mut self,
        outpoint: &OutPoint,
    ) -> spaces_protocol::errors::Result<Option<NumOut>> {
        Ok(self.numouts.get(outpoint).cloned())
    }

    fn get_num_id(
        &mut self,
        _snum: &SNumeric,
    ) -> spaces_protocol::errors::Result<Option<NumId>> {
        Ok(None)
    }
}

fn mint_locktime() -> LockTime {
    let lt = LockTime::from_consensus(500_000_777);
    assert!(spaces_nums::is_num_minting_locktime(&lt));
    lt
}

fn spk(tag: u8) -> ScriptBuf {
    // Arbitrary distinct scripts; the validator only hashes them.
    ScriptBuf::from_bytes(vec![0x51, tag])
}

fn outpoint(tag: u8, vout: u32) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([tag; 32]),
        vout,
    }
}

fn build_tx(lock_time: LockTime, inputs: &[OutPoint], outputs: &[(ScriptBuf, u64)]) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time,
        input: inputs
            .iter()
            .map(|&previous_output| TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs
            .iter()
            .map(|(script_pubkey, sats)| TxOut {
                value: Amount::from_sat(*sats),
                script_pubkey: script_pubkey.clone(),
            })
            .collect(),
    }
}

/// Seed a live num whose current utxo is `current`. Passing `genesis_spk ==
/// current_spk` models a never-rotated num; different spks model a rotated one.
fn seed_num(
    src: &mut MockSrc,
    genesis_spk: &ScriptBuf,
    current: OutPoint,
    current_spk: &ScriptBuf,
    value: u64,
) -> Num {
    let id = NumId::from_spk::<TestHasher>(genesis_spk.clone());
    let num = Num {
        id,
        name: SNumeric::new(1, 0, current.vout as u16),
        data: None,
        last_update: 1,
    };
    src.numouts.insert(
        current,
        NumOut {
            n: current.vout as usize,
            num: num.clone(),
            value: Amount::from_sat(value),
            script_pubkey: current_spk.clone(),
            spent: false,
        },
    );
    src.identities.insert(id, current);
    num
}

/// Park a rebind at `death_spk`, as if `prev` died there at `prev_outpoint`.
fn seed_rebind(src: &mut MockSrc, death_spk: &ScriptBuf, prev_outpoint: OutPoint, prev: Num) {
    src.rebinds.insert(
        RebindKey::from_spk::<TestHasher>(death_spk.clone()),
        RebindData {
            prev_outpoint,
            prev,
        },
    );
}

fn foreign_num(genesis_spk: &ScriptBuf) -> Num {
    Num {
        id: NumId::from_spk::<TestHasher>(genesis_spk.clone()),
        name: SNumeric::new(2, 0, 0),
        data: None,
        last_update: 2,
    }
}

fn process(src: &mut MockSrc, tx: &Transaction, new_spaces: Vec<SpaceOut>) -> TxChangeSet {
    let ctx = TxContext::from_tx::<MockSrc, TestHasher>(src, tx, false, new_spaces.clone(), HEIGHT)
        .expect("source never errors")
        .expect("tx should be relevant");
    Validator::new().process::<TestHasher>(HEIGHT, tx, TX_POS, ctx, vec![], new_spaces)
}

#[test]
fn mint_requires_locktime_signal_for_relevance() {
    let mut src = MockSrc::default();
    let tx = build_tx(LockTime::ZERO, &[outpoint(9, 0)], &[(spk(1), 1077)]);
    let ctx = TxContext::from_tx::<MockSrc, TestHasher>(&mut src, &tx, false, vec![], HEIGHT)
        .unwrap();
    assert!(
        ctx.is_none(),
        "num-valued outputs without the minting locktime must not make a tx relevant"
    );

    let tx = build_tx(mint_locktime(), &[outpoint(9, 0)], &[(spk(1), 1077)]);
    let changeset = process(&mut src, &tx, vec![]);
    assert_eq!(changeset.creates.len(), 1);
    let created = &changeset.creates[0];
    assert_eq!(created.n, 0);
    assert_eq!(created.num.id, NumId::from_spk::<TestHasher>(spk(1)));
    assert_eq!(created.num.name, SNumeric::new(HEIGHT, TX_POS, 0));
    assert_eq!(created.num.last_update, HEIGHT);
    assert!(!created.spent);
}

#[test]
fn num_spend_tx_does_not_mint_at_incidental_outputs() {
    // A tx relevant only because it spends a num must not mint at outputs
    // that merely carry a mint value (e.g. a 77-ending change output).
    let mut src = MockSrc::default();
    let a = seed_num(&mut src, &spk(1), outpoint(1, 0), &spk(1), 1000);

    let rotation_and_change = &[(spk(2), 1000), (spk(3), 5077)];
    let tx = build_tx(LockTime::ZERO, &[outpoint(1, 0)], rotation_and_change);
    let changeset = process(&mut src, &tx, vec![]);

    assert_eq!(changeset.creates.len(), 1, "only the rotation, no mint");
    assert_eq!(changeset.creates[0].num.id, a.id);
    assert_eq!(changeset.creates[0].n, 0);
    assert!(changeset.unbinds.is_empty());

    // The same tx WITH the minting locktime also mints at the change output.
    let tx = build_tx(mint_locktime(), &[outpoint(1, 0)], rotation_and_change);
    let changeset = process(&mut src, &tx, vec![]);
    assert_eq!(changeset.creates.len(), 2);
    assert_eq!(changeset.creates[1].n, 1);
    assert_eq!(
        changeset.creates[1].num.id,
        NumId::from_spk::<TestHasher>(spk(3))
    );
}

#[test]
fn spaces_tx_mints_without_num_locktime() {
    // Space flows (operate: space transfer + create_num) cannot carry the num
    // locktime since spaces tracking claims it, so spaces txs mint without it.
    let mut src = MockSrc::default();
    let space_out = SpaceOut {
        n: 0,
        space: None,
        value: Amount::from_sat(662),
        script_pubkey: spk(1),
    };
    let tx = build_tx(LockTime::ZERO, &[outpoint(9, 0)], &[(spk(1), 662), (spk(2), 1077)]);
    let changeset = process(&mut src, &tx, vec![space_out]);

    assert_eq!(changeset.creates.len(), 1);
    assert_eq!(changeset.creates[0].n, 1, "space-claimed output 0 must not mint");
    assert_eq!(
        changeset.creates[0].num.id,
        NumId::from_spk::<TestHasher>(spk(2))
    );
}

#[test]
fn unbind_emits_tombstone_only() {
    // A death emits only the spent tombstone — no identity write, no
    // rotated/non-rotated distinction. Apply parks the rebind derived from
    // the tombstone at rebind(death spk); the identity slot is untouched.
    for rotated in [false, true] {
        let mut src = MockSrc::default();
        let genesis = spk(1);
        let current = if rotated { spk(2) } else { spk(1) };
        let a = seed_num(&mut src, &genesis, outpoint(1, 0), &current, 500);

        // Output 0 exists but value-mismatches and there is no output 1.
        let tx = build_tx(LockTime::ZERO, &[outpoint(1, 0)], &[(spk(9), 600)]);
        let changeset = process(&mut src, &tx, vec![]);

        assert!(changeset.creates.is_empty());
        assert!(changeset.spends.is_empty());
        assert!(changeset.rebinds.is_empty());
        assert_eq!(changeset.unbinds.len(), 1);
        let fno = &changeset.unbinds[0];
        assert!(fno.numout.spent);
        assert_eq!(fno.outpoint(), outpoint(1, 0));
        assert_eq!(fno.numout.num.id, a.id);
        assert_eq!(fno.numout.num.last_update, HEIGHT);
        assert_eq!(fno.numout.script_pubkey, current, "tombstone keeps the death spk");
    }
}

#[test]
fn value_match_beats_fallback_and_loser_unbinds() {
    // Input 0 mismatches output 0 and would fall back to output 1, but input 1
    // value-matches output 1. The value-match must win regardless of input
    // order (untrusted assemblers control ordering), and the displaced num
    // must go dormant — not dangle at an outpoint recorded as another num.
    let mut src = MockSrc::default();
    let a = seed_num(&mut src, &spk(1), outpoint(1, 0), &spk(1), 500);
    let b = seed_num(&mut src, &spk(2), outpoint(2, 1), &spk(2), 1000);

    let tx = build_tx(
        LockTime::ZERO,
        &[outpoint(1, 0), outpoint(2, 1)],
        &[(spk(8), 600), (spk(9), 1000)],
    );
    let changeset = process(&mut src, &tx, vec![]);

    assert_eq!(changeset.creates.len(), 1, "output 1 hosts exactly one successor");
    assert_eq!(changeset.creates[0].n, 1);
    assert_eq!(changeset.creates[0].num.id, b.id, "value-match wins the output");
    assert_eq!(changeset.spends, vec![1], "only the winner's input is a plain spend");

    assert_eq!(changeset.unbinds.len(), 1, "the displaced num goes dormant");
    let fno = &changeset.unbinds[0];
    assert_eq!(fno.numout.num.id, a.id);
    assert!(fno.numout.spent);
}

#[test]
fn fallback_claims_next_output_when_unclaimed() {
    // Trading-tx shape: seller's payment at N, num successor at N+1 with an
    // arbitrary buyer-chosen value (no num-value requirement — even 88).
    let mut src = MockSrc::default();
    let a = seed_num(&mut src, &spk(1), outpoint(1, 0), &spk(1), 500);

    let tx = build_tx(
        LockTime::ZERO,
        &[outpoint(1, 0)],
        &[(spk(8), 600), (spk(9), 12388)],
    );
    let changeset = process(&mut src, &tx, vec![]);

    assert!(changeset.unbinds.is_empty());
    assert_eq!(changeset.spends, vec![0]);
    assert_eq!(changeset.creates.len(), 1);
    let created = &changeset.creates[0];
    assert_eq!(created.n, 1);
    assert_eq!(created.num.id, a.id);
    assert_eq!(created.value, Amount::from_sat(12388));
    assert_eq!(created.script_pubkey, spk(9));
    assert!(
        changeset.rebinds.is_empty(),
        "an output claimed as a successor never doubles as a revival trigger"
    );
}

#[test]
fn revival_consumes_rebind_and_deletes_slot() {
    // An 88 output at a spk with a parked rebind revives it — uniformly for
    // foreign (died away from genesis) and native (died at genesis) nums.
    for native in [false, true] {
        let mut src = MockSrc::default();
        let revival_spk = spk(1);
        let genesis_spk = if native { spk(1) } else { spk(7) };
        let dormant = foreign_num(&genesis_spk);
        seed_rebind(&mut src, &revival_spk, outpoint(4, 0), dormant.clone());

        let tx = build_tx(mint_locktime(), &[outpoint(9, 0)], &[(revival_spk.clone(), 1088)]);
        let changeset = process(&mut src, &tx, vec![]);

        assert_eq!(changeset.rebinds.len(), 1);
        let rebind = &changeset.rebinds[0];
        assert_eq!(
            rebind.key,
            RebindKey::from_spk::<TestHasher>(revival_spk.clone()),
            "the parked rebind slot is deleted"
        );
        assert_eq!(rebind.prev_outpoint, outpoint(4, 0), "tombstone entry is deleted");

        assert_eq!(changeset.creates.len(), 1);
        let created = &changeset.creates[0];
        assert_eq!(created.num.id, dormant.id, "revival keeps the genesis identity");
        assert_eq!(created.num.name, dormant.name);
        assert_eq!(created.num.last_update, HEIGHT);
        assert!(!created.spent);
    }
}

#[test]
fn revival_requires_mint_signal() {
    // A dormant slot must not be revived by a tx that is only relevant
    // because it spends some unrelated num.
    let mut src = MockSrc::default();
    seed_rebind(&mut src, &spk(1), outpoint(4, 0), foreign_num(&spk(7)));
    let unrelated = seed_num(&mut src, &spk(5), outpoint(5, 0), &spk(5), 1000);

    let tx = build_tx(
        LockTime::ZERO,
        &[outpoint(5, 0)],
        &[(spk(5), 1000), (spk(1), 1088)],
    );
    let changeset = process(&mut src, &tx, vec![]);

    assert!(changeset.rebinds.is_empty(), "no revival without the mint signal");
    assert_eq!(changeset.creates.len(), 1);
    assert_eq!(changeset.creates[0].num.id, unrelated.id, "only the rotation");
}

#[test]
fn mint_value_does_not_revive() {
    // Explicit intent: a 77 output at a spk with a parked rebind and a FREE
    // identity slot mints a fresh num; the rebind stays parked. They coexist.
    let mut src = MockSrc::default();
    let dormant = foreign_num(&spk(7));
    seed_rebind(&mut src, &spk(1), outpoint(4, 0), dormant.clone());

    let tx = build_tx(mint_locktime(), &[outpoint(9, 0)], &[(spk(1), 1077)]);
    let changeset = process(&mut src, &tx, vec![]);

    assert!(changeset.rebinds.is_empty(), "the parked rebind is untouched");
    assert_eq!(changeset.creates.len(), 1);
    assert_eq!(
        changeset.creates[0].num.id,
        NumId::from_spk::<TestHasher>(spk(1)),
        "a fresh num is minted, not the dormant one revived"
    );
    assert_ne!(changeset.creates[0].num.id, dormant.id);
}

#[test]
fn revival_value_at_empty_slot_is_noop() {
    // An 88 output with nothing parked does nothing — no fresh mint either.
    let mut src = MockSrc::default();
    let tx = build_tx(mint_locktime(), &[outpoint(9, 0)], &[(spk(1), 1088)]);
    let changeset = process(&mut src, &tx, vec![]);

    assert!(changeset.creates.is_empty());
    assert!(changeset.rebinds.is_empty());
}

#[test]
fn same_tx_mint_and_revive_at_same_spk() {
    // Dedup is per (spk, intent): one tx may both revive the dormant num and
    // mint a fresh one at the same spk. Two nums with different ids coexist.
    let mut src = MockSrc::default();
    let dormant = foreign_num(&spk(7));
    seed_rebind(&mut src, &spk(1), outpoint(4, 0), dormant.clone());

    let tx = build_tx(
        mint_locktime(),
        &[outpoint(9, 0)],
        &[(spk(1), 1077), (spk(1), 1088)],
    );
    let changeset = process(&mut src, &tx, vec![]);

    assert_eq!(changeset.creates.len(), 2);
    assert_eq!(changeset.creates[0].num.id, NumId::from_spk::<TestHasher>(spk(1)));
    assert_eq!(changeset.creates[1].num.id, dormant.id);
    assert_eq!(changeset.rebinds.len(), 1);
}

#[test]
fn minted_slot_blocks_fresh_mint() {
    // Anti-dup for live nums, and the rotated-away/dormant genesis guard: an
    // occupied identity slot (never deleted) blocks minting forever.
    let mut src = MockSrc::default();
    seed_num(&mut src, &spk(1), outpoint(1, 0), &spk(1), 1000);

    let tx = build_tx(mint_locktime(), &[outpoint(9, 0)], &[(spk(1), 1077)]);
    let changeset = process(&mut src, &tx, vec![]);

    assert!(changeset.creates.is_empty());
    assert!(changeset.rebinds.is_empty());
}

#[test]
fn duplicate_spk_outputs_act_once() {
    // Fresh slot: two mint outputs at the same spk mint exactly one num.
    let mut src = MockSrc::default();
    let tx = build_tx(
        mint_locktime(),
        &[outpoint(9, 0)],
        &[(spk(1), 1077), (spk(1), 2077)],
    );
    let changeset = process(&mut src, &tx, vec![]);
    assert_eq!(changeset.creates.len(), 1);
    assert_eq!(changeset.creates[0].n, 0);

    // Dormant slot: two revival outputs consume the rebind exactly once.
    let mut src = MockSrc::default();
    seed_rebind(&mut src, &spk(1), outpoint(4, 0), foreign_num(&spk(7)));
    let tx = build_tx(
        mint_locktime(),
        &[outpoint(9, 0)],
        &[(spk(1), 1088), (spk(1), 2088)],
    );
    let changeset = process(&mut src, &tx, vec![]);
    assert_eq!(changeset.rebinds.len(), 1);
    assert_eq!(changeset.creates.len(), 1);
    assert_eq!(changeset.creates[0].n, 0);
}

#[test]
fn rotation_successor_not_double_minted() {
    // An output claimed by a rotation must not also be treated as a mint,
    // even when the tx carries the minting locktime.
    let mut src = MockSrc::default();
    let a = seed_num(&mut src, &spk(1), outpoint(1, 0), &spk(1), 1077);

    let tx = build_tx(mint_locktime(), &[outpoint(1, 0)], &[(spk(2), 1077)]);
    let changeset = process(&mut src, &tx, vec![]);

    assert_eq!(changeset.creates.len(), 1);
    assert_eq!(changeset.creates[0].num.id, a.id, "rotation, not a fresh mint");
    assert_eq!(changeset.spends, vec![0]);
}

#[test]
fn successor_claim_beats_revival_dispatch() {
    // Resolved design question #2: a rotating num may land in an 88 output.
    // If that output's spk also has a parked rebind, the successor claim wins
    // and no revival fires — reviving needs a separate unclaimed 88 output.
    let mut src = MockSrc::default();
    let a = seed_num(&mut src, &spk(1), outpoint(1, 0), &spk(2), 1088);
    seed_rebind(&mut src, &spk(3), outpoint(4, 0), foreign_num(&spk(7)));

    // Value-match rotation into output 0 = (spk(3), 1088).
    let tx = build_tx(mint_locktime(), &[outpoint(1, 0)], &[(spk(3), 1088)]);
    let changeset = process(&mut src, &tx, vec![]);

    assert_eq!(changeset.creates.len(), 1);
    assert_eq!(changeset.creates[0].num.id, a.id, "successor claim wins");
    assert!(changeset.rebinds.is_empty(), "revival does not fire on a claimed output");
}