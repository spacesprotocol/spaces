use anyhow::anyhow;
use spaces_client::rpc::{
    CommitParams, CreateNumParams, OperateParams, SetFallbackParams, Subject, TransferSpacesParams,
};
use spaces_client::store::Sha256;
use spaces_client::{
    rpc::{RpcClient, RpcWalletRequest, RpcWalletTxBuilder},
    wallets::{AddressKind, WalletResponse},
};
use spaces_nums::num_id::NumId;
use spaces_protocol::bitcoin::hashes::{Hash, sha256};
use spaces_protocol::{bitcoin, bitcoin::FeeRate};
use spaces_testutil::TestRig;
use spaces_wallet::address::SpaceAddress;
use spaces_wallet::export::WalletExport;
use std::{path::PathBuf, str::FromStr};

const ALICE: &str = "wallet_99";
const BOB: &str = "wallet_98";
const EVE: &str = "wallet_93";

// ============== Helper Functions ==============

fn wallet_res_err(res: &WalletResponse) -> anyhow::Result<()> {
    for tx in &res.result {
        if let Some(e) = tx.error.as_ref() {
            let s = e
                .iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(anyhow!("{}", s));
        }
    }
    Ok(())
}

pub async fn load_wallet(rig: &TestRig, wallets_dir: PathBuf, name: &str) -> anyhow::Result<()> {
    let wallet_path = wallets_dir.join(format!("{name}.json"));
    let json = std::fs::read_to_string(wallet_path)?;
    let export = WalletExport::from_str(&json)?;
    rig.spaced.client.wallet_import(export).await?;
    Ok(())
}

async fn wallet_do(
    rig: &TestRig,
    wallet: &str,
    requests: Vec<RpcWalletRequest>,
    force: bool,
) -> anyhow::Result<WalletResponse> {
    let res = rig
        .spaced
        .client
        .wallet_send_request(
            wallet,
            RpcWalletTxBuilder {
                bidouts: None,
                requests,
                fee_rate: Some(FeeRate::from_sat_per_vb(1).expect("fee")),
                dust: None,
                force,
                confirmed_only: false,
                skip_tx_check: false,
            },
        )
        .await?;
    Ok(res)
}

async fn sync_all(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    rig.wait_until_wallet_synced(BOB).await?;
    Ok(())
}

async fn mine_and_sync(rig: &TestRig, blocks: usize) -> anyhow::Result<()> {
    rig.mine_blocks(blocks, None).await?;
    sync_all(rig).await
}

// ============== Test: Basic Num Id Creation ==============

async fn it_should_create_nums(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;

    // Create ptr bound to addr0
    let addr0 = rig
        .spaced
        .client
        .wallet_get_new_address(ALICE, AddressKind::Coin)
        .await?;
    let addr0_spk = bitcoin::address::Address::from_str(&addr0)
        .expect("valid")
        .assume_checked()
        .script_pubkey();
    let create0 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreateNum(CreateNumParams {
            bind_spk: Some(addr0_spk.clone()),
        })],
        false,
    )
    .await
    .expect("CreatePtr addr0");
    assert!(
        wallet_res_err(&create0).is_ok(),
        "CreatePtr(addr0) must not error"
    );

    mine_and_sync(rig, 1).await?;

    let spk0 = bitcoin::address::Address::from_str(&addr0)
        .expect("valid addr0")
        .assume_checked()
        .script_pubkey();
    let id0 = NumId::from_spk::<Sha256>(spk0.clone());

    let ptr0 = rig
        .spaced
        .client
        .get_num(Subject::NumId(id0))
        .await?
        .expect("ptr must exist after first CreatePtr");
    let bound_spk_before = ptr0.numout.script_pubkey.clone();

    // Transfer ptr to addr1 (binding should change)
    let addr1 = rig
        .spaced
        .client
        .wallet_get_new_address(BOB, AddressKind::Space)
        .await?;
    let xfer = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None,
            spaces: vec![Subject::NumId(id0)],
            to: Some(addr1.clone()),
            data: None,
        })],
        false,
    )
    .await
    .expect("Transfer PTR to addr1");
    assert!(wallet_res_err(&xfer).is_ok(), "Transfer PTR must not error");

    mine_and_sync(rig, 1).await?;

    let spk1 = SpaceAddress::from_str(&addr1)
        .expect("valid addr1")
        .script_pubkey();

    let ptr_after_xfer = rig
        .spaced
        .client
        .get_num(Subject::NumId(id0))
        .await?
        .expect("ptr must still resolve after transfer");
    let bound_spk_after = ptr_after_xfer.numout.script_pubkey.clone();

    assert_ne!(
        bound_spk_before, bound_spk_after,
        "binding must change after transfer"
    );
    assert_eq!(
        bound_spk_after, spk1,
        "binding must equal new destination spk"
    );

    // Duplicate CreatePtr on ORIGINAL addr0 → should be ignored
    let dup = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreateNum(CreateNumParams {
            bind_spk: Some(addr0_spk.clone()),
        })],
        true,
    )
    .await
    .expect("duplicate CreatePtr(addr0)");
    assert!(
        wallet_res_err(&dup).is_ok(),
        "duplicate CreatePtr should not error"
    );

    mine_and_sync(rig, 1).await?;

    let ptr_after_dup = rig
        .spaced
        .client
        .get_num(Subject::NumId(id0))
        .await?
        .expect("ptr must still resolve after duplicate");
    let bound_spk_final = ptr_after_dup.numout.script_pubkey.clone();

    assert_eq!(bound_spk_final, spk1, "duplicate CreatePtr must be ignored");
    assert_ne!(bound_spk_final, spk0, "binding must not revert to original");

    Ok(())
}

// ============== Test: Basic Commitments with Rollback ==============

async fn it_should_commit_and_rollback(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Get a space that Alice owns
    let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let owned = alice_spaces
        .owned
        .first()
        .cloned()
        .expect("Alice should own at least one space");
    let space_name = owned
        .spaceout
        .space
        .as_ref()
        .expect("space must exist")
        .name
        .clone();

    // Setup: Delegate the space to establish Num Id
    let delegate = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Operate(OperateParams {
            subject: space_name.clone().into(),
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&delegate).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify delegation is set up
    rig.spaced
        .client
        .get_delegation(space_name.clone().into())
        .await?
        .expect("delegation should be established");

    // Test 1: Make initial commitment [1u8;32]
    println!("Creating initial commitment [1u8;32]...");
    let commit1 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: space_name.clone().into(),
            root: Some(sha256::Hash::from_slice(&[1u8; 32]).expect("valid")),
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&commit1).is_ok());
    mine_and_sync(rig, 1).await?;

    let tip = rig
        .spaced
        .client
        .get_commitment(space_name.clone().into(), None)
        .await?
        .expect("commitment should exist");
    assert_eq!(tip.state_root, [1u8; 32]);
    assert_eq!(tip.prev_root, None);

    // Test 2: Rollback pending commitment
    println!("Rolling back pending commitment [1u8;32]...");
    let rollback = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: space_name.clone().into(),
            root: None, // None = rollback
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&rollback).is_ok());
    mine_and_sync(rig, 1).await?;

    let tip_after_rollback = rig
        .spaced
        .client
        .get_commitment(space_name.clone().into(), None)
        .await?;
    assert_eq!(tip_after_rollback, None, "commitment should be rolled back");

    // Test 3: Create new commitment and finalize it
    println!("Creating commitment [2u8;32] and finalizing...");
    let commit2 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: space_name.clone().into(),
            root: Some(sha256::Hash::from_slice(&[2u8; 32]).expect("valid")),
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&commit2).is_ok());
    mine_and_sync(rig, 1).await?;

    // Finalize by mining 144 blocks
    println!("Mining 144 blocks to finalize [2u8;32]...");
    mine_and_sync(rig, 144).await?;

    // Test 4: Try to rollback finalized commitment (should fail/no-op)
    println!("Attempting to rollback finalized commitment...");
    let rollback_finalized = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: space_name.clone().into(),
            root: None, // Rollback attempt
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&rollback_finalized).is_ok());
    mine_and_sync(rig, 1).await?;

    let tip_after_failed_rollback = rig
        .spaced
        .client
        .get_commitment(space_name.clone().into(), None)
        .await?
        .expect("finalized commitment should still exist");
    assert_eq!(
        tip_after_failed_rollback.state_root, [2u8; 32],
        "finalized commitment should not be rolled back"
    );

    // Test 5: Add new commitment on top of finalized
    println!("Adding [3u8;32] on top of finalized [2u8;32]...");
    let commit3 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: space_name.clone().into(),
            root: Some(sha256::Hash::from_slice(&[3u8; 32]).expect("valid")),
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&commit3).is_ok());
    mine_and_sync(rig, 1).await?;

    let tip_final = rig
        .spaced
        .client
        .get_commitment(space_name.clone().into(), None)
        .await?
        .expect("new commitment should exist");
    assert_eq!(tip_final.state_root, [3u8; 32]);
    assert_eq!(tip_final.prev_root, Some([2u8; 32]));

    // Verify finalized [2u8;32] still exists
    let finalized = rig
        .spaced
        .client
        .get_commitment(
            space_name.clone().into(),
            Some(sha256::Hash::from_slice(&[2u8; 32]).expect("valid")),
        )
        .await?
        .expect("finalized commitment should be preserved");
    assert_eq!(finalized.state_root, [2u8; 32]);

    // Test 6: Rollback pending [3u8;32] and verify registry points back to [2u8;32]
    println!("Rolling back pending [3u8;32]...");
    let rollback3 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: space_name.clone().into(),
            root: None,
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&rollback3).is_ok());
    mine_and_sync(rig, 1).await?;

    let tip_after_rollback = rig
        .spaced
        .client
        .get_commitment(space_name.clone().into(), None)
        .await?
        .expect("should still have finalized commitment after rollback");
    assert_eq!(
        tip_after_rollback.state_root, [2u8; 32],
        "registry should point back to finalized [2u8;32] after rolling back pending"
    );
    println!("✓ Registry correctly updated to [2u8;32] after rollback");

    Ok(())
}

// ============== Test: Multiple Commitments in Single Transaction ==============

async fn it_should_handle_multiple_commitments(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Get two spaces that Alice owns
    let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    assert!(
        alice_spaces.owned.len() >= 2,
        "Alice needs at least 2 spaces for this test"
    );

    let space1_name = alice_spaces.owned[0]
        .spaceout
        .space
        .as_ref()
        .expect("space must exist")
        .name
        .clone();
    let space2_name = alice_spaces.owned[1]
        .spaceout
        .space
        .as_ref()
        .expect("space must exist")
        .name
        .clone();

    // Setup: Delegate both spaces to establish Num Ids
    for space_name in [&space1_name, &space2_name] {
        let delegate = wallet_do(
            rig,
            ALICE,
            vec![RpcWalletRequest::Operate(OperateParams {
                subject: space_name.clone().into(),
            })],
            false,
        )
        .await?;
        assert!(wallet_res_err(&delegate).is_ok());
    }
    mine_and_sync(rig, 1).await?;

    // Verify both delegations exist
    let id1 = rig
        .spaced
        .client
        .get_delegation(space1_name.clone().into())
        .await?
        .expect("space1 should have delegation");
    let id2 = rig
        .spaced
        .client
        .get_delegation(space2_name.clone().into())
        .await?
        .expect("space2 should have delegation");

    println!("Space 1: {} -> Num Id: {}", space1_name, id1);
    println!("Space 2: {} -> Num Id: {}", space2_name, id2);

    // Verify delegations match delegator
    let delegator1 = rig
        .spaced
        .client
        .get_delegator(Subject::NumId(id1))
        .await?
        .expect("id1 delegator should exist");
    let delegator2 = rig
        .spaced
        .client
        .get_delegator(Subject::NumId(id2))
        .await?
        .expect("id2 delegator should exist");

    assert_eq!(
        delegator1.to_string(),
        space1_name.to_string(),
        "space 1 delegators dont match"
    );
    assert_eq!(
        delegator2.to_string(),
        space2_name.to_string(),
        "space 2 delegators dont match"
    );

    // Test 1: Submit two commitments in one transaction
    println!("Submitting 2 commitments in single transaction...");
    let multi_commit = wallet_do(
        rig,
        ALICE,
        vec![
            RpcWalletRequest::Commit(CommitParams {
                subject: space1_name.clone().into(),
                root: Some(sha256::Hash::from_slice(&[10u8; 32]).expect("valid")),
            }),
            RpcWalletRequest::Commit(CommitParams {
                subject: space2_name.clone().into(),
                root: Some(sha256::Hash::from_slice(&[20u8; 32]).expect("valid")),
            }),
        ],
        false,
    )
    .await?;
    assert!(wallet_res_err(&multi_commit).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify both commitments were created
    let commit2 = rig
        .spaced
        .client
        .get_commitment(space2_name.clone().into(), None)
        .await?
        .expect("space2 should have commitment");
    let commit1 = rig
        .spaced
        .client
        .get_commitment(space1_name.clone().into(), None)
        .await?
        .expect("space1 should have commitment");

    assert_eq!(commit1.state_root, [10u8; 32], "space1 commitment");
    assert_eq!(commit2.state_root, [20u8; 32], "space2 commitment");

    // Test 2: Rollback both in single transaction
    println!("Rolling back both commitments in single transaction...");
    let multi_rollback = wallet_do(
        rig,
        ALICE,
        vec![
            RpcWalletRequest::Commit(CommitParams {
                subject: space1_name.clone().into(),
                root: None, // rollback
            }),
            RpcWalletRequest::Commit(CommitParams {
                subject: space2_name.clone().into(),
                root: None, // rollback
            }),
        ],
        false,
    )
    .await?;
    assert!(wallet_res_err(&multi_rollback).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify both were rolled back
    let commit1_after = rig
        .spaced
        .client
        .get_commitment(space1_name.clone().into(), None)
        .await?;
    let commit2_after = rig
        .spaced
        .client
        .get_commitment(space2_name.clone().into(), None)
        .await?;

    assert_eq!(commit1_after, None, "space1 should be rolled back");
    assert_eq!(commit2_after, None, "space2 should be rolled back");

    // Test 3: Mixed operations - commit one, keep other unchanged
    println!("Mixed operation: new commitment for space1 only...");
    let mixed = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: space1_name.clone().into(),
            root: Some(sha256::Hash::from_slice(&[30u8; 32]).expect("valid")),
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&mixed).is_ok());
    mine_and_sync(rig, 1).await?;

    let commit1_final = rig
        .spaced
        .client
        .get_commitment(space1_name.clone().into(), None)
        .await?
        .expect("space1 should have new commitment");
    let commit2_final = rig
        .spaced
        .client
        .get_commitment(space2_name.clone().into(), None)
        .await?;

    assert_eq!(commit1_final.state_root, [30u8; 32], "space1 updated");
    assert_eq!(commit2_final, None, "space2 unchanged");

    Ok(())
}

// ============== Test: Commitment Override Within 144 Blocks ==============

async fn it_should_override_pending_commitments(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let space_name = alice_spaces.owned[0]
        .spaceout
        .space
        .as_ref()
        .expect("space must exist")
        .name
        .clone();

    // Setup: Delegate the space to establish Num Id
    let delegate = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Operate(OperateParams {
            subject: space_name.clone().into(),
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&delegate).is_ok());
    mine_and_sync(rig, 1).await?;

    // Make commitment [1u8;32]
    println!("Creating commitment [1u8;32]...");
    let commit1 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: space_name.clone().into(),
            root: Some(sha256::Hash::from_slice(&[1u8; 32]).expect("valid")),
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&commit1).is_ok());
    mine_and_sync(rig, 1).await?;

    // Override with [2u8;32] while still pending
    println!("Overriding with [2u8;32] while pending...");
    let commit2 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: space_name.clone().into(),
            root: Some(sha256::Hash::from_slice(&[2u8; 32]).expect("valid")),
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&commit2).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify [1u8;32] is gone, [2u8;32] is tip
    let old_commit = rig
        .spaced
        .client
        .get_commitment(
            space_name.clone().into(),
            Some(sha256::Hash::from_slice(&[1u8; 32]).expect("valid")),
        )
        .await?;
    assert_eq!(old_commit, None, "[1u8;32] should be overridden");

    let tip = rig
        .spaced
        .client
        .get_commitment(space_name.clone().into(), None)
        .await?
        .expect("tip should exist");
    assert_eq!(tip.state_root, [2u8; 32]);
    assert_eq!(
        tip.prev_root, None,
        "no previous since [1u8;32] was overridden"
    );

    // Finalize [2u8;32]
    println!("Finalizing [2u8;32]...");
    mine_and_sync(rig, 144).await?;

    // Try to override finalized [2u8;32] with [3u8;32] - should chain instead
    println!("Adding [3u8;32] on top of finalized [2u8;32]...");
    let commit3 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: space_name.clone().into(),
            root: Some(sha256::Hash::from_slice(&[3u8; 32]).expect("valid")),
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&commit3).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify [2u8;32] still exists and [3u8;32] chains from it
    let finalized = rig
        .spaced
        .client
        .get_commitment(
            space_name.clone().into(),
            Some(sha256::Hash::from_slice(&[2u8; 32]).expect("valid")),
        )
        .await?
        .expect("[2u8;32] should still exist");
    assert_eq!(finalized.state_root, [2u8; 32]);

    let new_tip = rig
        .spaced
        .client
        .get_commitment(space_name.clone().into(), None)
        .await?
        .expect("new tip should exist");
    assert_eq!(new_tip.state_root, [3u8; 32]);
    assert_eq!(new_tip.prev_root, Some([2u8; 32]));

    Ok(())
}

async fn it_should_reject_duplicate_num_id_delegations(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Get two spaces that Alice owns
    let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    assert!(
        alice_spaces.owned.len() >= 2,
        "Alice needs at least 2 spaces for this test"
    );

    let space1_name = alice_spaces.owned[0]
        .spaceout
        .space
        .as_ref()
        .expect("space must exist")
        .name
        .clone();
    let space2_name = alice_spaces.owned[1]
        .spaceout
        .space
        .as_ref()
        .expect("space must exist")
        .name
        .clone();

    println!(
        "Testing Num Id uniqueness with {} and {}",
        space1_name, space2_name
    );

    // Get a common address to create the same Num Id
    let common_addr = rig
        .spaced
        .client
        .wallet_get_new_address(ALICE, AddressKind::Space)
        .await?;
    let common_spk = SpaceAddress::from_str(&common_addr)
        .expect("valid space address")
        .script_pubkey();
    let common_id = NumId::from_spk::<Sha256>(common_spk.clone());

    println!("Common address: {}", common_addr);
    println!("Expected Num Id: {}", common_id);

    // Transfer space1 to the common address
    println!("Transferring {} to common address...", space1_name);
    let transfer1 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None,
            spaces: vec![Subject::Label(space1_name.clone())],
            to: Some(common_addr.clone()),
            data: None,
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&transfer1).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify the reverse mapping: Num Id -> space1
    let delegator1 = rig
        .spaced
        .client
        .get_delegator(Subject::NumId(common_id))
        .await?
        .expect("common Num Id should have delegator");
    assert_eq!(
        delegator1, space1_name,
        "common Num Id should point to space1"
    );

    println!(
        "✓ Space1 successfully claimed Num Id {} (reverse mapping: {} -> {})",
        common_id, common_id, space1_name
    );

    // Transfer space2 to the SAME address (same Num Id)
    println!(
        "Transferring {} to the same address (attempting to claim same Num Id)...",
        space2_name
    );
    let transfer2 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None,
            spaces: vec![Subject::Label(space2_name.clone())],
            to: Some(common_addr.clone()),
            data: None,
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&transfer2).is_ok());
    mine_and_sync(rig, 1).await?;

    // Key test: Verify the reverse mapping was NOT overwritten
    // The Num Id should still point to space1, not space2
    let delegator_after = rig
        .spaced
        .client
        .get_delegator(Subject::NumId(common_id))
        .await?
        .expect("common Num Id should still have delegator");
    assert_eq!(
        delegator_after, space1_name,
        "CRITICAL: common Num Id should still point to space1 (not overwritten by space2)"
    );

    println!(
        "✓ Space2 correctly rejected - reverse mapping preserved ({} -> {})",
        common_id, space1_name
    );

    // Note: get_delegation for both spaces will return Some(common_id) because
    // both are at the same address, but only space1 actually owns the delegation

    // Transfer space1 away to free up the Num Id
    println!("Moving {} away to free up Num Id...", space1_name);
    let new_addr = rig
        .spaced
        .client
        .wallet_get_new_address(ALICE, AddressKind::Space)
        .await?;
    let transfer_away = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None,
            spaces: vec![Subject::Label(space1_name.clone())],
            to: Some(new_addr),
            data: None,
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&transfer_away).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify common_id is now free (reverse mapping removed)
    let delegator_freed = rig
        .spaced
        .client
        .get_delegator(Subject::NumId(common_id))
        .await?;
    assert_eq!(
        delegator_freed, None,
        "common Num Id should be free (no reverse mapping) after space1 moved"
    );

    println!("✓ Num Id freed - reverse mapping removed");

    // Now space2 should be able to claim it if we transfer it back
    println!("Re-transferring {} to now-free Num Id...", space2_name);
    let transfer2_retry = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None,
            spaces: vec![Subject::Label(space2_name.clone())],
            to: Some(common_addr),
            data: None,
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&transfer2_retry).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify space2 now owns the reverse mapping
    let delegator2_retry = rig
        .spaced
        .client
        .get_delegator(Subject::NumId(common_id))
        .await?
        .expect("common Num Id should have delegator");
    assert_eq!(
        delegator2_retry, space2_name,
        "common Num Id should now point to space2 (reverse mapping updated)"
    );

    println!(
        "✓ Space2 successfully claimed Num Id after it was freed ({} -> {})",
        common_id, space2_name
    );

    Ok(())
}

// ============== Test: Transfer Back to Original Num Id ==============
// Regression test for https://github.com/spacesprotocol/spaces/issues/134

async fn it_should_restore_delegation_when_transferring_back(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Step 1: Get a fresh address and transfer a space to it first to establish baseline
    let original_addr = rig
        .spaced
        .client
        .wallet_get_new_address(ALICE, AddressKind::Space)
        .await?;
    let original_spk = SpaceAddress::from_str(&original_addr)
        .expect("valid space address")
        .script_pubkey();
    let original_id = NumId::from_spk::<Sha256>(original_spk.clone());

    // Get a space that Alice owns
    let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let space = alice_spaces
        .owned
        .iter()
        .find(|s| s.spaceout.space.is_some())
        .expect("Alice needs at least 1 space for this test");

    let space_name = space
        .spaceout
        .space
        .as_ref()
        .expect("space must exist")
        .name
        .clone();

    println!("Testing transfer-away-and-back with space: {}", space_name);

    // Transfer space to original_addr first to establish the delegation
    println!(
        "\nStep 1: Transferring {} to original address to establish delegation...",
        space_name
    );
    let setup_transfer = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None,
            spaces: vec![Subject::Label(space_name.clone())],
            to: Some(original_addr.clone()),
            data: None,
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&setup_transfer).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify initial delegation is established
    let initial_delegator = rig
        .spaced
        .client
        .get_delegator(Subject::NumId(original_id))
        .await?
        .expect("Original Num Id should have delegation after setup");
    assert_eq!(initial_delegator, space_name);
    println!(
        "✓ Initial delegation established: {} -> {}",
        original_id, space_name
    );

    // Step 2: Transfer space to a NEW address (different Num Id)
    let new_addr = rig
        .spaced
        .client
        .wallet_get_new_address(ALICE, AddressKind::Space)
        .await?;
    let new_spk = SpaceAddress::from_str(&new_addr)
        .expect("valid space address")
        .script_pubkey();
    let new_id = NumId::from_spk::<Sha256>(new_spk.clone());

    println!("\nStep 2: Transferring {} to new address...", space_name);
    println!("New Num Id will be: {}", new_id);

    let transfer1 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None,
            spaces: vec![Subject::Label(space_name.clone())],
            to: Some(new_addr.clone()),
            data: None,
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&transfer1).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify: original Num Id should have NO delegation now
    let delegator_after_transfer1 = rig
        .spaced
        .client
        .get_delegator(Subject::NumId(original_id))
        .await?;
    assert_eq!(
        delegator_after_transfer1, None,
        "Original Num Id should have no delegation after space was transferred away"
    );
    println!(
        "✓ Original Num Id delegation revoked: {:?}",
        delegator_after_transfer1
    );

    // Verify: new Num Id should have the delegation
    let delegator_new = rig
        .spaced
        .client
        .get_delegator(Subject::NumId(new_id))
        .await?
        .expect("New Num Id should have delegation");
    assert_eq!(
        delegator_new, space_name,
        "New Num Id should point to the space"
    );
    println!(
        "✓ New Num Id has delegation: {} -> {}",
        new_id, delegator_new
    );

    // Step 3: Transfer space BACK to original address
    println!(
        "\nStep 3: Transferring {} BACK to original address...",
        space_name
    );
    println!("Original address: {}", original_addr);

    let transfer2 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None,
            spaces: vec![Subject::Label(space_name.clone())],
            to: Some(original_addr.clone()),
            data: None,
        })],
        false,
    )
    .await?;
    assert!(wallet_res_err(&transfer2).is_ok());
    mine_and_sync(rig, 1).await?;

    // KEY TEST: Original Num Id should have delegation RESTORED
    let delegator_restored = rig
        .spaced
        .client
        .get_delegator(Subject::NumId(original_id))
        .await?;
    println!("Delegation after transfer back: {:?}", delegator_restored);

    assert!(
        delegator_restored.is_some(),
        "Original Num Id should have delegation restored after transferring back!"
    );
    assert_eq!(
        delegator_restored.unwrap(),
        space_name,
        "Original Num Id should point to the space again"
    );

    println!(
        "✓ Original Num Id delegation RESTORED: {} -> {}",
        original_id, space_name
    );

    // Verify: new Num Id should have NO delegation now
    let delegator_new_after = rig
        .spaced
        .client
        .get_delegator(Subject::NumId(new_id))
        .await?;
    assert_eq!(
        delegator_new_after, None,
        "New Num Id should have no delegation after space was transferred back"
    );
    println!("✓ New Num Id delegation revoked");

    println!("\n✓ Transfer-back delegation restoration working correctly!");
    Ok(())
}

// ============== Test: PTR Data ==============

async fn it_should_set_and_persist_ptr_data(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Test 1: Create a PTR
    println!("Test 1: Create PTR");
    let addr0 = rig
        .spaced
        .client
        .wallet_get_new_address(ALICE, AddressKind::Coin)
        .await?;
    let addr0_spk = bitcoin::address::Address::from_str(&addr0)?
        .assume_checked()
        .script_pubkey();
    wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreateNum(CreateNumParams {
            bind_spk: Some(addr0_spk.clone()),
        })],
        false,
    )
    .await?;
    mine_and_sync(rig, 1).await?;

    let id = NumId::from_spk::<Sha256>(addr0_spk.clone());
    println!("Num id created: {}", id);

    // Verify PTR exists with no data
    let ptr_initial = rig
        .spaced
        .client
        .get_num(Subject::NumId(id))
        .await?
        .expect("ptr should exist");
    assert_eq!(
        ptr_initial.numout.num.data, None,
        "PTR should have no data initially"
    );

    // Test 2: Set data on the PTR
    println!("\nTest 2: Set data on PTR");
    let test_data = b"Hello, PTR data!".to_vec();
    let set_data = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::SetFallback(SetFallbackParams {
            subject: Subject::NumId(id),
            data: test_data.clone(),
        })],
        false,
    )
    .await?;
    assert!(
        wallet_res_err(&set_data).is_ok(),
        "SetFallback should succeed"
    );
    mine_and_sync(rig, 1).await?;

    use spaces_protocol::Bytes;
    // Verify data was set
    let ptr_with_data = rig
        .spaced
        .client
        .get_num(Subject::NumId(id))
        .await?
        .expect("ptr should exist");
    assert_eq!(
        ptr_with_data.numout.num.data,
        Some(Bytes::new(test_data.clone())),
        "PTR data should be set"
    );
    println!(
        "✓ PTR data set successfully: {:?}",
        String::from_utf8_lossy(&test_data)
    );

    // Test 3: Transfer PTR without data - data should persist
    println!("\nTest 3: Transfer PTR without setting new data - data should persist");
    let bob_addr = rig
        .spaced
        .client
        .wallet_get_new_address(BOB, AddressKind::Space)
        .await?;
    let transfer = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None,
            spaces: vec![Subject::NumId(id)],
            to: Some(bob_addr.clone()),
            data: None,
        })],
        false,
    )
    .await?;
    assert!(
        wallet_res_err(&transfer).is_ok(),
        "Transfer PTR should succeed"
    );
    mine_and_sync(rig, 1).await?;

    let ptr_after_transfer = rig
        .spaced
        .client
        .get_num(Subject::NumId(id))
        .await?
        .expect("ptr should exist after transfer");
    assert_eq!(
        ptr_after_transfer.numout.num.data,
        Some(Bytes::new(test_data.clone())),
        "PTR data should persist after transfer without new data"
    );
    println!("✓ PTR data persisted after transfer");

    // Test 4: Update data with new value
    println!("\nTest 4: Update PTR data with new value");
    let new_data = b"Updated data!".to_vec();
    let update_data = wallet_do(
        rig,
        BOB,
        vec![RpcWalletRequest::SetFallback(SetFallbackParams {
            subject: Subject::NumId(id),
            data: new_data.clone(),
        })],
        false,
    )
    .await?;
    assert!(
        wallet_res_err(&update_data).is_ok(),
        "SetFallback should succeed"
    );
    mine_and_sync(rig, 1).await?;

    let ptr_updated = rig
        .spaced
        .client
        .get_num(Subject::NumId(id))
        .await?
        .expect("ptr should exist");
    assert_eq!(
        ptr_updated.numout.num.data,
        Some(Bytes::new(new_data.clone())),
        "PTR data should be updated"
    );
    println!(
        "✓ PTR data updated successfully: {:?}",
        String::from_utf8_lossy(&new_data)
    );

    // Test 5: Set empty data
    println!("\nTest 5: Set empty data");
    let empty_data = Vec::new();
    let set_empty = wallet_do(
        rig,
        BOB,
        vec![RpcWalletRequest::SetFallback(SetFallbackParams {
            subject: Subject::NumId(id),
            data: empty_data.clone(),
        })],
        false,
    )
    .await?;
    assert!(
        wallet_res_err(&set_empty).is_ok(),
        "SetFallback with empty data should succeed"
    );
    mine_and_sync(rig, 1).await?;

    let ptr_empty = rig
        .spaced
        .client
        .get_num(Subject::NumId(id))
        .await?
        .expect("ptr should exist");
    assert_eq!(
        ptr_empty.numout.num.data,
        Some(Bytes::new(empty_data)),
        "PTR data should be set to empty"
    );
    println!("✓ PTR data set to empty successfully");

    Ok(())
}

// ============== Test: Space Fallback Data ==============

async fn it_should_set_and_get_space_fallback(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let owned = alice_spaces
        .owned
        .first()
        .cloned()
        .expect("Alice should own at least one space");
    let space_name = owned
        .spaceout
        .space
        .as_ref()
        .expect("space must exist")
        .name
        .clone();
    let space_str = space_name.to_string();

    // Record the outpoint and script_pubkey before setfallback
    let space_before = rig
        .spaced
        .client
        .get_space(&space_str)
        .await?
        .expect("space should exist");
    let spk_before = space_before.spaceout.script_pubkey.clone();

    // Verify no fallback data initially via getfallback
    let subject = Subject::Label(space_name.clone());
    let fallback_before = rig.spaced.client.get_fallback(subject.clone()).await?;
    assert!(
        fallback_before.is_none(),
        "space should have no fallback data initially"
    );
    println!("✓ No fallback data initially");

    // Test 1: Set SIP-7 fallback data on the space
    println!("\nTest 1: Set SIP-7 fallback data on space");
    let records = sip7::RecordSet::pack(vec![
        sip7::Record::txt("btc", &["bc1qtest"]),
        sip7::Record::txt("nostr", &["npub1abc"]),
    ])
    .unwrap();
    let wire_data = records.as_slice().to_vec();

    let set_result = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::SetFallback(SetFallbackParams {
            subject: subject.clone(),
            data: wire_data.clone(),
        })],
        false,
    )
    .await?;
    assert!(
        wallet_res_err(&set_result).is_ok(),
        "SetFallback on space should succeed"
    );
    mine_and_sync(rig, 1).await?;

    // Verify space still exists and is still owned by Alice
    let space_after = rig
        .spaced
        .client
        .get_space(&space_str)
        .await?
        .expect("space should still exist after setfallback");
    assert!(
        space_after.spaceout.space.as_ref().unwrap().is_owned(),
        "space should still be owned after setfallback"
    );
    assert_eq!(
        space_after.spaceout.script_pubkey, spk_before,
        "space script_pubkey should not change after setfallback"
    );
    println!("✓ Space still owned by Alice at same address");

    // Verify data was set on the covenant
    use spaces_protocol::Covenant;
    match &space_after.spaceout.space.as_ref().unwrap().covenant {
        Covenant::Transfer { data, .. } => {
            assert_eq!(
                data.as_ref().map(|b| b.clone().to_vec()),
                Some(wire_data.clone()),
                "covenant data should match"
            );
        }
        _ => panic!("space should be in Transfer covenant"),
    }
    println!("✓ Covenant data matches wire-encoded SIP-7 records");

    // Verify via getfallback RPC
    let fallback = rig
        .spaced
        .client
        .get_fallback(subject.clone())
        .await?
        .expect("getfallback should return data");
    let parsed = fallback.records.expect("should parse as SIP-7 records");
    assert_eq!(parsed.unpack().unwrap().len(), 2, "should have 2 records");
    println!("✓ getfallback returns parsed SIP-7 records");

    // Test 2: Alice can still transfer the space after setfallback
    println!("\nTest 2: Transfer space after setfallback");
    let bob_addr = rig
        .spaced
        .client
        .wallet_get_new_address(BOB, AddressKind::Space)
        .await?;
    let transfer = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None,
            spaces: vec![Subject::Label(space_name.clone())],
            to: Some(bob_addr),
            data: None,
        })],
        false,
    )
    .await?;
    assert!(
        wallet_res_err(&transfer).is_ok(),
        "should be able to transfer space after setfallback"
    );
    mine_and_sync(rig, 1).await?;

    // Data should persist after transfer
    let fallback_after_transfer = rig
        .spaced
        .client
        .get_fallback(subject.clone())
        .await?
        .expect("fallback data should persist after transfer");
    assert!(
        fallback_after_transfer.records.is_some(),
        "SIP-7 records should still parse"
    );
    println!("✓ Fallback data persists after transfer");

    // Test 3: Bob can overwrite the fallback data
    println!("\nTest 3: Bob overwrites fallback data");
    let new_records =
        sip7::RecordSet::pack(vec![sip7::Record::txt("eth", &["0xdeadbeef"])]).unwrap();
    let new_wire = new_records.as_slice().to_vec();

    let bob_set = wallet_do(
        rig,
        BOB,
        vec![RpcWalletRequest::SetFallback(SetFallbackParams {
            subject: subject.clone(),
            data: new_wire.clone(),
        })],
        false,
    )
    .await?;
    assert!(
        wallet_res_err(&bob_set).is_ok(),
        "Bob should be able to setfallback on his space"
    );
    mine_and_sync(rig, 1).await?;

    let fallback_bob = rig
        .spaced
        .client
        .get_fallback(subject)
        .await?
        .expect("should have fallback data");
    let bob_parsed = fallback_bob.records.expect("should parse as SIP-7");
    assert_eq!(
        bob_parsed.unpack().unwrap().len(),
        1,
        "should have 1 record now"
    );
    println!("✓ Bob successfully overwrote fallback data");

    Ok(())
}

// ============== Main Test Runner ==============

#[tokio::test]
async fn run_ptr_tests() -> anyhow::Result<()> {
    let rig = TestRig::new_with_regtest_preset().await?;
    let wallets_path = rig.testdata_wallets_path().await;

    let count = rig.get_block_count().await? as u32;
    assert!(count > 3000, "expected an initialized test set");

    rig.wait_until_synced().await?;
    load_wallet(&rig, wallets_path.clone(), ALICE).await?;
    load_wallet(&rig, wallets_path.clone(), BOB).await?;
    load_wallet(&rig, wallets_path, EVE).await?;

    println!("\n=== Running Num Id Creation Tests ===");
    it_should_create_nums(&rig).await?;

    println!("\n=== Running Num Id Uniqueness Tests ===");
    it_should_reject_duplicate_num_id_delegations(&rig).await?;

    println!("\n=== Running Transfer-Back Delegation Restoration Tests ===");
    it_should_restore_delegation_when_transferring_back(&rig).await?;

    println!("\n=== Running Commitment & Rollback Tests ===");
    it_should_commit_and_rollback(&rig).await?;

    println!("\n=== Running Multiple Commitment Tests ===");
    it_should_handle_multiple_commitments(&rig).await?;

    println!("\n=== Running Pending Override Tests ===");
    it_should_override_pending_commitments(&rig).await?;

    println!("\n=== Running PTR n→n Transfer Rule Tests ===");
    it_should_transfer_ptr_with_n_to_n_rule(&rig).await?;

    println!("\n=== Running PTR Data Tests ===");
    it_should_set_and_persist_ptr_data(&rig).await?;

    println!("\n=== Running Space Fallback Data Tests ===");
    it_should_set_and_get_space_fallback(&rig).await?;

    println!("\n=== Running Numeric Delegation Tests ===");
    it_should_delegate_and_commit_numeric(&rig).await?;

    println!("\n=== Running Numeric Authorize Tests ===");
    it_should_authorize_numeric_to_another_wallet(&rig).await?;

    println!("\n=== Running Multiple Nums Same Tx Tests ===");
    it_should_create_multiple_nums_same_tx(&rig).await?;

    println!("\n=== Running Foreign Num Transfer Tests ===");
    it_should_transfer_foreign_num_with_secret(&rig).await?;

    println!("\n=== All tests passed! ===");
    Ok(())
}

fn gen_p2tr_keypair() -> (bitcoin::ScriptBuf, [u8; 32]) {
    use bitcoin::key::TapTweak;
    use bitcoin::opcodes::all::OP_PUSHNUM_1;
    use bitcoin::script::Builder;
    use bitcoin::secp256k1::{Keypair, Secp256k1};

    let secp = Secp256k1::new();
    let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let tweaked = keypair.tap_tweak(&secp, None);
    let (xonly, _) = tweaked.to_keypair().x_only_public_key();

    let spk = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(xonly.serialize())
        .into_script();

    let tweaked_secret = tweaked.to_keypair().secret_key().secret_bytes();
    (spk, tweaked_secret)
}

async fn it_should_transfer_foreign_num_with_secret(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Generate a keypair not owned by any wallet
    let (spk, secret) = gen_p2tr_keypair();
    let num_id = NumId::from_spk::<Sha256>(spk.clone());
    println!(
        "Test 1: Create num bound to external key (num_id={})",
        num_id
    );

    // Create a num bound to the external spk
    wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreateNum(CreateNumParams {
            bind_spk: Some(spk.clone()),
        })],
        false,
    )
    .await?;
    mine_and_sync(rig, 1).await?;

    // Verify the num exists
    let num_info = rig
        .spaced
        .client
        .get_num(Subject::NumId(num_id))
        .await?
        .expect("num should exist");
    assert_eq!(
        num_info.numout.script_pubkey, spk,
        "num should be bound to external spk"
    );
    println!(
        "  Num created: {} (id={})",
        num_info.numout.num.name, num_id
    );

    // Before transfer: num should appear in external list, not owned list
    rig.wait_until_wallet_synced(ALICE).await?;
    let owned_before = rig.spaced.client.wallet_list_nums(ALICE, None).await?;
    let external_before = rig
        .spaced
        .client
        .wallet_list_nums(ALICE, Some("external".to_string()))
        .await?;
    assert!(
        !owned_before.nums.iter().any(|n| n.numout.num.id == num_id),
        "num should NOT be in owned list before transfer"
    );
    assert!(
        external_before
            .nums
            .iter()
            .any(|n| n.numout.num.id == num_id),
        "num should be in external list before transfer"
    );
    println!("✓ Num correctly listed as external before transfer");

    // Test 1: Transfer the foreign num to ALICE's wallet using the secret
    println!("\nTest 2: Transfer foreign num to wallet using secret key");
    let secret_hex = hex::encode(secret);
    let result = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: Some(secret_hex.clone()),
            spaces: vec![Subject::NumId(num_id)],
            to: None, // transfer to self (wallet's own address)
            data: None,
        })],
        false,
    )
    .await?;
    assert!(
        wallet_res_err(&result).is_ok(),
        "transfer with secret should succeed"
    );
    mine_and_sync(rig, 1).await?;
    rig.wait_until_wallet_synced(ALICE).await?;

    // Verify ALICE's wallet now lists the num as owned, not external
    let owned_after = rig.spaced.client.wallet_list_nums(ALICE, None).await?;
    let external_after = rig
        .spaced
        .client
        .wallet_list_nums(ALICE, Some("external".to_string()))
        .await?;
    assert!(
        owned_after.nums.iter().any(|n| n.numout.num.id == num_id),
        "num should be in owned list after transfer"
    );
    assert!(
        !external_after
            .nums
            .iter()
            .any(|n| n.numout.num.id == num_id),
        "num should NOT be in external list after transfer"
    );
    println!("✓ Foreign num transferred to wallet, correctly moved from external to owned");

    // Test 2: Generate a second keypair, transfer using secret to that external address
    println!("\nTest 3: Transfer num from wallet to a new external key using wallet ownership");
    let (spk2, _secret2) = gen_p2tr_keypair();
    let addr2 = SpaceAddress(
        bitcoin::Address::from_script(&spk2, bitcoin::Network::Regtest).expect("valid address"),
    );

    let result2 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None, // ALICE owns it now, no secret needed
            spaces: vec![Subject::NumId(num_id)],
            to: Some(addr2.to_string()),
            data: None,
        })],
        false,
    )
    .await?;
    assert!(
        wallet_res_err(&result2).is_ok(),
        "transfer to external address should succeed"
    );
    mine_and_sync(rig, 1).await?;

    // Verify the num is now at the new spk
    let num_after = rig
        .spaced
        .client
        .get_num(Subject::NumId(num_id))
        .await?
        .expect("num should still exist");
    assert_eq!(
        num_after.numout.script_pubkey, spk2,
        "num should be at new external spk"
    );
    println!("✓ Num transferred to new external address");

    // After transferring out: should be back in external list, not owned
    rig.wait_until_wallet_synced(ALICE).await?;
    let owned_final = rig.spaced.client.wallet_list_nums(ALICE, None).await?;
    let external_final = rig
        .spaced
        .client
        .wallet_list_nums(ALICE, Some("external".to_string()))
        .await?;
    assert!(
        !owned_final.nums.iter().any(|n| n.numout.num.id == num_id),
        "num should NOT be in owned list after transferring out"
    );
    assert!(
        external_final
            .nums
            .iter()
            .any(|n| n.numout.num.id == num_id),
        "num should be back in external list after transferring out"
    );
    println!("✓ Num correctly back in external list after transferring out");

    Ok(())
}

// ============== Test: PTR n→n Transfer Rule ==============

async fn it_should_transfer_ptr_with_n_to_n_rule(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Test 1: Basic n→n transfer (same value, key rotation)
    println!("Test 1: n→n transfer (same value)");
    {
        // Create a PTR
        let addr0 = rig
            .spaced
            .client
            .wallet_get_new_address(ALICE, AddressKind::Coin)
            .await?;
        let addr0_spk = bitcoin::address::Address::from_str(&addr0)?
            .assume_checked()
            .script_pubkey();
        wallet_do(
            rig,
            ALICE,
            vec![RpcWalletRequest::CreateNum(CreateNumParams {
                bind_spk: Some(addr0_spk.clone()),
            })],
            false,
        )
        .await?;
        mine_and_sync(rig, 1).await?;

        let id = NumId::from_spk::<Sha256>(addr0_spk.clone());
        let ptr_before = rig
            .spaced
            .client
            .get_num(Subject::NumId(id))
            .await?
            .expect("ptr must exist");
        let value_before = ptr_before.numout.value;

        // Transfer to addr1 with SAME value (should use n→n rule)
        let addr1 = rig
            .spaced
            .client
            .wallet_get_new_address(BOB, AddressKind::Space)
            .await?;
        wallet_do(
            rig,
            ALICE,
            vec![RpcWalletRequest::Transfer(TransferSpacesParams {
                secret: None,
                spaces: vec![Subject::NumId(id)],
                to: Some(addr1.clone()),
                data: None,
            })],
            false,
        )
        .await?;
        mine_and_sync(rig, 1).await?;

        let ptr_after = rig
            .spaced
            .client
            .get_num(Subject::NumId(id))
            .await?
            .expect("ptr must still exist");
        let spk1 = SpaceAddress::from_str(&addr1)?.script_pubkey();

        assert_eq!(
            ptr_after.numout.script_pubkey, spk1,
            "PTR should transfer to new address"
        );
        assert_eq!(
            ptr_after.numout.value, value_before,
            "PTR value should remain same (n→n)"
        );
        println!("✓ n→n transfer successful (same value preserved)");
    }

    // Test 2: Multiple PTR transfers in same transaction
    println!("\nTest 2: Multiple PTR transfers in same tx");
    {
        // Create two PTRs
        let addr_a = rig
            .spaced
            .client
            .wallet_get_new_address(ALICE, AddressKind::Coin)
            .await?;
        let addr_b = rig
            .spaced
            .client
            .wallet_get_new_address(ALICE, AddressKind::Coin)
            .await?;
        let spk_a = bitcoin::address::Address::from_str(&addr_a)?
            .assume_checked()
            .script_pubkey();
        let spk_b = bitcoin::address::Address::from_str(&addr_b)?
            .assume_checked()
            .script_pubkey();

        wallet_do(
            rig,
            ALICE,
            vec![
                RpcWalletRequest::CreateNum(CreateNumParams {
                    bind_spk: Some(spk_a.clone()),
                }),
                RpcWalletRequest::CreateNum(CreateNumParams {
                    bind_spk: Some(spk_b.clone()),
                }),
            ],
            false,
        )
        .await?;
        mine_and_sync(rig, 1).await?;

        let id_a = NumId::from_spk::<Sha256>(spk_a.clone());
        let id_b = NumId::from_spk::<Sha256>(spk_b.clone());

        // Transfer both to different addresses
        let dest_a = rig
            .spaced
            .client
            .wallet_get_new_address(BOB, AddressKind::Space)
            .await?;
        let dest_b = rig
            .spaced
            .client
            .wallet_get_new_address(BOB, AddressKind::Space)
            .await?;

        wallet_do(
            rig,
            ALICE,
            vec![
                RpcWalletRequest::Transfer(TransferSpacesParams {
                    secret: None,
                    spaces: vec![Subject::NumId(id_a)],
                    to: Some(dest_a.clone()),
                    data: None,
                }),
                RpcWalletRequest::Transfer(TransferSpacesParams {
                    secret: None,
                    spaces: vec![Subject::NumId(id_b)],
                    to: Some(dest_b.clone()),
                    data: None,
                }),
            ],
            false,
        )
        .await?;
        mine_and_sync(rig, 1).await?;

        let ptr_a_after = rig
            .spaced
            .client
            .get_num(Subject::NumId(id_a))
            .await?
            .expect("ptr_a must exist");
        let ptr_b_after = rig
            .spaced
            .client
            .get_num(Subject::NumId(id_b))
            .await?
            .expect("ptr_b must exist");
        let spk_dest_a = SpaceAddress::from_str(&dest_a)?.script_pubkey();
        let spk_dest_b = SpaceAddress::from_str(&dest_b)?.script_pubkey();

        assert_eq!(
            ptr_a_after.numout.script_pubkey, spk_dest_a,
            "PTR A should transfer correctly"
        );
        assert_eq!(
            ptr_b_after.numout.script_pubkey, spk_dest_b,
            "PTR B should transfer correctly"
        );
        println!("✓ Multiple PTR transfers handled correctly");
    }

    // Test 3: Commitment preserves n→n rule (same value)
    println!("\nTest 3: Commitment uses n→n (same value preserved)");
    {
        // Get a space and delegate it
        let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
        let space = alice_spaces
            .owned
            .first()
            .expect("Alice should own a space")
            .clone();
        let space_name = space.spaceout.space.as_ref().expect("space").name.clone();

        // Delegate to create PTR
        wallet_do(
            rig,
            ALICE,
            vec![RpcWalletRequest::Operate(OperateParams {
                subject: space_name.clone().into(),
            })],
            false,
        )
        .await?;
        mine_and_sync(rig, 1).await?;

        let id = rig
            .spaced
            .client
            .get_delegation(space_name.clone().into())
            .await?
            .expect("delegation should exist");
        let ptr_before_commit = rig
            .spaced
            .client
            .get_num(Subject::NumId(id))
            .await?
            .expect("ptr must exist");
        let value_before = ptr_before_commit.numout.value;
        let spk_before = ptr_before_commit.numout.script_pubkey.clone();

        // Make a commitment (should preserve value via n→n)
        wallet_do(
            rig,
            ALICE,
            vec![RpcWalletRequest::Commit(CommitParams {
                subject: space_name.clone().into(),
                root: Some(sha256::Hash::from_slice(&[1u8; 32])?),
            })],
            false,
        )
        .await?;
        mine_and_sync(rig, 1).await?;

        let ptr_after_commit = rig
            .spaced
            .client
            .get_num(Subject::NumId(id))
            .await?
            .expect("ptr must exist after commit");

        assert_eq!(
            ptr_after_commit.numout.value, value_before,
            "Commitment should preserve PTR value (n→n)"
        );
        assert_eq!(
            ptr_after_commit.numout.script_pubkey, spk_before,
            "Commitment should keep same address"
        );

        // Verify commitment was created
        let commitment = rig
            .spaced
            .client
            .get_commitment(space_name.clone().into(), None)
            .await?
            .expect("commitment should exist");
        assert_eq!(
            commitment.state_root, [1u8; 32],
            "Commitment root should match"
        );
        println!("✓ Commitment preserves PTR value and address (n→n rule)");
    }

    Ok(())
}

// ============== Test: Numeric Delegation and Commitment ==============

async fn it_should_delegate_and_commit_numeric(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Create a num
    println!("Test 1: Create and delegate a numeric");
    let addr = rig
        .spaced
        .client
        .wallet_get_new_address(ALICE, AddressKind::Coin)
        .await?;
    let spk = bitcoin::address::Address::from_str(&addr)?
        .assume_checked()
        .script_pubkey();
    wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreateNum(CreateNumParams {
            bind_spk: Some(spk.clone()),
        })],
        false,
    )
    .await?;
    mine_and_sync(rig, 1).await?;

    let id = NumId::from_spk::<Sha256>(spk);
    let num_info = rig
        .spaced
        .client
        .get_num(Subject::NumId(id))
        .await?
        .expect("num must exist");
    let numeric = num_info.numout.num.name;
    let numeric_label = numeric.to_slabel();
    println!("  Created numeric: {}", numeric);

    // Verify no delegation exists yet
    let delegation_before = rig
        .spaced
        .client
        .get_delegation(Subject::Label(numeric_label.clone()))
        .await?;
    assert!(delegation_before.is_none(), "no delegation before delegate");

    // Delegate the numeric
    let delegate_res = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Operate(OperateParams {
            subject: Subject::Label(numeric_label.clone()),
        })],
        false,
    )
    .await?;
    wallet_res_err(&delegate_res)?;
    mine_and_sync(rig, 1).await?;

    // Verify delegation exists
    let delegation = rig
        .spaced
        .client
        .get_delegation(Subject::Label(numeric_label.clone()))
        .await?
        .expect("delegation should exist after delegate");
    println!("  Delegation established, delegator: {}", delegation);

    // Verify the num now has delegate dust value
    let num_after = rig
        .spaced
        .client
        .get_num(Subject::NumId(id))
        .await?
        .expect("num must still exist after delegate");
    assert_eq!(
        num_after.numout.value.to_sat() % 10,
        8,
        "num should have delegate dust signaling (value % 10 == 8)"
    );

    // Verify can_operate works for numeric subjects
    let can_op = rig
        .spaced
        .client
        .wallet_can_operate(ALICE, Subject::Label(numeric_label.clone()))
        .await?;
    assert!(can_op, "owner should be able to operate delegated numeric");
    let can_op_bob = rig
        .spaced
        .client
        .wallet_can_operate(BOB, Subject::Label(numeric_label.clone()))
        .await?;
    assert!(
        !can_op_bob,
        "non-owner should not be able to operate delegated numeric"
    );
    println!("✓ Numeric delegation and can_operate successful");

    // Test 2: Commit to the numeric
    println!("\nTest 2: Commit to delegated numeric");
    let commit_res = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: Subject::Label(numeric_label.clone()),
            root: Some(sha256::Hash::from_slice(&[42u8; 32])?),
        })],
        false,
    )
    .await?;
    wallet_res_err(&commit_res)?;
    mine_and_sync(rig, 1).await?;

    let commitment = rig
        .spaced
        .client
        .get_commitment(Subject::Label(numeric_label.clone()), None)
        .await?
        .expect("commitment should exist");
    assert_eq!(
        commitment.state_root, [42u8; 32],
        "commitment root should match"
    );
    println!("✓ Numeric commitment successful");

    // Test 3: Rollback the commitment
    println!("\nTest 3: Rollback numeric commitment");
    let rollback_res = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: Subject::Label(numeric_label.clone()),
            root: None,
        })],
        false,
    )
    .await?;
    wallet_res_err(&rollback_res)?;
    mine_and_sync(rig, 1).await?;

    let after_rollback = rig
        .spaced
        .client
        .get_commitment(Subject::Label(numeric_label.clone()), None)
        .await?;
    assert!(
        after_rollback.is_none(),
        "commitment tip should be gone after rollback"
    );
    println!("✓ Numeric rollback successful");

    Ok(())
}

// ============== Test: Authorize Numeric to Another Wallet ==============

async fn it_should_authorize_numeric_to_another_wallet(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Create a num for Alice
    println!("Test 1: Alice creates and delegates a numeric");
    wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreateNum(CreateNumParams {
            bind_spk: None,
        })],
        false,
    )
    .await?;
    mine_and_sync(rig, 1).await?;

    let alice_nums = rig.spaced.client.wallet_list_nums(ALICE, None).await?;
    let num_entry = alice_nums.nums.last().expect("Alice should have a num");
    let numeric_label = num_entry.numout.num.name.to_slabel();
    let num_id = num_entry.numout.num.id;
    println!(
        "  Created numeric: {} (id={})",
        num_entry.numout.num.name, num_id
    );

    // Delegate it
    let delegate_res = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Operate(OperateParams {
            subject: Subject::Label(numeric_label.clone()),
        })],
        false,
    )
    .await?;
    wallet_res_err(&delegate_res)?;
    mine_and_sync(rig, 1).await?;

    // Alice can operate, Bob cannot
    let can_op_alice = rig
        .spaced
        .client
        .wallet_can_operate(ALICE, Subject::Label(numeric_label.clone()))
        .await?;
    assert!(
        can_op_alice,
        "Alice should be able to operate before authorize"
    );
    let can_op_bob = rig
        .spaced
        .client
        .wallet_can_operate(BOB, Subject::Label(numeric_label.clone()))
        .await?;
    assert!(
        !can_op_bob,
        "Bob should not be able to operate before authorize"
    );
    println!("✓ Pre-authorize: Alice can operate, Bob cannot");

    // Get the delegating NumId
    let delegation_id = rig
        .spaced
        .client
        .get_delegation(Subject::Label(numeric_label.clone()))
        .await?
        .expect("delegation must exist");
    println!("  Delegating num id: {}", delegation_id);

    // Alice transfers the delegating num to Bob (authorize)
    println!("\nTest 2: Alice authorizes Bob by transferring the delegating num");
    let bob_addr = rig
        .spaced
        .client
        .wallet_get_new_address(BOB, AddressKind::Space)
        .await?;
    let authorize_res = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            secret: None,
            spaces: vec![Subject::NumId(delegation_id)],
            to: Some(bob_addr),
            data: None,
        })],
        false,
    )
    .await?;
    wallet_res_err(&authorize_res)?;
    mine_and_sync(rig, 1).await?;

    // Now Bob can operate, Alice cannot
    let can_op_bob_after = rig
        .spaced
        .client
        .wallet_can_operate(BOB, Subject::Label(numeric_label.clone()))
        .await?;
    assert!(
        can_op_bob_after,
        "Bob should be able to operate after authorize"
    );
    let can_op_alice_after = rig
        .spaced
        .client
        .wallet_can_operate(ALICE, Subject::Label(numeric_label.clone()))
        .await?;
    assert!(
        !can_op_alice_after,
        "Alice should not be able to operate after authorize"
    );
    println!("✓ Post-authorize: Bob can operate, Alice cannot");

    // Test 3: Bob can commit to the numeric
    println!("\nTest 3: Bob commits to the numeric");
    let commit_res = wallet_do(
        rig,
        BOB,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: Subject::Label(numeric_label.clone()),
            root: Some(sha256::Hash::from_slice(&[99u8; 32])?),
        })],
        false,
    )
    .await?;
    wallet_res_err(&commit_res)?;
    mine_and_sync(rig, 1).await?;

    let commitment = rig
        .spaced
        .client
        .get_commitment(Subject::Label(numeric_label.clone()), None)
        .await?
        .expect("commitment should exist after Bob commits");
    assert_eq!(
        commitment.state_root, [99u8; 32],
        "commitment root should match Bob's"
    );
    println!("✓ Bob successfully committed to Alice's numeric");

    // Test 4: Bob rolls back the commitment
    println!("\nTest 4: Bob rolls back the commitment");
    let rollback_res = wallet_do(
        rig,
        BOB,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: Subject::Label(numeric_label.clone()),
            root: None,
        })],
        false,
    )
    .await?;
    wallet_res_err(&rollback_res)?;
    mine_and_sync(rig, 1).await?;

    let after_rollback = rig
        .spaced
        .client
        .get_commitment(Subject::Label(numeric_label.clone()), None)
        .await?;
    assert!(
        after_rollback.is_none(),
        "commitment tip should be gone after rollback"
    );

    // Delegation should still be intact after rollback
    let can_op_bob_after_rollback = rig
        .spaced
        .client
        .wallet_can_operate(BOB, Subject::Label(numeric_label.clone()))
        .await?;
    assert!(
        can_op_bob_after_rollback,
        "Bob should still be able to operate after rollback"
    );
    println!("✓ Bob rolled back successfully, delegation intact");

    // Test 5: Alice re-delegates to revoke Bob's authorization
    println!("\nTest 5: Alice re-delegates to revoke Bob's authorization");
    let redelegate_res = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Operate(OperateParams {
            subject: Subject::Label(numeric_label.clone()),
        })],
        false,
    )
    .await?;
    wallet_res_err(&redelegate_res)?;
    mine_and_sync(rig, 1).await?;

    let can_op_alice_revoked = rig
        .spaced
        .client
        .wallet_can_operate(ALICE, Subject::Label(numeric_label.clone()))
        .await?;
    assert!(
        can_op_alice_revoked,
        "Alice should be able to operate after re-delegate"
    );
    let can_op_bob_revoked = rig
        .spaced
        .client
        .wallet_can_operate(BOB, Subject::Label(numeric_label.clone()))
        .await?;
    assert!(
        !can_op_bob_revoked,
        "Bob should no longer be able to operate after revoke"
    );
    println!("✓ Re-delegate revoked Bob's authorization, Alice has control again");

    // Test 6: Alice commits successfully after re-delegation
    println!("\nTest 6: Alice commits after revoking Bob");
    let alice_commit_res = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: Subject::Label(numeric_label.clone()),
            root: Some(sha256::Hash::from_slice(&[77u8; 32])?),
        })],
        false,
    )
    .await?;
    wallet_res_err(&alice_commit_res)?;
    mine_and_sync(rig, 1).await?;

    let alice_commitment = rig
        .spaced
        .client
        .get_commitment(Subject::Label(numeric_label.clone()), None)
        .await?
        .expect("commitment should exist after Alice commits");
    assert_eq!(
        alice_commitment.state_root, [77u8; 32],
        "commitment root should match Alice's"
    );
    println!("✓ Alice committed successfully");

    // Test 7: Bob can no longer commit
    println!("\nTest 7: Bob cannot commit after revocation");
    let bob_fail_res = wallet_do(
        rig,
        BOB,
        vec![RpcWalletRequest::Commit(CommitParams {
            subject: Subject::Label(numeric_label.clone()),
            root: Some(sha256::Hash::from_slice(&[88u8; 32])?),
        })],
        false,
    )
    .await;
    assert!(
        bob_fail_res.is_err(),
        "Bob's commit should fail after revocation"
    );
    println!("✓ Bob cannot commit after Alice revoked authorization");

    Ok(())
}

// ============== Test: Multiple Nums Created in Same Tx ==============

async fn it_should_create_multiple_nums_same_tx(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    println!("Test 1: Create two nums in a single transaction (auto-generated addresses)");
    let before = rig.spaced.client.wallet_list_nums(ALICE, None).await?;
    let before_count = before.nums.len();

    wallet_do(
        rig,
        ALICE,
        vec![
            RpcWalletRequest::CreateNum(CreateNumParams { bind_spk: None }),
            RpcWalletRequest::CreateNum(CreateNumParams { bind_spk: None }),
        ],
        false,
    )
    .await?;
    mine_and_sync(rig, 1).await?;

    let after = rig.spaced.client.wallet_list_nums(ALICE, None).await?;
    assert_eq!(after.nums.len(), before_count + 2, "two new nums created");

    let new_nums: Vec<_> = after
        .nums
        .iter()
        .filter(|e| {
            !before
                .nums
                .iter()
                .any(|b| b.numout.num.id == e.numout.num.id)
        })
        .collect();
    assert_eq!(new_nums.len(), 2, "exactly two new nums");

    let name_a = new_nums[0].numout.num.name;
    let name_b = new_nums[1].numout.num.name;
    let id_a = new_nums[0].numout.num.id;
    let id_b = new_nums[1].numout.num.id;

    println!("  Num A: {} (id={})", name_a, id_a);
    println!("  Num B: {} (id={})", name_b, id_b);

    // Both should share same block and tx_pos but have different vouts
    assert_eq!(name_a.block(), name_b.block(), "same block");
    assert_eq!(name_a.tx_pos(), name_b.tx_pos(), "same tx position");
    assert_ne!(name_a.vout(), name_b.vout(), "different vouts");
    println!("✓ Multiple nums in same tx have unique SNumeric (different vout)");

    // Test 2: Both can be looked up by their numeric label
    println!("\nTest 2: Lookup both by numeric label");
    let lookup_a = rig
        .spaced
        .client
        .get_num(Subject::Label(name_a.to_slabel()))
        .await?;
    let lookup_b = rig
        .spaced
        .client
        .get_num(Subject::Label(name_b.to_slabel()))
        .await?;
    assert!(
        lookup_a.is_some(),
        "num A must be findable by numeric label"
    );
    assert!(
        lookup_b.is_some(),
        "num B must be findable by numeric label"
    );
    assert_eq!(
        lookup_a.unwrap().numout.num.id,
        id_a,
        "correct num A resolved"
    );
    assert_eq!(
        lookup_b.unwrap().numout.num.id,
        id_b,
        "correct num B resolved"
    );
    println!("✓ Both nums resolvable by their unique numeric labels");

    // Test 3: Delegate both and verify independent delegations
    println!("\nTest 3: Delegate both nums independently");
    wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Operate(OperateParams {
            subject: Subject::Label(name_a.to_slabel()),
        })],
        false,
    )
    .await?;
    mine_and_sync(rig, 1).await?;

    wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Operate(OperateParams {
            subject: Subject::Label(name_b.to_slabel()),
        })],
        false,
    )
    .await?;
    mine_and_sync(rig, 1).await?;

    let del_a = rig
        .spaced
        .client
        .get_delegation(Subject::Label(name_a.to_slabel()))
        .await?;
    let del_b = rig
        .spaced
        .client
        .get_delegation(Subject::Label(name_b.to_slabel()))
        .await?;
    assert!(del_a.is_some(), "delegation A should exist");
    assert!(del_b.is_some(), "delegation B should exist");
    println!("✓ Both nums delegated independently");

    Ok(())
}
