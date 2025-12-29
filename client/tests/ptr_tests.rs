use std::{path::PathBuf, str::FromStr};
use anyhow::anyhow;
use spaces_client::{
    rpc::{
        RpcClient, RpcWalletRequest,
        RpcWalletTxBuilder,
    },
    wallets::{AddressKind, WalletResponse},
};
use spaces_client::rpc::{CommitParams, CreatePtrParams, DelegateParams, SetPtrDataParams, SpaceOrPtr, TransferSpacesParams};
use spaces_client::store::Sha256;
use spaces_protocol::{bitcoin, bitcoin::{FeeRate}};
use spaces_protocol::bitcoin::hashes::{sha256, Hash};
use spaces_ptr::sptr::Sptr;
use spaces_testutil::TestRig;
use spaces_wallet::{export::WalletExport};
use spaces_wallet::address::SpaceAddress;

const ALICE: &str = "wallet_99";
const BOB: &str = "wallet_98";
const EVE: &str = "wallet_93";

// ============== Helper Functions ==============

fn wallet_res_err(res: &WalletResponse) -> anyhow::Result<()> {
    for tx in &res.result {
        if let Some(e) = tx.error.as_ref() {
            let s = e.iter()
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

// ============== Test: Basic SPTR Creation ==============

async fn it_should_create_sptrs(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;

    // Create ptr bound to addr0
    let addr0 = rig.spaced.client.wallet_get_new_address(ALICE, AddressKind::Coin).await?;
    let addr0_spk = bitcoin::address::Address::from_str(&addr0)
        .expect("valid").assume_checked()
        .script_pubkey();
    let addr0_spk_string = hex::encode(addr0_spk.as_bytes());

    let create0 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreatePtr(CreatePtrParams { spk: addr0_spk_string.clone() })],
        false,
    ).await.expect("CreatePtr addr0");
    assert!(wallet_res_err(&create0).is_ok(), "CreatePtr(addr0) must not error");

    mine_and_sync(rig, 1).await?;

    let spk0 = bitcoin::address::Address::from_str(&addr0)
        .expect("valid addr0")
        .assume_checked()
        .script_pubkey();
    let sptr0 = Sptr::from_spk::<Sha256>(spk0.clone());

    let ptr0 = rig.spaced.client.get_ptr(sptr0).await?
        .expect("ptr must exist after first CreatePtr");
    let bound_spk_before = ptr0.ptrout.script_pubkey.clone();

    // Transfer ptr to addr1 (binding should change)
    let addr1 = rig.spaced.client.wallet_get_new_address(BOB, AddressKind::Space).await?;
    let xfer = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            spaces: vec![SpaceOrPtr::Ptr(sptr0)],
            to: Some(addr1.clone()),
            data: None,
        })],
        false,
    ).await.expect("Transfer PTR to addr1");
    assert!(wallet_res_err(&xfer).is_ok(), "Transfer PTR must not error");

    mine_and_sync(rig, 1).await?;

    let spk1 = SpaceAddress::from_str(&addr1)
        .expect("valid addr1")
        .script_pubkey();

    let ptr_after_xfer = rig.spaced.client.get_ptr(sptr0).await?
        .expect("ptr must still resolve after transfer");
    let bound_spk_after = ptr_after_xfer.ptrout.script_pubkey.clone();

    assert_ne!(bound_spk_before, bound_spk_after, "binding must change after transfer");
    assert_eq!(bound_spk_after, spk1, "binding must equal new destination spk");

    // Duplicate CreatePtr on ORIGINAL addr0 → should be ignored
    let dup = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreatePtr(CreatePtrParams { spk: addr0_spk_string })],
        true,
    ).await.expect("duplicate CreatePtr(addr0)");
    assert!(wallet_res_err(&dup).is_ok(), "duplicate CreatePtr should not error");

    mine_and_sync(rig, 1).await?;

    let ptr_after_dup = rig.spaced.client.get_ptr(sptr0).await?
        .expect("ptr must still resolve after duplicate");
    let bound_spk_final = ptr_after_dup.ptrout.script_pubkey.clone();

    assert_eq!(bound_spk_final, spk1, "duplicate CreatePtr must be ignored");
    assert_ne!(bound_spk_final, spk0, "binding must not revert to original");

    Ok(())
}

// ============== Test: Basic Commitments with Rollback ==============

async fn it_should_commit_and_rollback(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Get a space that Alice owns
    let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let owned = alice_spaces.owned.first().cloned()
        .expect("Alice should own at least one space");
    let space_name = owned.spaceout.space.as_ref()
        .expect("space must exist").name.clone();

    // Setup: Delegate the space to establish SPTR
    let delegate = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Delegate(DelegateParams {
            space: space_name.clone(),
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&delegate).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify delegation is set up
    rig.spaced.client.get_delegation(space_name.clone()).await?
        .expect("delegation should be established");

    // Test 1: Make initial commitment [1u8;32]
    println!("Creating initial commitment [1u8;32]...");
    let commit1 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            space: space_name.clone(),
            root: Some(sha256::Hash::from_slice(&[1u8;32]).expect("valid")),
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&commit1).is_ok());
    mine_and_sync(rig, 1).await?;

    let tip = rig.spaced.client.get_commitment(space_name.clone(), None).await?
        .expect("commitment should exist");
    assert_eq!(tip.state_root, [1u8;32]);
    assert_eq!(tip.prev_root, None);

    // Test 2: Rollback pending commitment
    println!("Rolling back pending commitment [1u8;32]...");
    let rollback = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            space: space_name.clone(),
            root: None, // None = rollback
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&rollback).is_ok());
    mine_and_sync(rig, 1).await?;

    let tip_after_rollback = rig.spaced.client.get_commitment(space_name.clone(), None).await?;
    assert_eq!(tip_after_rollback, None, "commitment should be rolled back");

    // Test 3: Create new commitment and finalize it
    println!("Creating commitment [2u8;32] and finalizing...");
    let commit2 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            space: space_name.clone(),
            root: Some(sha256::Hash::from_slice(&[2u8;32]).expect("valid")),
        })],
        false,
    ).await?;
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
            space: space_name.clone(),
            root: None, // Rollback attempt
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&rollback_finalized).is_ok());
    mine_and_sync(rig, 1).await?;

    let tip_after_failed_rollback = rig.spaced.client.get_commitment(space_name.clone(), None).await?
        .expect("finalized commitment should still exist");
    assert_eq!(tip_after_failed_rollback.state_root, [2u8;32],
               "finalized commitment should not be rolled back");

    // Test 5: Add new commitment on top of finalized
    println!("Adding [3u8;32] on top of finalized [2u8;32]...");
    let commit3 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            space: space_name.clone(),
            root: Some(sha256::Hash::from_slice(&[3u8;32]).expect("valid")),
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&commit3).is_ok());
    mine_and_sync(rig, 1).await?;

    let tip_final = rig.spaced.client.get_commitment(space_name.clone(), None).await?
        .expect("new commitment should exist");
    assert_eq!(tip_final.state_root, [3u8;32]);
    assert_eq!(tip_final.prev_root, Some([2u8;32]));

    // Verify finalized [2u8;32] still exists
    let finalized = rig.spaced.client.get_commitment(
        space_name.clone(),
        Some(sha256::Hash::from_slice(&[2u8;32]).expect("valid"))
    ).await?.expect("finalized commitment should be preserved");
    assert_eq!(finalized.state_root, [2u8;32]);

    // Test 6: Rollback pending [3u8;32] and verify registry points back to [2u8;32]
    println!("Rolling back pending [3u8;32]...");
    let rollback3 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            space: space_name.clone(),
            root: None,
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&rollback3).is_ok());
    mine_and_sync(rig, 1).await?;

    let tip_after_rollback = rig.spaced.client.get_commitment(space_name.clone(), None).await?
        .expect("should still have finalized commitment after rollback");
    assert_eq!(tip_after_rollback.state_root, [2u8;32],
        "registry should point back to finalized [2u8;32] after rolling back pending");
    println!("✓ Registry correctly updated to [2u8;32] after rollback");

    Ok(())
}

// ============== Test: Multiple Commitments in Single Transaction ==============

async fn it_should_handle_multiple_commitments(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Get two spaces that Alice owns
    let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    assert!(alice_spaces.owned.len() >= 2, "Alice needs at least 2 spaces for this test");

    let space1_name = alice_spaces.owned[0].spaceout.space.as_ref()
        .expect("space must exist").name.clone();
    let space2_name = alice_spaces.owned[1].spaceout.space.as_ref()
        .expect("space must exist").name.clone();

    // Setup: Delegate both spaces to establish SPTRs
    for space_name in [&space1_name, &space2_name] {
        let delegate = wallet_do(
            rig,
            ALICE,
            vec![RpcWalletRequest::Delegate(DelegateParams {
                space: space_name.clone(),
            })],
            false,
        ).await?;
        assert!(wallet_res_err(&delegate).is_ok());
    }
    mine_and_sync(rig, 1).await?;

    // Verify both delegations exist
    let sptr1 = rig.spaced.client.get_delegation(space1_name.clone()).await?
        .expect("space1 should have delegation");
    let sptr2 = rig.spaced.client.get_delegation(space2_name.clone()).await?
        .expect("space2 should have delegation");

    println!("Space 1: {} -> SPTR: {}", space1_name, sptr1);
    println!("Space 2: {} -> SPTR: {}", space2_name, sptr2);

    // Verify delegations match delegator
    let delegator1 = rig.spaced.client.get_delegator(sptr1).await?
        .expect("sptr1 delegator should exist");
    let delegator2 = rig.spaced.client.get_delegator(sptr2).await?
        .expect("sptr2 delegator should exist");

    assert_eq!(delegator1.to_string(), space1_name.to_string(), "space 1 delegators dont match");
    assert_eq!(delegator2.to_string(), space2_name.to_string(), "space 2 delegators dont match");


    // Test 1: Submit two commitments in one transaction
    println!("Submitting 2 commitments in single transaction...");
    let multi_commit = wallet_do(
        rig,
        ALICE,
        vec![
            RpcWalletRequest::Commit(CommitParams {
                space: space1_name.clone(),
                root: Some(sha256::Hash::from_slice(&[10u8;32]).expect("valid")),
            }),
            RpcWalletRequest::Commit(CommitParams {
                space: space2_name.clone(),
                root: Some(sha256::Hash::from_slice(&[20u8;32]).expect("valid")),
            }),
        ],
        false,
    ).await?;
    assert!(wallet_res_err(&multi_commit).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify both commitments were created
    let commit2 = rig.spaced.client.get_commitment(space2_name.clone(), None).await?
        .expect("space2 should have commitment");
    let commit1 = rig.spaced.client.get_commitment(space1_name.clone(), None).await?
        .expect("space1 should have commitment");


    assert_eq!(commit1.state_root, [10u8;32], "space1 commitment");
    assert_eq!(commit2.state_root, [20u8;32], "space2 commitment");

    // Test 2: Rollback both in single transaction
    println!("Rolling back both commitments in single transaction...");
    let multi_rollback = wallet_do(
        rig,
        ALICE,
        vec![
            RpcWalletRequest::Commit(CommitParams {
                space: space1_name.clone(),
                root: None, // rollback
            }),
            RpcWalletRequest::Commit(CommitParams {
                space: space2_name.clone(),
                root: None, // rollback
            }),
        ],
        false,
    ).await?;
    assert!(wallet_res_err(&multi_rollback).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify both were rolled back
    let commit1_after = rig.spaced.client.get_commitment(space1_name.clone(), None).await?;
    let commit2_after = rig.spaced.client.get_commitment(space2_name.clone(), None).await?;

    assert_eq!(commit1_after, None, "space1 should be rolled back");
    assert_eq!(commit2_after, None, "space2 should be rolled back");

    // Test 3: Mixed operations - commit one, keep other unchanged
    println!("Mixed operation: new commitment for space1 only...");
    let mixed = wallet_do(
        rig,
        ALICE,
        vec![
            RpcWalletRequest::Commit(CommitParams {
                space: space1_name.clone(),
                root: Some(sha256::Hash::from_slice(&[30u8;32]).expect("valid")),
            }),
        ],
        false,
    ).await?;
    assert!(wallet_res_err(&mixed).is_ok());
    mine_and_sync(rig, 1).await?;

    let commit1_final = rig.spaced.client.get_commitment(space1_name.clone(), None).await?
        .expect("space1 should have new commitment");
    let commit2_final = rig.spaced.client.get_commitment(space2_name.clone(), None).await?;

    assert_eq!(commit1_final.state_root, [30u8;32], "space1 updated");
    assert_eq!(commit2_final, None, "space2 unchanged");

    Ok(())
}

// ============== Test: Commitment Override Within 144 Blocks ==============

async fn it_should_override_pending_commitments(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let space_name = alice_spaces.owned[0].spaceout.space.as_ref()
        .expect("space must exist").name.clone();

    // Setup: Delegate the space to establish SPTR
    let delegate = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Delegate(DelegateParams {
            space: space_name.clone(),
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&delegate).is_ok());
    mine_and_sync(rig, 1).await?;

    // Make commitment [1u8;32]
    println!("Creating commitment [1u8;32]...");
    let commit1 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            space: space_name.clone(),
            root: Some(sha256::Hash::from_slice(&[1u8;32]).expect("valid")),
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&commit1).is_ok());
    mine_and_sync(rig, 1).await?;

    // Override with [2u8;32] while still pending
    println!("Overriding with [2u8;32] while pending...");
    let commit2 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            space: space_name.clone(),
            root: Some(sha256::Hash::from_slice(&[2u8;32]).expect("valid")),
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&commit2).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify [1u8;32] is gone, [2u8;32] is tip
    let old_commit = rig.spaced.client.get_commitment(
        space_name.clone(),
        Some(sha256::Hash::from_slice(&[1u8;32]).expect("valid"))
    ).await?;
    assert_eq!(old_commit, None, "[1u8;32] should be overridden");

    let tip = rig.spaced.client.get_commitment(space_name.clone(), None).await?
        .expect("tip should exist");
    assert_eq!(tip.state_root, [2u8;32]);
    assert_eq!(tip.prev_root, None, "no previous since [1u8;32] was overridden");

    // Finalize [2u8;32]
    println!("Finalizing [2u8;32]...");
    mine_and_sync(rig, 144).await?;

    // Try to override finalized [2u8;32] with [3u8;32] - should chain instead
    println!("Adding [3u8;32] on top of finalized [2u8;32]...");
    let commit3 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            space: space_name.clone(),
            root: Some(sha256::Hash::from_slice(&[3u8;32]).expect("valid")),
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&commit3).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify [2u8;32] still exists and [3u8;32] chains from it
    let finalized = rig.spaced.client.get_commitment(
        space_name.clone(),
        Some(sha256::Hash::from_slice(&[2u8;32]).expect("valid"))
    ).await?.expect("[2u8;32] should still exist");
    assert_eq!(finalized.state_root, [2u8;32]);

    let new_tip = rig.spaced.client.get_commitment(space_name.clone(), None).await?
        .expect("new tip should exist");
    assert_eq!(new_tip.state_root, [3u8;32]);
    assert_eq!(new_tip.prev_root, Some([2u8;32]));

    Ok(())
}

async fn it_should_reject_duplicate_sptr_delegations(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Get two spaces that Alice owns
    let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    assert!(alice_spaces.owned.len() >= 2, "Alice needs at least 2 spaces for this test");

    let space1_name = alice_spaces.owned[0].spaceout.space.as_ref()
        .expect("space must exist").name.clone();
    let space2_name = alice_spaces.owned[1].spaceout.space.as_ref()
        .expect("space must exist").name.clone();

    println!("Testing SPTR uniqueness with {} and {}", space1_name, space2_name);

    // Get a common address to create the same SPTR
    let common_addr = rig.spaced.client.wallet_get_new_address(ALICE, AddressKind::Space).await?;
    let common_spk = SpaceAddress::from_str(&common_addr)
        .expect("valid space address")
        .script_pubkey();
    let common_sptr = Sptr::from_spk::<Sha256>(common_spk.clone());

    println!("Common address: {}", common_addr);
    println!("Expected SPTR: {}", common_sptr);

    // Transfer space1 to the common address
    println!("Transferring {} to common address...", space1_name);
    let transfer1 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            spaces: vec![SpaceOrPtr::Space(space1_name.clone())],
            to: Some(common_addr.clone()),
            data: None,
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&transfer1).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify the reverse mapping: SPTR -> space1
    let delegator1 = rig.spaced.client.get_delegator(common_sptr).await?
        .expect("common SPTR should have delegator");
    assert_eq!(delegator1, space1_name, "common SPTR should point to space1");

    println!("✓ Space1 successfully claimed SPTR {} (reverse mapping: {} -> {})",
        common_sptr, common_sptr, space1_name);

    // Transfer space2 to the SAME address (same SPTR)
    println!("Transferring {} to the same address (attempting to claim same SPTR)...", space2_name);
    let transfer2 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            spaces: vec![SpaceOrPtr::Space(space2_name.clone())],
            to: Some(common_addr.clone()),
            data: None,
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&transfer2).is_ok());
    mine_and_sync(rig, 1).await?;

    // Key test: Verify the reverse mapping was NOT overwritten
    // The SPTR should still point to space1, not space2
    let delegator_after = rig.spaced.client.get_delegator(common_sptr).await?
        .expect("common SPTR should still have delegator");
    assert_eq!(delegator_after, space1_name,
        "CRITICAL: common SPTR should still point to space1 (not overwritten by space2)");

    println!("✓ Space2 correctly rejected - reverse mapping preserved ({} -> {})",
        common_sptr, space1_name);

    // Note: get_delegation for both spaces will return Some(common_sptr) because
    // both are at the same address, but only space1 actually owns the delegation

    // Transfer space1 away to free up the SPTR
    println!("Moving {} away to free up SPTR...", space1_name);
    let new_addr = rig.spaced.client.wallet_get_new_address(ALICE, AddressKind::Space).await?;
    let transfer_away = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            spaces: vec![SpaceOrPtr::Space(space1_name.clone())],
            to: Some(new_addr),
            data: None,
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&transfer_away).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify common_sptr is now free (reverse mapping removed)
    let delegator_freed = rig.spaced.client.get_delegator(common_sptr).await?;
    assert_eq!(delegator_freed, None, "common SPTR should be free (no reverse mapping) after space1 moved");

    println!("✓ SPTR freed - reverse mapping removed");

    // Now space2 should be able to claim it if we transfer it back
    println!("Re-transferring {} to now-free SPTR...", space2_name);
    let transfer2_retry = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            spaces: vec![SpaceOrPtr::Space(space2_name.clone())],
            to: Some(common_addr),
            data: None,
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&transfer2_retry).is_ok());
    mine_and_sync(rig, 1).await?;

    // Verify space2 now owns the reverse mapping
    let delegator2_retry = rig.spaced.client.get_delegator(common_sptr).await?
        .expect("common SPTR should have delegator");
    assert_eq!(delegator2_retry, space2_name,
        "common SPTR should now point to space2 (reverse mapping updated)");

    println!("✓ Space2 successfully claimed SPTR after it was freed ({} -> {})",
        common_sptr, space2_name);

    Ok(())
}

// ============== Test: PTR Data ==============

async fn it_should_set_and_persist_ptr_data(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Test 1: Create a PTR
    println!("Test 1: Create PTR");
    let addr0 = rig.spaced.client.wallet_get_new_address(ALICE, AddressKind::Coin).await?;
    let addr0_spk = bitcoin::address::Address::from_str(&addr0)?
        .assume_checked()
        .script_pubkey();
    let addr0_spk_string = hex::encode(addr0_spk.as_bytes());

    wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreatePtr(CreatePtrParams {
            spk: addr0_spk_string,
        })],
        false,
    ).await?;
    mine_and_sync(rig, 1).await?;

    let sptr = Sptr::from_spk::<Sha256>(addr0_spk.clone());
    println!("SPTR created: {}", sptr);

    // Verify PTR exists with no data
    let ptr_initial = rig.spaced.client.get_ptr(sptr).await?
        .expect("ptr should exist");
    assert_eq!(ptr_initial.ptrout.sptr.as_ref().unwrap().data, None, "PTR should have no data initially");

    // Test 2: Set data on the PTR
    println!("\nTest 2: Set data on PTR");
    let test_data = b"Hello, PTR data!".to_vec();
    let set_data = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::SetPtrData(SetPtrDataParams {
            sptr,
            data: test_data.clone(),
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&set_data).is_ok(), "SetPtrData should succeed");
    mine_and_sync(rig, 1).await?;

    use spaces_protocol::Bytes;
    // Verify data was set
    let ptr_with_data = rig.spaced.client.get_ptr(sptr).await?
        .expect("ptr should exist");
    assert_eq!(ptr_with_data.ptrout.sptr.as_ref().unwrap().data, Some(Bytes::new(test_data.clone())), "PTR data should be set");
    println!("✓ PTR data set successfully: {:?}", String::from_utf8_lossy(&test_data));

    // Test 3: Transfer PTR without data - data should persist
    println!("\nTest 3: Transfer PTR without setting new data - data should persist");
    let bob_addr = rig.spaced.client.wallet_get_new_address(BOB, AddressKind::Space).await?;
    let transfer = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            spaces: vec![SpaceOrPtr::Ptr(sptr)],
            to: Some(bob_addr.clone()),
            data: None,
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&transfer).is_ok(), "Transfer PTR should succeed");
    mine_and_sync(rig, 1).await?;

    let ptr_after_transfer = rig.spaced.client.get_ptr(sptr).await?
        .expect("ptr should exist after transfer");
    assert_eq!(ptr_after_transfer.ptrout.sptr.as_ref().unwrap().data, Some(Bytes::new(test_data.clone())),
        "PTR data should persist after transfer without new data");
    println!("✓ PTR data persisted after transfer");

    // Test 4: Update data with new value
    println!("\nTest 4: Update PTR data with new value");
    let new_data = b"Updated data!".to_vec();
    let update_data = wallet_do(
        rig,
        BOB,
        vec![RpcWalletRequest::SetPtrData(SetPtrDataParams {
            sptr,
            data: new_data.clone(),
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&update_data).is_ok(), "SetPtrData should succeed");
    mine_and_sync(rig, 1).await?;

    let ptr_updated = rig.spaced.client.get_ptr(sptr).await?
        .expect("ptr should exist");
    assert_eq!(ptr_updated.ptrout.sptr.as_ref().unwrap().data, Some(Bytes::new(new_data.clone())), "PTR data should be updated");
    println!("✓ PTR data updated successfully: {:?}", String::from_utf8_lossy(&new_data));

    // Test 5: Set empty data
    println!("\nTest 5: Set empty data");
    let empty_data = Vec::new();
    let set_empty = wallet_do(
        rig,
        BOB,
        vec![RpcWalletRequest::SetPtrData(SetPtrDataParams {
            sptr,
            data: empty_data.clone(),
        })],
        false,
    ).await?;
    assert!(wallet_res_err(&set_empty).is_ok(), "SetPtrData with empty data should succeed");
    mine_and_sync(rig, 1).await?;

    let ptr_empty = rig.spaced.client.get_ptr(sptr).await?
        .expect("ptr should exist");
    assert_eq!(ptr_empty.ptrout.sptr.as_ref().unwrap().data, Some(Bytes::new(empty_data)), "PTR data should be set to empty");
    println!("✓ PTR data set to empty successfully");

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

    println!("\n=== Running SPTR Creation Tests ===");
    it_should_create_sptrs(&rig).await?;

    println!("\n=== Running SPTR Uniqueness Tests ===");
    it_should_reject_duplicate_sptr_delegations(&rig).await?;

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

    println!("\n=== All tests passed! ===");
    Ok(())
}

// ============== Test: PTR n→n Transfer Rule ==============

async fn it_should_transfer_ptr_with_n_to_n_rule(rig: &TestRig) -> anyhow::Result<()> {
    sync_all(rig).await?;

    // Test 1: Basic n→n transfer (same value, key rotation)
    println!("Test 1: n→n transfer (same value)");
    {
        // Create a PTR
        let addr0 = rig.spaced.client.wallet_get_new_address(ALICE, AddressKind::Coin).await?;
        let addr0_spk = bitcoin::address::Address::from_str(&addr0)?.assume_checked().script_pubkey();
        let addr0_spk_string = hex::encode(addr0_spk.as_bytes());

        wallet_do(rig, ALICE, vec![
            RpcWalletRequest::CreatePtr(CreatePtrParams { spk: addr0_spk_string })
        ], false).await?;
        mine_and_sync(rig, 1).await?;

        let sptr = Sptr::from_spk::<Sha256>(addr0_spk.clone());
        let ptr_before = rig.spaced.client.get_ptr(sptr).await?.expect("ptr must exist");
        let value_before = ptr_before.ptrout.value;

        // Transfer to addr1 with SAME value (should use n→n rule)
        let addr1 = rig.spaced.client.wallet_get_new_address(BOB, AddressKind::Space).await?;
        wallet_do(rig, ALICE, vec![
            RpcWalletRequest::Transfer(TransferSpacesParams {
                spaces: vec![SpaceOrPtr::Ptr(sptr)],
                to: Some(addr1.clone()),
                data: None,
            })
        ], false).await?;
        mine_and_sync(rig, 1).await?;

        let ptr_after = rig.spaced.client.get_ptr(sptr).await?.expect("ptr must still exist");
        let spk1 = SpaceAddress::from_str(&addr1)?.script_pubkey();

        assert_eq!(ptr_after.ptrout.script_pubkey, spk1, "PTR should transfer to new address");
        assert_eq!(ptr_after.ptrout.value, value_before, "PTR value should remain same (n→n)");
        println!("✓ n→n transfer successful (same value preserved)");
    }

    // Test 2: Multiple PTR transfers in same transaction
    println!("\nTest 2: Multiple PTR transfers in same tx");
    {
        // Create two PTRs
        let addr_a = rig.spaced.client.wallet_get_new_address(ALICE, AddressKind::Coin).await?;
        let addr_b = rig.spaced.client.wallet_get_new_address(ALICE, AddressKind::Coin).await?;
        let spk_a = bitcoin::address::Address::from_str(&addr_a)?.assume_checked().script_pubkey();
        let spk_b = bitcoin::address::Address::from_str(&addr_b)?.assume_checked().script_pubkey();

        wallet_do(rig, ALICE, vec![
            RpcWalletRequest::CreatePtr(CreatePtrParams { spk: hex::encode(spk_a.as_bytes()) }),
            RpcWalletRequest::CreatePtr(CreatePtrParams { spk: hex::encode(spk_b.as_bytes()) }),
        ], false).await?;
        mine_and_sync(rig, 1).await?;

        let sptr_a = Sptr::from_spk::<Sha256>(spk_a.clone());
        let sptr_b = Sptr::from_spk::<Sha256>(spk_b.clone());

        // Transfer both to different addresses
        let dest_a = rig.spaced.client.wallet_get_new_address(BOB, AddressKind::Space).await?;
        let dest_b = rig.spaced.client.wallet_get_new_address(BOB, AddressKind::Space).await?;

        wallet_do(rig, ALICE, vec![
            RpcWalletRequest::Transfer(TransferSpacesParams {
                spaces: vec![SpaceOrPtr::Ptr(sptr_a)],
                to: Some(dest_a.clone()),
                data: None,
            }),
            RpcWalletRequest::Transfer(TransferSpacesParams {
                spaces: vec![SpaceOrPtr::Ptr(sptr_b)],
                to: Some(dest_b.clone()),
                data: None,
            }),
        ], false).await?;
        mine_and_sync(rig, 1).await?;

        let ptr_a_after = rig.spaced.client.get_ptr(sptr_a).await?.expect("ptr_a must exist");
        let ptr_b_after = rig.spaced.client.get_ptr(sptr_b).await?.expect("ptr_b must exist");
        let spk_dest_a = SpaceAddress::from_str(&dest_a)?.script_pubkey();
        let spk_dest_b = SpaceAddress::from_str(&dest_b)?.script_pubkey();

        assert_eq!(ptr_a_after.ptrout.script_pubkey, spk_dest_a, "PTR A should transfer correctly");
        assert_eq!(ptr_b_after.ptrout.script_pubkey, spk_dest_b, "PTR B should transfer correctly");
        println!("✓ Multiple PTR transfers handled correctly");
    }

    // Test 3: Commitment preserves n→n rule (same value)
    println!("\nTest 3: Commitment uses n→n (same value preserved)");
    {
        // Get a space and delegate it
        let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
        let space = alice_spaces.owned.first().expect("Alice should own a space").clone();
        let space_name = space.spaceout.space.as_ref().expect("space").name.clone();

        // Delegate to create PTR
        wallet_do(rig, ALICE, vec![
            RpcWalletRequest::Delegate(DelegateParams { space: space_name.clone() })
        ], false).await?;
        mine_and_sync(rig, 1).await?;

        let sptr = rig.spaced.client.get_delegation(space_name.clone()).await?
            .expect("delegation should exist");
        let ptr_before_commit = rig.spaced.client.get_ptr(sptr).await?.expect("ptr must exist");
        let value_before = ptr_before_commit.ptrout.value;
        let spk_before = ptr_before_commit.ptrout.script_pubkey.clone();

        // Make a commitment (should preserve value via n→n)
        wallet_do(rig, ALICE, vec![
            RpcWalletRequest::Commit(CommitParams {
                space: space_name.clone(),
                root: Some(sha256::Hash::from_slice(&[1u8; 32])?),
            })
        ], false).await?;
        mine_and_sync(rig, 1).await?;

        let ptr_after_commit = rig.spaced.client.get_ptr(sptr).await?.expect("ptr must exist after commit");

        assert_eq!(ptr_after_commit.ptrout.value, value_before, "Commitment should preserve PTR value (n→n)");
        assert_eq!(ptr_after_commit.ptrout.script_pubkey, spk_before, "Commitment should keep same address");

        // Verify commitment was created
        let commitment = rig.spaced.client.get_commitment(space_name.clone(), None).await?
            .expect("commitment should exist");
        assert_eq!(commitment.state_root, [1u8; 32], "Commitment root should match");
        println!("✓ Commitment preserves PTR value and address (n→n rule)");
    }

    Ok(())
}