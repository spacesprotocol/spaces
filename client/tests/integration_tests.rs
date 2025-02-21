use std::{path::PathBuf, str::FromStr};

use spaces_protocol::{
    bitcoin::{Amount, FeeRate},
    constants::RENEWAL_INTERVAL,
    script::SpaceScript,
    Bytes, Covenant,
};
use spaces_client::{
    rpc::{
        BidParams, ExecuteParams, OpenParams, RegisterParams, RpcClient, RpcWalletRequest,
        RpcWalletTxBuilder, TransferSpacesParams,
    },
    wallets::{AddressKind, WalletResponse},
};
use spaces_testutil::TestRig;
use spaces_wallet::{export::WalletExport, tx_event::TxEventKind};

const ALICE: &str = "wallet_99";
const BOB: &str = "wallet_98";
const EVE: &str = "wallet_93";

const TEST_SPACE: &str = "@example123";
const TEST_INITIAL_BID: u64 = 5000;

/// alice opens [TEST_SPACE] for auction
async fn it_should_open_a_space_for_auction(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;
    let response = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Open(OpenParams {
            name: TEST_SPACE.to_string(),
            amount: TEST_INITIAL_BID,
        })],
        false,
    )
    .await
    .expect("send request");

    println!("{}", serde_json::to_string_pretty(&response).unwrap());

    for tx_res in &response.result {
        assert!(tx_res.error.is_none(), "expect no errors for simple open");
    }
    assert_eq!(response.result.len(), 2, "must be 2 transactions");

    rig.mine_blocks(1, None).await?;
    rig.wait_until_synced().await?;

    let fullspaceout = rig.spaced.client.get_space(TEST_SPACE).await?;
    let fullspaceout = fullspaceout.expect("a fullspace out");
    let space = fullspaceout.spaceout.space.expect("a space");

    match space.covenant {
        Covenant::Bid {
            total_burned,
            burn_increment,
            claim_height,
            ..
        } => {
            assert!(claim_height.is_none(), "none for pre-auctions");
            assert_eq!(total_burned, burn_increment, "equal for initial bid");
            assert_eq!(
                total_burned,
                Amount::from_sat(TEST_INITIAL_BID),
                "must be equal to opened bid"
            );
        }
        _ => panic!("expected a bid covenant"),
    }

    Ok(())
}

/// Bob outbids alice by 1 sat
async fn it_should_allow_outbidding(rig: &TestRig) -> anyhow::Result<()> {
    // Bob outbids alice
    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    let bobs_spaces = rig.spaced.client.wallet_list_spaces(BOB).await?;
    let alices_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let alices_balance = rig.spaced.client.wallet_get_balance(ALICE).await?;

    let result = wallet_do(
        rig,
        BOB,
        vec![RpcWalletRequest::Bid(BidParams {
            name: TEST_SPACE.to_string(),
            amount: TEST_INITIAL_BID + 1,
        })],
        false,
    )
    .await
    .expect("send request");

    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    rig.mine_blocks(1, None).await?;

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    let bob_spaces_updated = rig.spaced.client.wallet_list_spaces(BOB).await?;
    let alice_spaces_updated = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let alices_balance_updated = rig.spaced.client.wallet_get_balance(ALICE).await?;

    assert_eq!(
        alices_spaces.winning.len() - 1,
        alice_spaces_updated.winning.len(),
        "alice must have one less space"
    );
    assert_eq!(
        alices_spaces.outbid.len() + 1,
        alice_spaces_updated.outbid.len(),
        "alice must have one less space"
    );
    assert_eq!(
        bobs_spaces.winning.len() + 1,
        bob_spaces_updated.winning.len(),
        "bob must have a new space"
    );
    assert_eq!(
        alices_balance_updated.balance,
        alices_balance.balance + Amount::from_sat(TEST_INITIAL_BID + 662),
        "alice must be refunded this exact amount"
    );

    let fullspaceout = rig.spaced.client.get_space(TEST_SPACE).await?;
    let fullspaceout = fullspaceout.expect("a fullspace out");
    let space = fullspaceout.spaceout.space.expect("a space");

    match space.covenant {
        Covenant::Bid {
            total_burned,
            burn_increment,
            claim_height,
            ..
        } => {
            assert!(claim_height.is_none(), "none for pre-auctions");
            assert_eq!(
                total_burned,
                Amount::from_sat(TEST_INITIAL_BID + 1),
                "total burned"
            );
            assert_eq!(
                burn_increment,
                Amount::from_sat(1),
                "burn increment only 1 sat"
            );
        }
        _ => panic!("expected a bid covenant"),
    }

    Ok(())
}

async fn it_should_insert_txout_for_bids(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(BOB).await?;

    let tx = rig
        .spaced
        .client
        .wallet_list_transactions(BOB, 10, 0)
        .await?
        .iter()
        .filter(|tx| tx.events.iter().any(|event| event.kind == TxEventKind::Bid))
        .next()
        .expect("a bid")
        .clone();

    assert!(tx.fee.is_some(), "must be able to calculate fees");
    Ok(())
}

/// Eve makes an invalid bid with a burn increment of 0 only refunding Bob's money
async fn it_should_only_accept_forced_zero_value_bid_increments_and_revoke(
    rig: &TestRig,
) -> anyhow::Result<()> {
    // Bob outbids alice
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_wallet_synced(EVE).await?;
    let eve_spaces = rig.spaced.client.wallet_list_spaces(EVE).await?;
    let bob_spaces = rig.spaced.client.wallet_list_spaces(BOB).await?;
    let bob_balance = rig.spaced.client.wallet_get_balance(BOB).await?;

    let fullspaceout = rig
        .spaced
        .client
        .get_space(TEST_SPACE)
        .await?
        .expect("exists");
    let space = fullspaceout.spaceout.space.expect("a space");
    let last_bid = match space.covenant {
        Covenant::Bid { total_burned, .. } => total_burned,
        _ => panic!("expected a bid"),
    };

    assert!(
        wallet_do(
            rig,
            EVE,
            vec![RpcWalletRequest::Bid(BidParams {
                name: TEST_SPACE.to_string(),
                amount: last_bid.to_sat(),
            }),],
            false
        )
        .await
        .is_err(),
        "shouldn't be able to bid with same value unless forced"
    );

    // force only
    assert!(
        rig.spaced
            .client
            .wallet_send_request(
                EVE,
                RpcWalletTxBuilder {
                    bidouts: None,
                    requests: vec![RpcWalletRequest::Bid(BidParams {
                        name: TEST_SPACE.to_string(),
                        amount: last_bid.to_sat(),
                    }),],
                    fee_rate: Some(FeeRate::from_sat_per_vb(1).expect("fee")),
                    dust: None,
                    force: true,
                    confirmed_only: false,
                    skip_tx_check: false,
                },
            )
            .await
            .is_err(),
        "should require skip tx check"
    );

    // force & skip tx check
    let result = rig
        .spaced
        .client
        .wallet_send_request(
            EVE,
            RpcWalletTxBuilder {
                bidouts: None,
                requests: vec![RpcWalletRequest::Bid(BidParams {
                    name: TEST_SPACE.to_string(),
                    amount: last_bid.to_sat(),
                })],
                fee_rate: Some(FeeRate::from_sat_per_vb(1).expect("fee")),
                dust: None,
                force: true,
                confirmed_only: false,
                skip_tx_check: true,
            },
        )
        .await?;

    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    rig.mine_blocks(1, None).await?;

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    let bob_spaces_updated = rig.spaced.client.wallet_list_spaces(BOB).await?;
    let bob_balance_updated = rig.spaced.client.wallet_get_balance(BOB).await?;
    let eve_spaces_updated = rig.spaced.client.wallet_list_spaces(EVE).await?;

    assert_eq!(
        bob_spaces.winning.len() - 1,
        bob_spaces_updated.winning.len(),
        "bob must have one less space"
    );
    assert_eq!(
        bob_balance_updated.balance,
        bob_balance.balance + Amount::from_sat(last_bid.to_sat() + 662),
        "alice must be refunded this exact amount"
    );
    assert_eq!(
        eve_spaces_updated.winning.len(),
        eve_spaces.winning.len(),
        "eve must have the same number of spaces"
    );

    let fullspaceout = rig.spaced.client.get_space(TEST_SPACE).await?;
    assert!(fullspaceout.is_none(), "must be revoked");
    Ok(())
}

async fn it_should_allow_claim_on_or_after_claim_height(rig: &TestRig) -> anyhow::Result<()> {
    let wallet = EVE;
    let claimable_space = "@test9880";
    let space = rig
        .spaced
        .client
        .get_space(claimable_space)
        .await?
        .expect(claimable_space);
    let space = space.spaceout.space.expect(claimable_space);

    let current_height = rig.get_block_count().await?;
    let claim_height = space.claim_height().expect("height") as u64;
    rig.mine_blocks((claim_height - current_height) as _, None)
        .await?;

    assert_eq!(
        claim_height,
        rig.get_block_count().await?,
        "heights must match"
    );

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(wallet).await?;
    let all_spaces = rig.spaced.client.wallet_list_spaces(wallet).await?;

    let result = wallet_do(
        rig,
        wallet,
        vec![RpcWalletRequest::Register(RegisterParams {
            name: claimable_space.to_string(),
            to: None,
        })],
        false,
    )
    .await
    .expect("send request");

    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    rig.mine_blocks(1, None).await?;

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(wallet).await?;
    let all_spaces_2 = rig.spaced.client.wallet_list_spaces(wallet).await?;

    assert_eq!(
        all_spaces.owned.len() + 1,
        all_spaces_2.owned.len(),
        "must be equal"
    );

    let space = rig
        .spaced
        .client
        .get_space(claimable_space)
        .await?
        .expect(claimable_space);
    let space = space.spaceout.space.expect(claimable_space);

    match space.covenant {
        Covenant::Transfer { .. } => {}
        _ => panic!("covenant is not transfer"),
    }
    Ok(())
}

async fn it_should_allow_batch_transfers_refreshing_expire_height(
    rig: &TestRig,
) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;
    rig.wait_until_synced().await?;
    let all_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let registered_spaces: Vec<_> = all_spaces
        .owned
        .iter()
        .map(|out| out.spaceout.space.as_ref().expect("space").name.to_string())
        .collect();

    let space_address = rig
        .spaced
        .client
        .wallet_get_new_address(ALICE, AddressKind::Space)
        .await?;

    let result = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            spaces: registered_spaces.clone(),
            to: Some(space_address),
        })],
        false,
    )
    .await
    .expect("send request");

    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    rig.mine_blocks(1, None).await?;
    let expected_expire_height = rig.get_block_count().await? as u32 + RENEWAL_INTERVAL;

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    let all_spaces_2 = rig.spaced.client.wallet_list_spaces(ALICE).await?;

    assert_eq!(
        all_spaces.owned.len(),
        all_spaces_2.owned.len(),
        "must be equal"
    );

    let _ = all_spaces_2.owned.iter().for_each(|s| {
        let space = s.spaceout.space.as_ref().expect("space");
        match space.covenant {
            Covenant::Transfer { expire_height, .. } => {
                assert_eq!(
                    expire_height, expected_expire_height,
                    "must refresh expire height"
                );
            }
            _ => {}
        }
    });

    assert_eq!(
        all_spaces.winning.len(),
        all_spaces_2.winning.len(),
        "shouldn't change number of held spaces"
    );

    Ok(())
}

async fn it_should_allow_applying_script_in_batch(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;
    rig.wait_until_synced().await?;
    let all_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let registered_spaces: Vec<_> = all_spaces
        .owned
        .iter()
        .map(|out| out.spaceout.space.as_ref().expect("space").name.to_string())
        .collect();

    let result = wallet_do(
        rig,
        ALICE,
        vec![
            // TODO: transfer then execute causes stack to be outdated
            // RpcWalletRequest::Transfer(TransferSpacesParams {
            //     spaces: registered_spaces.clone(),
            //     to: addr,
            // }),
            RpcWalletRequest::Execute(ExecuteParams {
                context: registered_spaces.clone(),
                space_script: SpaceScript::create_set_fallback(&[0xDE, 0xAD, 0xBE, 0xEF]),
            }),
        ],
        false,
    )
    .await
    .expect("send request");

    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    rig.mine_blocks(1, None).await?;
    let expected_expire_height = rig.get_block_count().await? as u32 + RENEWAL_INTERVAL;

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    let all_spaces_2 = rig.spaced.client.wallet_list_spaces(ALICE).await?;

    assert_eq!(
        all_spaces.owned.len(),
        all_spaces_2.owned.len(),
        "must be equal"
    );
    assert_eq!(
        all_spaces.winning.len(),
        all_spaces_2.winning.len(),
        "must be equal"
    );

    all_spaces_2.owned.iter().for_each(|s| {
        let space = s.spaceout.space.as_ref().expect("space");
        match &space.covenant {
            Covenant::Transfer {
                expire_height,
                data,
            } => {
                assert_eq!(
                    *expire_height, expected_expire_height,
                    "must refresh expire height"
                );
                assert!(data.is_some(), "must be data set");
                assert_eq!(
                    data.clone().unwrap().to_vec(),
                    vec![0xDE, 0xAD, 0xBE, 0xEF],
                    "must set correct data"
                );
            }
            _ => {}
        }
    });
    Ok(())
}

// Alice places an unconfirmed bid on @test2.
// Bob attempts to replace it but fails due to a lack of confirmed bid & funding utxos.
// Eve, with confirmed bid outputs/funds, successfully replaces the bid.
async fn it_should_replace_mempool_bids(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_wallet_synced(EVE).await?;

    // make sure Bob runs out of confirmed bidouts
    let bob_bidout_count = rig
        .spaced
        .client
        .wallet_list_bidouts(BOB)
        .await
        .expect("get bidouts")
        .len();
    for i in 0..bob_bidout_count {
        wallet_do(
            rig,
            BOB,
            vec![RpcWalletRequest::Bid(BidParams {
                name: format!("@test{}", i + 100),
                amount: 200,
            })],
            false,
        )
        .await
        .expect("bob makes a bid");
    }

    // create some confirmed bid outs for Alice and Eve
    rig.spaced
        .client
        .wallet_send_request(
            EVE,
            RpcWalletTxBuilder {
                bidouts: Some(2),
                requests: vec![],
                fee_rate: Some(FeeRate::from_sat_per_vb(2).expect("fee")),
                dust: None,
                force: false,
                confirmed_only: false,
                skip_tx_check: false,
            },
        )
        .await
        .expect("send request");
    rig.spaced
        .client
        .wallet_send_request(
            ALICE,
            RpcWalletTxBuilder {
                bidouts: Some(2),
                requests: vec![],
                fee_rate: Some(FeeRate::from_sat_per_vb(2).expect("fee")),
                dust: None,
                force: false,
                confirmed_only: false,
                skip_tx_check: false,
            },
        )
        .await
        .expect("send request");
    rig.mine_blocks(1, None).await?;

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_wallet_synced(EVE).await?;

    let response = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Bid(BidParams {
            name: "@test2".to_string(),
            amount: 1000,
        })],
        false,
    )
    .await
    .expect("send request");

    let response = serde_json::to_string_pretty(&response).unwrap();
    println!("Alice bid on @test2 (unconf): {}", response);

    rig.wait_until_wallet_synced(BOB).await?;
    let response = wallet_do(
        rig,
        BOB,
        vec![RpcWalletRequest::Bid(BidParams {
            name: "@test2".to_string(),
            amount: 1000,
        })],
        false,
    )
    .await
    .expect("send request");

    let response = serde_json::to_string_pretty(&response).unwrap();

    println!("Bob bid on @test (unconf) {}", response);

    assert!(
        response.contains("hint"),
        "should have a hint about replacement errors"
    );

    let replacement = rig
        .spaced
        .client
        .wallet_send_request(
            BOB,
            RpcWalletTxBuilder {
                bidouts: None,
                requests: vec![RpcWalletRequest::Bid(BidParams {
                    name: "@test2".to_string(),
                    amount: 1000,
                })],
                fee_rate: Some(FeeRate::from_sat_per_vb(2).expect("fee")),
                dust: None,
                force: false,
                confirmed_only: false,
                skip_tx_check: false,
            },
        )
        .await
        .expect("send request");

    let response = serde_json::to_string_pretty(&replacement).unwrap();
    println!("{}", response);

    assert!(
        response.contains("hint"),
        "should have a hint about confirmed only"
    );
    assert!(
        response.contains("replacement-adds-unconfirmed"),
        "expected a replacement-adds-unconfirmed in the message"
    );

    // now let Eve try a replacement since she has confirmed outputs
    let replacement = rig
        .spaced
        .client
        .wallet_send_request(
            EVE,
            RpcWalletTxBuilder {
                bidouts: None,
                requests: vec![RpcWalletRequest::Bid(BidParams {
                    name: "@test2".to_string(),
                    amount: 1000,
                })],
                fee_rate: Some(FeeRate::from_sat_per_vb(2).expect("fee")),
                dust: None,
                force: false,
                confirmed_only: false,
                skip_tx_check: false,
            },
        )
        .await
        .expect("send request");

    let eve_replacement_txid = replacement
        .result
        .iter()
        .filter_map(|tx| {
            if tx.events.iter().any(|event| event.kind == TxEventKind::Bid) {
                Some(tx.txid)
            } else {
                None
            }
        })
        .next()
        .expect("should have eve replacement txid");

    let response = serde_json::to_string_pretty(&replacement).unwrap();
    println!("Eve's replacement: {}", response);

    for tx_res in replacement.result {
        assert!(
            tx_res.error.is_none(),
            "Eve should have no problem replacing"
        )
    }

    // Wait until wallet checks mempool
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    // Wallet must undo double spent tx.
    let txs = rig
        .spaced
        .client
        .wallet_list_transactions(ALICE, 1000, 0)
        .await
        .expect("list transactions");
    let unconfirmed: Vec<_> = txs.iter().filter(|tx| !tx.confirmed).collect();
    for tx in &unconfirmed {
        println!("Alice's unconfiremd: {}", tx.txid);
    }
    assert_eq!(
        unconfirmed.len(),
        0,
        "there should be no stuck unconfirmed transactions"
    );

    // Now Eve's tx is confirmed. Alice wallet must filter it out as irrelevant
    rig.mine_blocks(1, None).await?;
    rig.wait_until_wallet_synced(ALICE).await?;

    let txs = rig
        .spaced
        .client
        .wallet_list_transactions(ALICE, 1000, 0)
        .await
        .expect("list transactions");

    assert!(
        txs.iter().all(|tx| tx.txid != eve_replacement_txid),
        "Eve's tx shouldn't be listed in Alice's wallet"
    );

    rig.wait_until_wallet_synced(EVE).await?;
    let eve_txs = rig
        .spaced
        .client
        .wallet_list_transactions(EVE, 1000, 0)
        .await
        .expect("list transactions");

    assert!(
        eve_txs
            .iter()
            .any(|tx| tx.txid == eve_replacement_txid && tx.confirmed),
        "Eve's tx should be confirmed"
    );

    let space = rig
        .spaced
        .client
        .get_space("@test2")
        .await
        .expect("space")
        .expect("space exists");

    println!("Space: {}", serde_json::to_string_pretty(&space).unwrap());
    Ok(())
}

async fn it_should_maintain_locktime_when_fee_bumping(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;

    let response = rig
        .spaced
        .client
        .wallet_send_request(
            ALICE,
            RpcWalletTxBuilder {
                bidouts: Some(2),
                requests: vec![],
                fee_rate: Some(FeeRate::from_sat_per_vb(1).expect("fee")),
                dust: None,
                force: false,
                confirmed_only: false,
                skip_tx_check: false,
            },
        )
        .await?;

    println!(
        "bumping fee: {}",
        serde_json::to_string_pretty(&response).unwrap()
    );

    let txid = response.result[0].txid;
    for tx_res in response.result {
        assert!(tx_res.error.is_none(), "should not be error");
    }

    let tx = rig.get_raw_transaction(&txid).await?;

    let bump = rig
        .spaced
        .client
        .wallet_bump_fee(
            ALICE,
            txid,
            FeeRate::from_sat_per_vb(4).expect("fee"),
            false,
        )
        .await?;

    println!(
        "after fee bump: {}",
        serde_json::to_string_pretty(&bump).unwrap()
    );
    assert_eq!(bump.len(), 1, "should only be 1 tx");
    assert!(bump[0].error.is_none(), "should be no errors");

    let replacement = rig.get_raw_transaction(&bump[0].txid).await?;

    assert_eq!(
        tx.lock_time, replacement.lock_time,
        "locktimes must not change"
    );
    Ok(())
}

async fn it_should_not_allow_register_or_transfer_to_same_space_multiple_times(
    rig: &TestRig,
) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(BOB).await.expect("synced");
    rig.wait_until_wallet_synced(ALICE).await.expect("synced");

    // known from data set
    let awaiting_claim = "@test9962".to_string();
    let response = wallet_do(
        rig,
        BOB,
        vec![RpcWalletRequest::Register(RegisterParams {
            name: awaiting_claim.clone(),
            to: None,
        })],
        false,
    )
    .await
    .expect("send request");

    println!("{}", serde_json::to_string_pretty(&response).unwrap());
    assert!(
        wallet_do(
            rig,
            BOB,
            vec![RpcWalletRequest::Register(RegisterParams {
                name: awaiting_claim.clone(),
                to: None,
            })],
            false,
        )
        .await
        .is_err(),
        "should not allow register to same space multiple times"
    );

    // Try transfer multiple times
    let bob_address = rig
        .spaced
        .client
        .wallet_get_new_address(BOB, AddressKind::Space)
        .await?;

    let transfer = "@test9995".to_string();
    let response = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            spaces: vec![transfer.clone()],
            to: Some(bob_address.clone()),
        })],
        false,
    )
    .await
    .expect("send request");

    println!(
        "Transfer {}: {}",
        transfer,
        serde_json::to_string_pretty(&response).unwrap()
    );
    wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            spaces: vec![transfer],
            to: Some(bob_address),
        })],
        false,
    )
    .await
    .expect_err("there's already a transfer submitted");

    let setdata = "@test9996".to_string();
    let response = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Execute(ExecuteParams {
            context: vec![setdata.clone()],
            space_script: SpaceScript::create_set_fallback(&[0xAA, 0xAA]),
        })],
        false,
    )
    .await
    .expect("send request");

    println!(
        "Update sent {}",
        serde_json::to_string_pretty(&response).unwrap()
    );
    wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Execute(ExecuteParams {
            context: vec![setdata],
            space_script: SpaceScript::create_set_fallback(&[0xDE, 0xAD]),
        })],
        false,
    )
    .await
    .expect_err("there's already an update submitted");

    rig.mine_blocks(1, None).await.expect("mine");
    rig.wait_until_synced().await.expect("synced");

    let space = rig
        .spaced
        .client
        .get_space("@test9996")
        .await
        .expect("space")
        .expect("spaceout exists")
        .spaceout
        .space
        .expect("space exists");

    match space.covenant {
        Covenant::Transfer { data, .. } => {
            assert!(data.is_some(), "data must be set");
            assert_eq!(
                data.unwrap().as_slice(),
                [0xAAu8, 0xAA].as_slice(),
                "data not correct"
            );
        }
        _ => panic!("expected transfer covenant"),
    }
    Ok(())
}

async fn it_can_batch_txs(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await.expect("synced");
    let bob_address = rig
        .spaced
        .client
        .wallet_get_new_address(BOB, AddressKind::Space)
        .await?;
    let res = wallet_do(
        rig,
        ALICE,
        vec![
            RpcWalletRequest::Transfer(TransferSpacesParams {
                spaces: vec!["@test9996".to_string()],
                to: Some(bob_address),
            }),
            RpcWalletRequest::Bid(BidParams {
                name: "@test100".to_string(),
                amount: 201,
            }),
            RpcWalletRequest::Open(OpenParams {
                name: "@batch2".to_string(),
                amount: 1000,
            }),
            RpcWalletRequest::Open(OpenParams {
                name: "@batch1".to_string(),
                amount: 1000,
            }),
            RpcWalletRequest::Execute(ExecuteParams {
                context: vec![
                    "@test10000".to_string(),
                    "@test9999".to_string(),
                    "@test9998".to_string(),
                ],
                // space_script: SpaceScript::create_set_fallback(&[0xEE, 0xEE, 0x22, 0x22]),
                space_script: SpaceScript::create_set_fallback(&[0xEE, 0xEE, 0x22, 0x22]),
            }),
        ],
        false,
    )
    .await
    .expect("send request");

    println!(
        "batch request: {}",
        serde_json::to_string_pretty(&res).unwrap()
    );
    assert!(
        res.result.iter().all(|tx| tx.error.is_none()),
        "batching should work"
    );
    assert_eq!(res.result.len(), 5, "expected 4 transactions");

    rig.mine_blocks(1, None).await.expect("mine");
    rig.wait_until_wallet_synced(ALICE).await.expect("synced");
    rig.wait_until_wallet_synced(BOB).await.expect("synced");

    let bob_spaces = rig
        .spaced
        .client
        .wallet_list_spaces(BOB)
        .await
        .expect("bob spaces");
    assert!(
        bob_spaces
            .owned
            .iter()
            .find(|output| output
                .spaceout
                .space
                .as_ref()
                .is_some_and(|s| s.name.to_string() == "@test9996"))
            .is_some(),
        "expected bob to own the space name"
    );

    let alice_spaces = rig
        .spaced
        .client
        .wallet_list_spaces(ALICE)
        .await
        .expect("alice spaces");
    let batch1 = alice_spaces
        .winning
        .iter()
        .find(|output| {
            output
                .spaceout
                .space
                .as_ref()
                .is_some_and(|s| s.name.to_string() == "@batch1")
        })
        .expect("exists")
        .spaceout
        .space
        .clone()
        .expect("space exists");

    match batch1.covenant {
        Covenant::Bid { total_burned, .. } => {
            assert_eq!(total_burned.to_sat(), 1000, "incorrect burn value")
        }
        _ => panic!("must be a bid"),
    }
    let batch2 = alice_spaces
        .winning
        .iter()
        .find(|output| {
            output
                .spaceout
                .space
                .as_ref()
                .is_some_and(|s| s.name.to_string() == "@batch2")
        })
        .expect("exists")
        .spaceout
        .space
        .clone()
        .expect("space exists");
    match batch2.covenant {
        Covenant::Bid { total_burned, .. } => {
            assert_eq!(total_burned.to_sat(), 1000, "incorrect burn value")
        }
        _ => panic!("must be a bid"),
    }

    for space in vec![
        "@test10000".to_string(),
        "@test9999".to_string(),
        "@test9998".to_string(),
    ] {
        let space = alice_spaces
            .owned
            .iter()
            .find(|output| {
                output
                    .spaceout
                    .space
                    .as_ref()
                    .is_some_and(|s| s.name.to_string() == space)
            })
            .expect("exists")
            .spaceout
            .space
            .clone()
            .expect("space exists");

        match space.covenant {
            Covenant::Transfer { data, .. } => {
                assert_eq!(
                    data.clone().unwrap().to_vec(),
                    vec![0xEE, 0xEE, 0x22, 0x22],
                    "must set correct data"
                );
            }
            _ => panic!("must be a transfer"),
        }
    }

    Ok(())
}

async fn it_can_use_reserved_op_codes(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await.expect("synced");
    let alice_spaces = vec![
        "@test10000".to_string(),
        "@test9999".to_string(),
        "@test9998".to_string(),
    ];

    let res = rig
        .spaced
        .client
        .wallet_send_request(
            ALICE,
            RpcWalletTxBuilder {
                bidouts: None,
                requests: vec![RpcWalletRequest::Execute(ExecuteParams {
                    context: alice_spaces.clone(),
                    space_script: SpaceScript::create_reserve(),
                })],
                fee_rate: Some(FeeRate::from_sat_per_vb(1).expect("fee")),
                dust: None,
                force: true,
                confirmed_only: false,
                skip_tx_check: true,
            },
        )
        .await
        .expect("response");

    assert!(
        res.result.iter().all(|tx| tx.error.is_none()),
        "reserve should work"
    );
    assert_eq!(res.result.len(), 2, "expected 2 transactions");

    rig.mine_blocks(1, None).await.expect("mine");
    rig.wait_until_wallet_synced(ALICE).await.expect("synced");

    for space in alice_spaces {
        let space = rig
            .spaced
            .client
            .get_space(&space)
            .await
            .expect("space")
            .expect("space exists")
            .spaceout
            .space
            .expect("space exists");

        assert!(
            matches!(space.covenant, Covenant::Reserved),
            "expected a reserved space"
        );
    }

    Ok(())
}

async fn it_should_allow_buy_sell(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await.expect("synced");
    rig.wait_until_wallet_synced(BOB).await.expect("synced");

    let alice_spaces = rig
        .spaced
        .client
        .wallet_list_spaces(ALICE)
        .await
        .expect("alice spaces");
    let space = alice_spaces
        .owned
        .first()
        .expect("alice should have at least 1 space");

    let space_name = space.spaceout.space.as_ref().unwrap().name.to_string();
    let listing = rig
        .spaced
        .client
        .wallet_sell(ALICE, space_name.clone(), 5000)
        .await
        .expect("sell");

    println!(
        "listing\n{}",
        serde_json::to_string_pretty(&listing).unwrap()
    );

    rig.spaced
        .client
        .verify_listing(listing.clone())
        .await
        .expect("verify");

    let alice_balance = rig
        .spaced
        .client
        .wallet_get_balance(ALICE)
        .await
        .expect("balance");
    let buy = rig
        .spaced
        .client
        .wallet_buy(
            BOB,
            listing.clone(),
            Some(FeeRate::from_sat_per_vb(1).expect("rate")),
            false,
        )
        .await
        .expect("buy");

    println!("{}", serde_json::to_string_pretty(&buy).unwrap());

    rig.mine_blocks(1, None).await.expect("mine");
    rig.wait_until_synced().await.expect("synced");
    rig.wait_until_wallet_synced(BOB).await.expect("synced");
    rig.wait_until_wallet_synced(ALICE).await.expect("synced");

    rig.spaced
        .client
        .verify_listing(listing)
        .await
        .expect_err("should no longer be valid");

    let bob_spaces = rig
        .spaced
        .client
        .wallet_list_spaces(BOB)
        .await
        .expect("bob spaces");

    assert!(
        bob_spaces
            .owned
            .iter()
            .find(|s| s.spaceout.space.as_ref().unwrap().name.to_string() == space_name)
            .is_some(),
        "bob should own it now"
    );

    let alice_balance_after = rig
        .spaced
        .client
        .wallet_get_balance(ALICE)
        .await
        .expect("balance");
    assert_eq!(
        alice_balance.balance + Amount::from_sat(5666),
        alice_balance_after.balance
    );

    Ok(())
}

async fn it_should_allow_sign_verify_messages(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(BOB).await.expect("synced");

    let alice_spaces = rig
        .spaced
        .client
        .wallet_list_spaces(BOB)
        .await
        .expect("bob spaces");
    let space = alice_spaces
        .owned
        .first()
        .expect("bob should have at least 1 space");

    let space_name = space.spaceout.space.as_ref().unwrap().name.to_string();

    let msg = Bytes::new(b"hello world".to_vec());
    let signed = rig
        .spaced
        .client
        .wallet_sign_message(BOB, &space_name, msg.clone())
        .await
        .expect("sign");

    println!("signed\n{}", serde_json::to_string_pretty(&signed).unwrap());
    assert_eq!(signed.space, space_name, "bad signer");
    assert_eq!(
        signed.message.as_slice(),
        msg.as_slice(),
        "msg content must match"
    );

    rig.spaced
        .client
        .verify_message(signed.clone())
        .await
        .expect("verify");

    let mut bad_signer = signed.clone();
    bad_signer.space = "@nothanks".to_string();
    rig.spaced
        .client
        .verify_message(bad_signer)
        .await
        .expect_err("bad signer");

    let mut bad_msg = signed.clone();
    bad_msg.message = Bytes::new(b"hello world 2".to_vec());
    rig.spaced
        .client
        .verify_message(bad_msg)
        .await
        .expect_err("bad msg");

    Ok(())
}

async fn it_should_handle_reorgs(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await.expect("synced");
    const NAME: &str = "hello_world";
    rig.spaced.client.wallet_create(NAME).await.expect("wallet");
    rig.mine_blocks(2, None).await.expect("mine blocks");
    rig.wait_until_wallet_synced(NAME).await.expect("synced");

    // reorg 20 blocks
    rig.reorg(20).await.expect("reorg");
    rig.wait_until_wallet_synced(NAME).await.expect("synced");

    rig.wait_until_wallet_synced(ALICE).await.expect("synced");
    Ok(())
}

#[tokio::test]
async fn run_auction_tests() -> anyhow::Result<()> {
    let rig = TestRig::new_with_regtest_preset().await?;
    let wallets_path = rig.testdata_wallets_path().await;

    let count = rig.get_block_count().await? as u32;
    assert!(count > 3000, "expected an initialized test set");

    rig.wait_until_synced().await?;
    load_wallet(&rig, wallets_path.clone(), ALICE).await?;
    load_wallet(&rig, wallets_path.clone(), BOB).await?;
    load_wallet(&rig, wallets_path, EVE).await?;

    it_should_open_a_space_for_auction(&rig)
        .await
        .expect("should open auction");
    it_should_allow_outbidding(&rig)
        .await
        .expect("should allow outbidding");
    it_should_insert_txout_for_bids(&rig)
        .await
        .expect("should insert txout");
    it_should_only_accept_forced_zero_value_bid_increments_and_revoke(&rig)
        .await
        .expect("should only revoke a bid");
    it_should_allow_claim_on_or_after_claim_height(&rig)
        .await
        .expect("should allow claim on or above height");
    it_should_allow_batch_transfers_refreshing_expire_height(&rig)
        .await
        .expect("should allow batch transfers refresh expire height");
    it_should_allow_applying_script_in_batch(&rig)
        .await
        .expect("should allow batch applying script");
    it_should_replace_mempool_bids(&rig)
        .await
        .expect("should replace mempool bids");
    it_should_maintain_locktime_when_fee_bumping(&rig)
        .await
        .expect("should maintain locktime");
    it_should_not_allow_register_or_transfer_to_same_space_multiple_times(&rig)
        .await
        .expect("should not allow register/transfer multiple times");
    it_can_batch_txs(&rig).await.expect("bump fee");
    it_can_use_reserved_op_codes(&rig)
        .await
        .expect("should use reserved opcodes");
    it_should_allow_buy_sell(&rig)
        .await
        .expect("should allow buy sell");
    it_should_allow_sign_verify_messages(&rig)
        .await
        .expect("should sign verify");

    // keep reorgs last as it can drop some txs from mempool and mess up wallet state
    it_should_handle_reorgs(&rig)
        .await
        .expect("should handle reorgs wallet");
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

pub async fn load_wallet(rig: &TestRig, wallets_dir: PathBuf, name: &str) -> anyhow::Result<()> {
    let wallet_path = wallets_dir.join(format!("{name}.json"));
    let json = std::fs::read_to_string(wallet_path)?;
    let export = WalletExport::from_str(&json)?;
    rig.spaced.client.wallet_import(export).await?;
    Ok(())
}
