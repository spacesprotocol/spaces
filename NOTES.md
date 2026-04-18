// Run Bitcoind Testnet4 on Zilla using Cookie Auth + RPCAuth
/opt/homebrew/opt/bitcoin/bin/bitcoind -testnet4 -rest -rpcbind=0.0.0.0 -rpcport=48332 -rpcallowip=192.168.1.0/24 -rpccookiefile=/Users/i830671/.bitcoin/.cookie  -rpcauth='iroxnnkko:3c7943866d485df3c6491dcf93c4b578$91b4f4e3008e7d370c8ed045545c80f1c215346b359ee44a253fdc4627fdf177'

echo "// Configure spaced for mainnet on Zilla using spaced-horologger data"
export PS1='spaces:\w$ '
export SPACED_BITCOIN_RPC_URL=http://192.168.1.84:8332
export SPACED_BITCOIN_RPC_USER=bearerasset
export SPACED_BITCOIN_RPC_PASSWORD=nocounterpartyrisk
export SPACED_BLOCK_INDEX=false
export SPACED_CHAIN=mainnet
# export SPACED_DATA_DIR='/Users/i830671/Library/Application Support/akron/spaces'
export SPACED_DATA_DIR='../spaced-horologger/data'
export SPACED_RPC_BIND=127.0.0.1
export SPACED_RPC_PORT=7225
export SPACED_RPC_URL=http://127.0.0.1:7225
export SPACED_RPC_USER=admin
export SPACED_RPC_PASSWORD=admin
export SPACES_STARTING_BLOCKHEIGHT=871220

export RPC_URL=http://127.0.0.1:7225
export RPC_USER=admin
export RPC_PASSWORD=admin

alias spaces='target/debug/space-cli -w go '

export SPACED_BITCOIN_RPC_URL=http://70.251.209.207:48332

echo "// Configure spaced for testnet4 on ragnar from Zilla"
export PS1='spaces:\w$ '
export PATH="$HOME/.cargo/bin:$PATH"
export SPACED_BITCOIN_RPC_URL=http://192.168.1.84:48332
export SPACED_BITCOIN_RPC_USER=bearerasset
export SPACED_BITCOIN_RPC_PASSWORD=nocounterpartyrisk
export SPACED_BLOCK_INDEX=true
export SPACED_CHAIN=testnet4
export SPACED_DATA_DIR=../spaced-horologger/data
export SPACED_RPC_BIND=127.0.0.1
export SPACED_RPC_PORT=7224
export SPACED_RPC_URL=http://127.0.0.1:7224
export SPACES_STARTING_BLOCKHEIGHT=41000

export SPACED_RPC_USER=testuser
export SPACED_RPC_PASSWORD=SomeRisk84

alias spaces='target/debug/space-cli -w old --chain=testnet4 --rpc-url=http://127.0.0.1:7224 '

export SPACED_BITCOIN_RPC_URL=http://192.168.1.84:48332

#export SPACED_BITCOIN_RPC_URL=http://192.168.1.84:48332
#export SPACED_BITCOIN_RPC_USER=bearerasset
#export SPACED_BITCOIN_RPC_PASSWORD=nocounterpartyrisk

// Run TestNet4 locally
/opt/homebrew/opt/bitcoin/bin/bitcoind -testnet4 -rest -rpcbind=0.0.0.0 -rpcport=48332 -rpcallowip=192.168.1.0/24 -rpcuser=iroxnnkko -rpcpassword=p3T9xW9u3WSxvV3oJdV



// This is the ONE! This is it! 
echo "// Configure spaced for testnet4 on ragnar from Zilla"
export PS1='spaces:\w$ '
export PATH="$HOME/.cargo/bin:$PATH"
export SPACED_BITCOIN_RPC_URL=http://70.251.209.207:48332
export SPACED_BITCOIN_RPC_URL=http://127.0.0.1:48332
export SPACED_BITCOIN_RPC_COOKIE=/Users/i830671/.bitcoin/.cookie
export SPACED_BLOCK_INDEX=true
export SPACED_CHAIN=testnet4
export SPACED_DATA_DIR=../spaced-horologger/data
export SPACED_DATA_DIR=./data
export SPACED_RPC_BIND=127.0.0.1
export SPACED_RPC_PORT=7224
export SPACED_RPC_URL=http://127.0.0.1:7224
export SPACES_STARTING_BLOCKHEIGHT=41000

export SPACED_RPC_USER=testuser
export SPACED_RPC_PASSWORD=SomeRisk84

alias spaces='target/debug/space-cli -w old --chain=testnet4 --rpc-url=http://127.0.0.1:7224 --rpc-user=testuser --rpc-password=SomeRisk84 '

alias spacesd='target/debug/space-cli -w default --chain=testnet4 --rpc-url=http://127.0.0.1:7224 --rpc-user=testuser --rpc-password=SomeRisk84 '

echo "spaced does not like VPN"

alias spaced='target/debug/spaced '

export SPACED_BITCOIN_RPC_USER=iroxnnkko
export SPACED_BITCOIN_RPC_PASSWORD=p3T9xW9u3WSxvV3oJdV
unset SPACED_BITCOIN_RPC_COOKIE

// End of this is it!

spaces:~/git/spaced-subspaces$ spaces operate @space
Assigning space to sptr sptr1az4txmr6qp9qyp6m5rtg4vu6rx8z5l3f8wstf96kht9teyh4tz3qjfakjh
⚠️ could not estimate fee rate
What does this actually do?

spaces -f 10 operate @space

$ spaces commit --root 9278d49cca2e2c430a6503b6a72a13c3fd51f0b5b769e03c3a01ebe2d80268b4 @space

9278d49cca2e2c430a6503b6a72a13c3fd51f0b5b769e03c3a01ebe2d80268b4


spaces:~/git/spaced-subspaces$ spaces getspace @space
{
  "txid": "476c1aa6d3a92ec70d2e0fef8575eab74538e1cbb344a94bc4c2abaca62b02a1",
  "n": 1,
  "name": "@space",
  "covenant": {
    "type": "transfer",
    "expire_height": 157576,
    "data": null
  },
  "value": 666,
  "script_pubkey": "51207af118ac81145433ea08f7192b6f69466c73476d14fcae7530e8c5df0b813808"
}

spaces:~/git/spaced-subspaces$ spaces createptr 51207af118ac81145433ea08f7192b6f69466c73476d14fcae7530e8c5df0b813808 10
Creating sptr: sptr1yehmfzsu2rr7tsxd5d5ehflgmvww9twqflq2x5es8na728jtx66sfqlk06
✓ Transaction c4f8d61b226c2f0b79f7a5d14701fa5504217bf64868297ad0e744ca821d53e3




spaces:~/git/spaced-subspaces$ spaces getspace @tabconf
{
  "txid": "675c5e6148f262ba63f09b440fe51b5679c0c26bf7c97286a18748fd9f62cd30",
  "n": 1,
  "name": "@tabconf",
  "covenant": {
    "type": "transfer",
    "expire_height": 157695,
    "data": null
  },
  "value": 666,
  "script_pubkey": "5120b54d49b0433bc3bdac234ff6818a1f8e800056a6e6c0c5a8ccbdfc3c4545290a"
}
spaces:~/git/spaced-subspaces$ spaces createptr 5120b54d49b0433bc3bdac234ff6818a1f8e800056a6e6c0c5a8ccbdfc3c4545290a 10
Creating sptr: sptr124y0tnu9zszt87vdr4srt8qfsxlex9vqw4v6pa490zfgtgxre25qz5pqnm
✓ Transaction af1e1ac9ba3e209354d92ebe3671309847f34ad17861164a233011e8eb2e17cb


spaces:~/git/spaced-subspaces$ spaces operate -f 10 @pubkey
Assigning space to sptr sptr1cjzy9nunudth76zlzsl4umg9zecrdykvwhula2x2mhz2vhpn0j8qgne6mn
✓ Transaction ea1f1ce3ea20677dda37021dc6a840e96285d20f7236b0c8ce8a6ee989c7dd22
 - Renew @pubkey
Creating UTXO for sptr sptr1cjzy9nunudth76zlzsl4umg9zecrdykvwhula2x2mhz2vhpn0j8qgne6mn
✓ Transaction aa0eeb7bb31a7978d2ea6379e38adf79140d67d9a7e7668cca825166196aab4a
Space should be operational once txs are confirmed

spaces:~/git/spaced-subspaces$ spaces commit -f 10 --root 466d35797396df20228329f585d32c91dbe40866279480dcdb683f6ed82e8a7c @space
✓ Transaction 6af6ca5053df2b68c7d351c2f5bd055f8e6e61635a10ea35d1975cbf11b8b43a


spaces:~/git/spaced-subspaces$ spaces renew -f 10 tabconf
✓ Transaction ec2a2e8713850711d27b3eb6bd9e937b7c779a3500b28bcc97c881dd24e40c60
 - Renew @tabconf

spaces:~/git/spaced-subspaces$ spaces commit -f 10 --root 218a9d0f6041aa54b785e7c850b00da6a1df544fb81456a13001d386cb02d57b @space
✓ Transaction 3f5b3184c9b2a11a760ea7633daab1d5d26113afad07e2c54db150dcdb9c7612

spaces:~/git/spaced-subspaces$ spaces bid -f 10 paradigm 10000
✓ Transaction c1223dc13df16de5d790da98d64b9eceaaee48b4de256e6a829fe08f52da2eef
 - Bid @paradigm
   New bid: 10000 (previous 1000)

spaces:~/git/spaced-subspaces$ spaces commit -f 10 --root a6227952ae60a921fcb7b5973d32aec8a0de96463240b53c4dbd50d1f7319ad7 @tabconf
✓ Transaction 22464969cb2d867ff76b1cf914efd94b9b3750435db0be636156279fedae788b


spaces commit -f 10 --root 2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5 @tabconf

spaces:~/git/spaced-subspaces$ spaces commit -f 10 --root 2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5 @tabconf
✓ Transaction 7baa684aea9e40cba47d49cedbdb338cf2a5cee7d1cf6a9da473a7967fe721e6

// verify if john@doe exists, is valid, and if it's on-chain (with or without req or cert)
// spaces getspace doe : if null then top-level @doe does not exist
// spaces getdelegation @doe : if null then @doe does not exist : else getdelegator to confirm @doe
// spaces getcommitment @doe : if null no commitment exists for @doe : else check state root?
// subs cert verify how?

// subs cert verify john@doe.cert.json : if cert is known

spaces:~/git/spaced-subspaces$ spaces getcommitment @tabconf
{"state_root":[42,244,151,43,27,197,221,53,71,82,124,1,138,3,47,235,69,161,133,219,22,27,206,151,149,53,211,105,239,66,148,213],"prev_root":[166,34,121,82,174,96,169,33,252,183,181,151,61,50,174,200,160,222,150,70,50,64,181,60,77,189,80,209,247,49,154,215],"history_hash":[92,21,149,235,155,234,157,134,146,184,14,170,29,2,18,118,218,199,224,54,250,210,146,86,140,31,1,150,48,220,70,155],"block_height":106104}

2af4971b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5
a6227952ae60a921fcb7b5973d32aec8a0de96463240b53c4dbd50d1f7319ad7
5c1595eb9bea9d8692b80eaa1d021276dac7e036fad292568c1f019630dc469b

Zilla:tabconf i830671$ subs cert verify admin\@tabconf.cert.json --root \@tabconf.cert.json 
Error: root mismatch: subtree=561b449da90aaafec91313073077a77180061b34a8eefc8819fc536e7ea10d5d receipt_final=2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5

Zilla:tabconf i830671$ subs cert verify --root \@tabconf.cert.json andrew\@tabconf.cert.json 
✔ Ready to verify for inclusion
   → handle : andrew@tabconf
   → genesis: e1886c40973423a2123c35a0d56f39577f6cb1a343534d409b2cd3c2df6f3689
   → root : 2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5
   → history : 03b2192078d0ee3b20d69e64c36de641f693954e7a1fb3ae76f682b5d45762d2

   To verify inclusion, run:
       $ space-cli getcommitment @tabconf 2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5
   ⚠️ Make sure the root, and history hashes match!

Zilla:tabconf i830671$ subs cert verify andrew\@tabconf.cert.json 
✔ Ready to verify inclusion
   → handle:   andrew@tabconf
   → genesis:  2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5
   → root:     2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5
   → history:  2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5

   To verify inclusion, run:
       $ space-cli getcommitment @tabconf 2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5
   ⚠️ Make sure the root, and history hashes match!

spaces getcommitment @tabconf 2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5
{"state_root":[42,244,151,43,27,197,221,53,71,82,124,1,138,3,47,235,69,161,133,219,22,27,206,151,149,53,211,105,239,66,148,213],"prev_root":[166,34,121,82,174,96,169,33,252,183,181,151,61,50,174,200,160,222,150,70,50,64,181,60,77,189,80,209,247,49,154,215],"history_hash":[92,21,149,235,155,234,157,134,146,184,14,170,29,2,18,118,218,199,224,54,250,210,146,86,140,31,1,150,48,220,70,155],"block_height":106104}

Zilla:tabconf i830671$ subs cert verify admin\@tabconf.cert.json 
✔ Ready to verify inclusion
   → handle:   admin@tabconf
   → genesis:  561b449da90aaafec91313073077a77180061b34a8eefc8819fc536e7ea10d5d
   → root:     561b449da90aaafec91313073077a77180061b34a8eefc8819fc536e7ea10d5d
   → history:  561b449da90aaafec91313073077a77180061b34a8eefc8819fc536e7ea10d5d

   To verify inclusion, run:
       $ space-cli getcommitment @tabconf 561b449da90aaafec91313073077a77180061b34a8eefc8819fc536e7ea10d5d
   ⚠️ Make sure the root, and history hashes match!

// seems handles committed in prior batches are not verified
// do you have to commit after each proof is run?
spaces:~/git/spaced-subspaces$ spaces getcommitment @tabconf 561b449da90aaafec91313073077a77180061b34a8eefc8819fc536e7ea10d5d
null

// floki & dana committed 2nd
6c61b19aeb82a3130d6f3b8b15217d0e1c62ec76e9ee4630c8e4bcb27cf2d714

spaces:~/git/spaced-subspaces$ spaces commit -f 10 --root 6c61b19aeb82a3130d6f3b8b15217d0e1c62ec76e9ee4630c8e4bcb27cf2d714 @tabconf
✓ Transaction 45b9f806ea107d4f37f1792acc6f2c8c5b6c293e6fdcf876d67ee7e36fe83fb2

// from admin & user committed 3rd but was rejected by spaced
561b449da90aaafec91313073077a77180061b34a8eefc8819fc536e7ea10d5d


spaces commit -f 10 --root 561b449da90aaafec91313073077a77180061b34a8eefc8819fc536e7ea10d5d @tabconf

spaces:~/git/spaced-subspaces$ spaces commit -f 10 --root 561b449da90aaafec91313073077a77180061b34a8eefc8819fc536e7ea10d5d @tabconf
⚠️ could not spend sptr at 7baa684aea9e40cba47d49cedbdb338cf2a5cee7d1cf6a9da473a7967fe721e6:1:UTXO not found in the internal database for txid: 7baa684aea9e40cba47d49cedbdb338cf2a5cee7d1cf6a9da473a7967fe721e6 with vout: 1

// Maybe need to wait for some block commits??

// Need a way to give the user the cert back after the commit that contains their handle is on-chain, so need their email or other way to send them the cert.

// Operator needs to be findable.  Suggest encoding operator site location in top-level spaces rawbytes(data).  Fabric A record for self@space check first?

spaces:~/git/spaced-subspaces$ spaces getcommitment @tabconf 6c61b19aeb82a3130d6f3b8b15217d0e1c62ec76e9ee4630c8e4bcb27cf2d714
{"state_root":[108,97,177,154,235,130,163,19,13,111,59,139,21,33,125,14,28,98,236,118,233,238,70,48,200,228,188,178,124,242,215,20],"prev_root":[42,244,151,43,27,197,221,53,71,82,124,1,138,3,47,235,69,161,133,219,22,27,206,151,149,53,211,105,239,66,148,213],"history_hash":[104,250,22,244,221,59,61,53,94,98,205,50,164,149,149,179,156,173,62,23,16,69,184,190,198,204,90,209,206,1,168,100],"block_height":106120}

spaces:~/git/spaced-subspaces$ spaces getcommitment @tabconf 561b449da90aaafec91313073077a77180061b34a8eefc8819fc536e7ea10d5d
null

// try again : seems like if you commit out of order you forever mess up the handles that were part of that commit.
spaces:~/git/spaced-subspaces$ spaces commit -f 10 --root 561b449da90aaafec91313073077a77180061b34a8eefc8819fc536e7ea10d5d @tabconf
✓ Transaction 15a6e66350b01efe11b1dc1d2cf66aaa4bfe51162ee5d8371a56e399e338990f

spaces:~/git/spaced-subspaces$ spaces commit -f 10 --root 8b0c28ef2fa0f61ad61065e5f17566a2cb5725beae7ccb3fefc43c2b0aae185a @tabconf
✓ Transaction 0eb85963ac21a6945206207bcf3fd094a3267727dbb76a904ee4cedd246875de

spaces bid -f 10 @nomad 10000
✓ Transaction 4bf01b15288de339668f3f1c190a9d8bebcdf349892ee844f6b428f9cb170634
 - Bid @nomad
   New bid: 10000 (previous 1000)



{
  "handle": "andrew@tabconf",
  "script_pubkey": "5120489cb40915375e750fcf6dc036a4bf555db7c670afd06e6de76f4614f95af012",
  "anchor": "2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5",
  "witness": {
    "type": "subtree",
    "data": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACfSrIjlcFVOkwWtLnSGUuGH6Ch/pcT5zA0sHuTQ83ccoAMWnVE/9Hz1tONQULRhW3S3uZZ5oOuIcEzmmzNrXYcz0AIlEgSJy0CRU3XnUPz23ANqS/VV23xnCv0G5t529GFPla8BICyzHubcyRSFOpVLqYwYrg7gA1kTyDq/3MPz/wU928a6Y="
  }
}

spaces:~/git/spaced-spacesops$ spaces createptr 5120489cb40915375e750fcf6dc036a4bf555db7c670afd06e6de76f4614f95af012 10
Creating sptr: sptr14frcyqqrnwydthgj7u09a8vq78wr4eewnwevffrzpake7ng9crkssgd5nz
✓ Transaction cdd18f6b142722a5f9ab22f2ca5283fc9ea2b620fd413628dd885048cedb5d66


spaces:~/git/spaced-spacesops$ spaces open -f 10 tether 10000
✓ Transaction 85aeb2a91d2a8d68f50dc88077c904709b6d55457a33995fdcda7a10d5ee36e8
 - Open @tether
   Initial bid: 10000
✓ Transaction 0ba4fed6209db99337ab36bd50281ed95c321061a43ff9d844c43ff5fdf190ff
 - Bidout 
   Count: 3
 - Commit @tether
spaces:~/git/spaced-spacesops$ spaces open -f 10 usdt 10000
✓ Transaction 21110ea4cc4a89318067ed7d099ed00cc3801eaedb879547f1b498034476786c
 - Open @usdt
   Initial bid: 10000
✓ Transaction 684b052f177a1f1128d98ac088a49f84f22b2057bfa956fafc81fc1aebd2d5e1
 - Commit @usdt
spaces:~/git/spaced-spacesops$ spaces open -f 10 xaut 10000
✓ Transaction b06a2f40ef899c8cf9e00c1e50374901b631376422e556ba5a869fdbc7ccf2fc
 - Open @xaut
   Initial bid: 10000
✓ Transaction bfef954f3305953ef7db495cd15d6d617d7e8479bd0c8fea92b60e3c0afcf71b
 - Commit @xaut
spaces:~/git/spaced-spacesops$ spaces open -f 10 xsat 10000
✓ Transaction 1040b94dfc40a96a0d368f10afcfffb68a72e00308c4f2d98a174b479f9f60a8
 - Open @xsat
   Initial bid: 10000
✓ Transaction 1041fb5fcb66089a0734c58b9579f50783d604d23725fcc5bae364881b2f524f
 - Bidout 
   Count: 3
 - Commit @xsat
spaces:~/git/spaced-spacesops$ spaces open -f 10 usdc 10000
✓ Transaction 056e581bce43f857e617146e0f73f67def3fb3f9e5533e8f7d445d3fd44b1167
 - Open @usdc
   Initial bid: 10000
✓ Transaction 481c04d5c0c1c4201e7c9e9914beb1ea608bdbab4120a41b5418aa7f58f0735d


spaces:~/git/spaced-spacesops$ spaces register -f 10 nomad
✓ Transaction 9c61c715aec3d2a3d21c60bd0a7e7102f6fbe0ea633e2d5cf201a2cb753a4add
 - Renew @nomad

spaces:~/git/spaced-spacesops$ spaces createptr -f 10 5120489cb40915375e750fcf6dc036a4bf555db7c670afd06e6de76f4614f95af012 deadbeef
Creating sptr: sptr14frcyqqrnwydthgj7u09a8vq78wr4eewnwevffrzpake7ng9crkssgd5nz
✓ Transaction c4b478b3402ae717798d7dc2e4f4e811973b738899f91ae01f344ec0f803d486

spaces:~/git/spaced-spacesops$ spaces bid -f 10 btc 10000
✓ Transaction 938018b633484c652d457f08c3b9d9fe2aea1252889dbd3afcb8b1c9edb55675
 - Bid @btc
   New bid: 10000 (previous 1000)


{
  "handle": "andrew@tabconf",
  "script_pubkey": "5120489cb40915375e750fcf6dc036a4bf555db7c670afd06e6de76f4614f95af012",
  "anchor": "2af4972b1bc5dd3547527c018a032feb45a185db161bce979535d369ef4294d5",
  "witness": {
    "type": "subtree",
    "data": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACfSrIjlcFVOkwWtLnSGUuGH6Ch/pcT5zA0sHuTQ83ccoAMWnVE/9Hz1tONQULRhW3S3uZZ5oOuIcEzmmzNrXYcz0AIlEgSJy0CRU3XnUPz23ANqS/VV23xnCv0G5t529GFPla8BICyzHubcyRSFOpVLqYwYrg7gA1kTyDq/3MPz/wU928a6Y="
  }
}


spaces:~/git/spaced-spacesops$ spaces createptr 5120489cb40915375e750fcf6dc036a4bf555db7c670afd06e6de76f4614f95af012 10
Creating sptr: sptr14frcyqqrnwydthgj7u09a8vq78wr4eewnwevffrzpake7ng9crkssgd5nz
✓ Transaction cdd18f6b142722a5f9ab22f2ca5283fc9ea2b620fd413628dd885048cedb5d66

spaces:~/git/spaced-spacesops$ spaces createptr -f 10 5120489cb40915375e750fcf6dc036a4bf555db7c670afd06e6de76f4614f95af012 deadbeef
Creating sptr: sptr14frcyqqrnwydthgj7u09a8vq78wr4eewnwevffrzpake7ng9crkssgd5nz
✓ Transaction c4b478b3402ae717798d7dc2e4f4e811973b738899f91ae01f344ec0f803d486

spaces:~/git/spaced-spacesops$ spaces getptr sptr14frcyqqrnwydthgj7u09a8vq78wr4eewnwevffrzpake7ng9crkssgd5nz
{
  "txid": "cdd18f6b142722a5f9ab22f2ca5283fc9ea2b620fd413628dd885048cedb5d66",
  "n": 0,
  "value": 1007,
  "script_pubkey": "5120489cb40915375e750fcf6dc036a4bf555db7c670afd06e6de76f4614f95af012",
  "genesis_spk": "5120489cb40915375e750fcf6dc036a4bf555db7c670afd06e6de76f4614f95af012",
  "data": null
}


{
  "handle": "dana@tabconf",
  "script_pubkey": "51208fe7dee373fb4d5cf3a4e41010e139a86b0519b2d1af576d66f451fe747bd039",
  "anchor": "8b0c28ef2fa0f61ad61065e5f17566a2cb5725beae7ccb3fefc43c2b0aae185a",
  "witness": {
    "type": "subtree",
    "data": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACVrKFQI7rJGqNsJYgBViI5LJto4lG+RSAcIHzN5e7o0EAYft1nCuTGRz5UcRN4v5bWScXhLoTpuaAzpN0KrnA114AIlEgj+fe43P7TVzzpOQQEOE5qGsFGbLRr1dtZvRR/nR70DkCMPWlwhMohWLWmZ7eC4BKT1jJYwmmlpc4UmA3LNbRWCw="
  }
}

spaces:~/git/spaced-spacesops$ spaces createptr -f 10 51208fe7dee373fb4d5cf3a4e41010e139a86b0519b2d1af576d66f451fe747bd039 beaded
Creating sptr: sptr1npggsr4cc0p08zpaxaed6e255rccrfcza084ty5wmr93u5jnmddqq664at
✓ Transaction 8f7b8415c6845d16fd592b661aad95a00999e3ef8b84abaaf1ac06ab4c11ea84


spaces:~/git/spaced-spacesops$ spaces getptr sptr1npggsr4cc0p08zpaxaed6e255rccrfcza084ty5wmr93u5jnmddqq664at
null

spaces:~/git/spaced-spacesops$ spaces getptr sptr1npggsr4cc0p08zpaxaed6e255rccrfcza084ty5wmr93u5jnmddqq664at
{
  "txid": "8f7b8415c6845d16fd592b661aad95a00999e3ef8b84abaaf1ac06ab4c11ea84",
  "n": 0,
  "value": 1007,
  "script_pubkey": "51208fe7dee373fb4d5cf3a4e41010e139a86b0519b2d1af576d66f451fe747bd039",
  "genesis_spk": "51208fe7dee373fb4d5cf3a4e41010e139a86b0519b2d1af576d66f451fe747bd039",
  "data": "beaded"
}

// If a transaction with a script_pubkey is already in existence, then probably should refuse to create a new one?
// Can a subspace owner create a ptr for themselves?  Only after a top-level space own creates one?
// Doesn't a subspace owner need a funded wallet for some operations?

{
  "handle": "floki@tabconf",
  "script_pubkey": "512082d32946d757e81ddd47f11ae85299d47fdccda5a62bf2ca59bf7c68b8f2c28f",
  "anchor": "8b0c28ef2fa0f61ad61065e5f17566a2cb5725beae7ccb3fefc43c2b0aae185a",
  "witness": {
    "type": "subtree",
    "data": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKLDGNAvmPXRAGvUdbgb3d9X/JcS15/ndIZofqgVM2PACJRIILTKUbXV+gd3UfxGuhSmdR/3M2lpivyylm/fGi48sKPAke7VFm8cRHIEsn0qnXLuPIqmebmBXyCcFXh83duTBdLAmK/Jf7IwGavMQfs75zLjXCBvDxSBqBzlIVhAmqRe4HrAjD1pcITKIVi1pme3guASk9YyWMJppaXOFJgNyzW0Vgs"
  }
}

spaces createptr -f 10 512082d32946d757e81ddd47f11ae85299d47fdccda5a62bf2ca59bf7c68b8f2c28f beefdead

spaces:~/git/spaced-spacesops$ spaces createptr -f 10 512082d32946d757e81ddd47f11ae85299d47fdccda5a62bf2ca59bf7c68b8f2c28f beefdead
Creating sptr: sptr1yclq973htf7uc0udgpj2hm6xlnqtvw9j9j8f738umhzu9lpznqtsj994rd
✓ Transaction 0e653474780aef75bd06cf2e9afec19a0ced41e618f768944693bfd0d12171c4

// What are the implications of passing a script pubkey that is already in existence?
subs request [OPTIONS] <HANDLE>
  -s, --script-pubkey <SCRIPT_PUBKEY>  

spaces commit -f 10 --root e1a06d37948d1e4ea06c155fbabac10f7e5920b877d077503d90d4176f63eda1 @tabconf

spaces:~/git/spaced-spacesops$ spaces commit -f 10 --root e1a06d37948d1e4ea06c155fbabac10f7e5920b877d077503d90d4176f63eda1 @tabconf
✓ Transaction 04dbcd997320cdaf7fb67bc6a2a267174b1c58388b515d60990812a8df8d18a4

spaces:~/git/spaced-spacesops$ spaces register -f 10 btc
✓ Transaction 526b95998f3be2052e742dd081ab5ea614895a21bd3cf85c4e8c449814ebf413
 - Renew @btc

export AUTH_TOKEN=$(echo -n "$SPACED_RPC_USER:$SPACED_RPC_PASSWORD" | base64)

curl -X POST -H "Content-Type: application/json" -H "Authorization: Basic $AUTH_TOKEN" -d '{"jsonrpc":"2.0","method":"getspace","params":["@bitcoin"],"id":1}' http://127.0.0.1:7224 | jq .

curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_TOKEN" \
  -d '{"jsonrpc":"2.0","method":"getcommitment","params":["@tabconf",null],"id":1}' \
  http://127.0.0.1:7224 | jq .

curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_TOKEN" \
  -d '{"jsonrpc":"2.0","method":"getptr","params":["sptr1z5fu9gsrvhgj74alq829n2z7pq6u9y5ae856gxkdxjzdk9myh50qgx5zaj"],"id":1}' \
  http://127.0.0.1:7224 | jq .


To test this:
## XXX
1. Create a pointer : createptr 
2. Transfer it to some other address B : transferptr
3. Create the pointer again : createptr
4. check the pointer it should be address B still : getptr

// Floki's pointer
spaces getptr sptr1yclq973htf7uc0udgpj2hm6xlnqtvw9j9j8f738umhzu9lpznqtsj994rd

// Transfer to John's address (uncommitted)
spaces transferptr sptr1yclq973htf7uc0udgpj2hm6xlnqtvw9j9j8f738umhzu9lpznqtsj994rd --to 5120e82b7767535c17b78cb5389cda7282848384da0
8d52145a4d3756f9feab64ed1
⚠️ legacy address base58 string

spaces:~/git/spaced-spacesops$ spaces getnewspaceaddress
tbs1ph7qpv7ajq2rmemkmv4c970m8lwpmdzvzu3zcqmmhu3qnj9l7mnzq2x3cdz

spaces transferptr sptr1yclq973htf7uc0udgpj2hm6xlnqtvw9j9j8f738umhzu9lpznqtsj994rd --to tbs1ph7qpv7ajq2rmemkmv4c970m8lwpmdzvzu3zcqmmhu3qnj9l7mnzq2x3cdz

spaces:~/git/spaced-spacesops$ spaces transferptr sptr1yclq973htf7uc0udgpj2hm6xlnqtvw9j9j8f738umhzu9lpznqtsj994rd --to tbs1ph7qpv7ajq2rmemkmv4c970m8lwpmdzvzu3zcqmmhu3qnj9l7mnzq2x3cdz
⚠️ could not transfer ptr at 0e653474780aef75bd06cf2e9afec19a0ced41e618f768944693bfd0d12171c4:0:UTXO not found in the internal database for txid: 0e653474780aef75bd06cf2e9afec19a0ced41e618f768944693bfd0d12171c4 with vout: 0

spaces:~/git/spaced-spacesops$ spaces getnewaddress
tb1ph7qpv7ajq2rmemkmv4c970m8lwpmdzvzu3zcqmmhu3qnj9l7mnzqvjehwk

spaces transferptr sptr1yclq973htf7uc0udgpj2hm6xlnqtvw9j9j8f738umhzu9lpznqtsj994rd --to tb1ph7qpv7ajq2rmemkmv4c970m8lwpmdzvzu3zcqmmhu3qnj9l7mnzqvjehwk

spaces:~/git/spaced-spacesops$ spaces transferptr sptr1yclq973htf7uc0udgpj2hm6xlnqtvw9j9j8f738umhzu9lpznqtsj994rd --to tb1ph7qpv7ajq2rmemkmv4c970m8lwpmdzvzu3zcqmmhu3qnj9l7mnzqvjehwk
⚠️ recipient must be a space address

spaces:~/git/spaced-spacesops$ spaces createptr -f 10 5120b54d49b0433bc3bdac234ff6818a1f8e800056a6e6c0c5a8ccbdfc3c4545290a abeef
Custom error: Invalid hex encoded data?
spaces:~/git/spaced-spacesops$ spaces createptr -f 10 5120b54d49b0433bc3bdac234ff6818a1f8e800056a6e6c0c5a8ccbdfc3c4545290a beef
Creating sptr: sptr124y0tnu9zszt87vdr4srt8qfsxlex9vqw4v6pa490zfgtgxre25qz5pqnm
✓ Transaction a0fea1b2cc258de0a3e260ccb43cfe222d648271330db294542a7f5378da5ded


spaces:~/git/spaced-spacesops$ spaces open -f 10 bitcoin 10000
⚠️ open '@bitcoin': space already exists
spaces:~/git/spaced-spacesops$ spaces open -f 10 --skip-tx-check bitcoin 10000
⚠️ open '@bitcoin': space already exists
spaces:~/git/spaced-spacesops$ spaces open -f 10 --force bitcoin 10000
✓ Transaction 4d0e4e7df1030bdb248544ca441133d25212dd3cd8b7cc8e124062380d206af2
 - Open @bitcoin
   Initial bid: 10000
✓ Transaction 3b29a49ab1c16a4ae1ae400b9079f631c83e3d0e519b101225fe164715f30768
 - Commit @bitcoin


spaces:~/git/spaced-spacesops$ spaces getspace bitcoin
{
  "txid": "f811529d79c9fc808c240a1b5087ba19610c4177a01ffa8047c3cc143cf3eb1a",
  "n": 1,
  "name": "@bitcoin",
  "covenant": {
    "type": "transfer",
    "expire_height": 108439,
    "data": "68656c6c6f20776f726c64"
  },
  "value": 666,
  "script_pubkey": "5120611454515f9fe8c656f80c51de229dc5d9cba9a05d00486b43a1e9033ef6393b"
}
spaces:~/git/spaced-spacesops$ spaces getspace bitcoin
{
  "txid": "88815f7de7ae848b0cf595487bb9651109c2004f2cf23f001bf5e1956e2d3416",
  "n": 1,
  "name": "@bitcoin",
  "covenant": {
    "type": "bid",
    "burn_increment": 10000,
    "signature": "1c7587934ba3ef3b77c43371ad3fbf2c2723b0dbec3d5135770c8cd23cea0d1d0b559b5b1d0573b4b63aad41d75d65dab600d82db8ef6dfcb6f66a56db9833c1",
    "total_burned": 10000,
    "claim_height": null
  },
  "value": 662,
  "script_pubkey": "5120bf80167bb20287bceedb65705f3f67fb83b68982e445806f77e4413917fedcc4"
}

// This is the space operator creating the initial ptr for hyper@space
spaces createptr -f 10 512025620c8e616d0d4edfd7ddf826e308b7b2b90e0be95c509285ce0f67c55bff25 beadedbeef

spaces:~/git/spaced-spacesops$ spaces createptr -f 10 512025620c8e616d0d4edfd7ddf826e308b7b2b90e0be95c509285ce0f67c55bff25 beadedbeef
Creating sptr: sptr1u0grpfulv0yqpf9t6vz0sflg2sypma5w7lydaazgada702pu95cqphwgv9
✓ Transaction 1ce5988254b1952ee4eb1cbe73f7219e0714db6594f2938cd37d434575df5445

spaces getptr sptr1u0grpfulv0yqpf9t6vz0sflg2sypma5w7lydaazgada702pu95cqphwgv9

// Create another ptr for hyper@space
spaces createptr -f 1 512025620c8e616d0d4edfd7ddf826e308b7b2b90e0be95c509285ce0f67c55bff25 feedbeef

spaces:~/git/spaced-spacesops$ spaces createptr -f 1 512025620c8e616d0d4edfd7ddf826e308b7b2b90e0be95c509285ce0f67c55bff25 feedbeef
Creating sptr: sptr1u0grpfulv0yqpf9t6vz0sflg2sypma5w7lydaazgada702pu95cqphwgv9
✓ Transaction c0761adf69bbcafa38bbbeac4f1f0888978e6e928ca3335294ddd4fc179099be


// Seems like if you createptr twice, it messes up the getptr
spaces getptr sptr1u0grpfulv0yqpf9t6vz0sflg2sypma5w7lydaazgada702pu95cqphwgv9
spaces getptr sptr1u0grpfulv0yqpf9t6vz0sflg2sypma5w7lydaazgada702pu95cqphwgv9

// Just didn't wait long enough for the transaction to be confirmed
// Returns the first one it finds

spaces:~/git/spaced-spacesops$ spaces getptr sptr1u0grpfulv0yqpf9t6vz0sflg2sypma5w7lydaazgada702pu95cqphwgv9
{
  "txid": "1ce5988254b1952ee4eb1cbe73f7219e0714db6594f2938cd37d434575df5445",
  "n": 0,
  "value": 1007,
  "script_pubkey": "512025620c8e616d0d4edfd7ddf826e308b7b2b90e0be95c509285ce0f67c55bff25",
  "genesis_spk": "512025620c8e616d0d4edfd7ddf826e308b7b2b90e0be95c509285ce0f67c55bff25",
  "data": "beadedbeef"
}

spaces commit -f 1 --root 100a481b50e620829982e2af9c1ca2ecd0aac2d6d543da0bdc6667a951b137aa @space

spaces:~/git/spaced-spacesops$ spaces commit -f 1 --root 100a481b50e620829982e2af9c1ca2ecd0aac2d6d543da0bdc6667a951b137aa @space
✓ Transaction 22615d78305a66268e30bf3a57c6bee0340900f015a61e96f4ece13cea9fb2fa


spaces createptr -f 1 29acea406846da41b3df365395469c3bf296b005a36352a24ee70a4a2bb58981 dabeef

spaces:~/git/spaced-spacesops$ spaces createptr -f 1 29acea406846da41b3df365395469c3bf296b005a36352a24ee70a4a2bb58981 dabeef
Creating sptr: sptr1n9sw9td9cwq9eurps9w9tk2mqzu9lshdjdwcjt9f0mmdw83hz54sw6flss
⚠️ Transaction failed to broadcast
message: scriptpubkey
rpc_code: -26

spaces:~/git/spaced-spacesops$ spaces getnewaddress
tb1  pknjl4sp8qavtv3x6lt63jcszhgs3dg4gprckdzyvn8e6d7d5899s 49cvf4
spaces:~/git/spaced-spacesops$ spaces getnewspaceaddress
tbs1 pknjl4sp8qavtv3x6lt63jcszhgs3dg4gprckdzyvn8e6d7d5899s n3sr2p

// How do I get a spaces address for a handle created in Nacho that I can transferptr to?

spaces transferptr -f 1 sptr1u0grpfulv0yqpf9t6vz0sflg2sypma5w7lydaazgada702pu95cqphwgv9 --to 25620c8e616d0d4edfd7ddf826e308b7b2b90e0be95c509285ce0f67c55bff25

// Try again for expansive@space
  "script_pubkey": "512029acea406846da41b3df365395469c3bf296b005a36352a24ee70a4a2bb58981",
spaces createptr -f 1 512029acea406846da41b3df365395469c3bf296b005a36352a24ee70a4a2bb58981 dabeef
spaces:~/git/spaced-spacesops$ spaces createptr -f 1 512029acea406846da41b3df365395469c3bf296b005a36352a24ee70a4a2bb58981 dabeef
Creating sptr: sptr147xuft6znjp3xsm4d8d56h9vsd5u373jdat44hah58qy205s3efsz6s9lg
✓ Transaction 72e3b74cd7392bb9747f1e40a83604eb2d541f276a9b3f5f176b1dfc332aa511

m/35053/0/0/0,669990ef0e4ece6cb3229c1b881a061ce0493d2d048c9c585574851534978c0b,0225620c8e616d0d4edfd7ddf826e308b7b2b90e0be95c509285ce0f67c55bff25,15hNcowbVWP72Fy985zBJYciQJzTn1AoEa
m/35053/0/0/1,7d3957b0ba89db9e39de8a4025134cd1f1ffa0c2743944fa7447060bb3450094,0329acea406846da41b3df365395469c3bf296b005a36352a24ee70a4a2bb58981,1L48Q6fA7bcDLZ47cP8MifWrXQmCM6bdku


// Commit for sacred@space
  "anchor": "74ae8295ca53465d2766fd52065e6bf1cbe511ef651dbe2fee38634b49abf120",
spaces commit -f 1 --root 74ae8295ca53465d2766fd52065e6bf1cbe511ef651dbe2fee38634b49abf120 @space

spaces:~/git/spaced-spacesops$ spaces commit -f 1 --root 74ae8295ca53465d2766fd52065e6bf1cbe511ef651dbe2fee38634b49abf120 @space
✓ Transaction 74337307d84253c31914f236b1314d9afeceda4783c3f467f25fb7232b4d7aa7


// Try for sacred@space from Nacho in Safari in testnet mode???
spaces createptr -f 1 51206454b5ddb90f4423011789b4c04f81a5e24a5a2c97725a288ce8539fcafc32e9 feedbeef

spaces createptr -f 1 51206454b5ddb90f4423011789b4c04f81a5e24a5a2c97725a288ce8539fcafc32e9 feedbeef
Creating sptr: sptr1yvnr5dvpt5rwwtea2nrzyuzsfl5f44jwhk7734acvjlarymc0l9szm4nk0
✓ Transaction d812ebd5122e68ad1b4af22b53baf280c50a66d848886b5b8c31af9f12c6af5e


// Created a new "default" wallet and a spaces address for it

spaces:~/git/spaced-spacesops$ target/debug/space-cli -w default --chain=testnet4 --rpc-url=http://127.0.0.1:7224 getnewspaceaddress
tbs1pjw09rc5fqlv2edj6zrd35ue4ejv38jv45zqqw6m4hacky9qq26jsrv8r0g

// Transfer the @pubkey to the new spaces address

spaces:~/git/spaced-spacesops$ spaces transfer -f 1 @pubkey --to tbs1pjw09rc5fqlv2edj6zrd35ue4ejv38jv45zqqw6m4hacky9qq26jsrv8r0g
✓ Transaction 959acc225cc80d5c47238331e2607101eaaf19655e6c51e7d103765e67ed8500
 - Transfer @pubkey
   Recipient: tbs1pjw09rc5fqlv2edj6zrd35ue4ejv38jv45zqqw6m4hacky9qq26jsrv8r0g


// Can't figure out how to delegate

spaces:~/git/spaced-spacesops$ target/debug/space-cli -w default --chain=testnet4 --rpc-url=http://127.0.0.1:7224 getnewspaceaddress
tbs1pu9y2yh4xuwsl4w0r2rp4wgjxmvqr0ajgtuvj7k5ahv2lzhqp22fq8jlcda
spaces:~/git/spaced-spacesops$ spaces delegate -f 1 --to tbs1pu9y2yh4xuwsl4w0r2rp4wgjxmvqr0ajgtuvj7k5ahv2lzhqp22fq8jlcda  @nomad
⚠️ transferptr: you don't own `sptr1qxcxdr5f0xl0f5g950jezqdt8lsff4st098x7seke5rrpmzf4hrsdrmj6d`
spaces:~/git/spaced-spacesops$ spaces delegate -f 1 --to tbs1pu9y2yh4xuwsl4w0r2rp4wgjxmvqr0ajgtuvj7k5ahv2lzhqp22fq8jlcda nomad
⚠️ expected a space name prefixed with @ or a hex encoded space hash
spaces:~/git/spaced-spacesops$ spaces delegate -f 1 --to tbs1pu9y2yh4xuwsl4w0r2rp4wgjxmvqr0ajgtuvj7k5ahv2lzhqp22fq8jlcda @nomad
⚠️ transferptr: you don't own `sptr1qxcxdr5f0xl0f5g950jezqdt8lsff4st098x7seke5rrpmzf4hrsdrmj6d`


// Start operating @nomad

spaces:~/git/spaced-spacesops$ spaces operate @nomad
Assigning space to sptr sptr1lh7d66wtnj2pcmscjk4r4z2uhgu7y6w0cmwcqx5msvz6984ssz9qn3v63g
✓ Transaction 771f5ccf7de9cc1a5d45f8c90ea9662bb47ea3906454cab8e91505b7b8b220c4
 - Renew @nomad
Creating UTXO for sptr sptr1lh7d66wtnj2pcmscjk4r4z2uhgu7y6w0cmwcqx5msvz6984ssz9qn3v63g
✓ Transaction 3fe3682adf178cb5fafc750bbbe45eaf2f48a5e23030acfd9162a2e0b1da7c78
Space should be operational once txs are confirmed

// Start operating @paradigm

spaces:~/git/spaced-spacesops$ spaces operate @paradigm
Assigning space to sptr sptr175esgvcwztyngegyvj4z6y257msn0g4qyp849lwrudgj2lel4n3sr03qx7
✓ Transaction 7591636779aad0e53ef2b91136f64141c40537374456cd9e20c25ca53260e273
 - Renew @paradigm
Creating UTXO for sptr sptr175esgvcwztyngegyvj4z6y257msn0g4qyp849lwrudgj2lel4n3sr03qx7
✓ Transaction d6416158568a4201fbdef486f761ef55cbe3570ac7b8ca7e26d313901d031727
Space should be operational once txs are confirmed

// Tried to operate @pubkey but it need some funds
spaces:~/git/spaced-spacesops$ target/debug/space-cli -w default --chain=testnet4 --rpc-url=http://127.0.0.1:7224 operate @pubkey
Assigning space to sptr sptr1cvws2jq9mdaq7r3xt26l8dh6cpvpr3cnyt9e0wrcm2kkzj3895hqu4exug
⚠️ Insufficient funds: 0.00000666 BTC available of 0.00001635 BTC needed

spaces:~/git/spaced-spacesops$ target/debug/space-cli -w default --chain=testnet4 --rpc-url=http://127.0.0.1:7224 getnewaddress
tb1pu9y2yh4xuwsl4w0r2rp4wgjxmvqr0ajgtuvj7k5ahv2lzhqp22fqpxhhwf


spaces:~/git/spaced-spacesops$ target/debug/space-cli -w default --chain=testnet4 --rpc-url=http://127.0.0.1:7224 operate -f 1 @pubkey
Assigning space to sptr sptr1pt7penn27npu0s3pksmwvwqpem4fsrrnn3ymf7pjset6t0ytlgpq0um7x5
✓ Transaction 213d28dff562a34c932de1f97305c8eaf6aac418bca5a39fdaf220ee0cf3bbd1
 - Renew @pubkey
Creating UTXO for sptr sptr1pt7penn27npu0s3pksmwvwqpem4fsrrnn3ymf7pjset6t0ytlgpq0um7x5
✓ Transaction 7de53b263000786d6c019fe2da70e16f5152108fecce531614e256887e160cc4
Space should be operational once txs are confirmed

// Get new space address for default wallet
spaces:~/git/spaced-spacesops$ target/debug/space-cli -w default --chain=testnet4 --rpc-url=http://127.0.0.1:7224 getnewaddress
tb1pknjxa09g2ewz0dleacnkt4mrlzp28dcjg9aqegnezz607cgq6j8qze82fp

spaces delegate -f 1 --to tbs1pknjxa09g2ewz0dleacnkt4mrlzp28dcjg9aqegnezz607cgq6j8qyd0924 @nomad

// Delegate @nomad to default wallet
spaces:~/git/spaced-spacesops$ spaces delegate -f 1 --to tbs1pknjxa09g2ewz0dleacnkt4mrlzp28dcjg9aqegnezz607cgq6j8qyd0924 @nomad
✓ Transaction ca0f593f994c2cacad1045e58c60b44d1a541e59b6b0fcb5bbd612b9995489bb


// I can commit to spaces I own(spaced)

spaces:~/git/spaced-spacesops$ spacesd commit -f 1 --root ff34824c30bba31618e7ce4e70c3d43fc14257efaaf639457d1e6d6f5b8b7040 @pubkey
✓ Transaction 5b14158121f1425e7eed26f0de2e4edfa9e998be6ff2fd05ef955019873b4e6a

// Commit to @nomad as delegated
spacesd commit -f 1 --root 274415d8ee521d09a96ae30928fff275038f255d332fb2651ff4cff874864f11 @nomad

spaces:~/git/spaced-spacesops$ spacesd commit -f 1 --root 274415d8ee521d09a96ae30928fff275038f255d332fb2651ff4cff874864f11 @nomad
✓ Transaction b50f2b80945be4c00d190b2d55265cc6fb4021a18b518306db40f0fc93fff1f9


spaces:~/git/spaced-spacesops$ spaces register -f 1 @tether
✓ Transaction 2963c33b5e6ff3ce6a21ff48655190e687de95fb9ed5571a615fa22baff7c310
 - Renew @tether
spaces:~/git/spaced-spacesops$ spaces register -f 1 @xaut
✓ Transaction 730f3d111f6e0fbf29a45cd172a955e33687e061d420af51be48860067bac49e
 - Renew @xaut
spaces:~/git/spaced-spacesops$ spaces register -f 1 @xsat
✓ Transaction 70930fde5e4ceefa42a827b15c918a7b24c6a0f0057d3c3b43568b58807ea223
 - Renew @xsat
spaces:~/git/spaced-spacesops$ spaces register -f 1 @usdc
✓ Transaction f5db5843e15afb44abff33f5aacb275b555709bf93cf1aa685eafe9a72c43072
 - Renew @usdc
spaces:~/git/spaced-spacesops$ spaces register -f 1 @usdt
✓ Transaction d2f8533acca6b5012b6c1d9ec1f83a21857866e1b76e85e0fdb985533da4bcfb
 - Renew @usdt

Evan Botello
anyone willing to send me a testnet4 spaces handle for testing? tbs1ptpt3ackx6v0ya6hahdzcfn7eqrf7w3d6gcsg8xenwzv97gh763qq6le8fw

spaces:~/git/spaced-spacesops$ spaces transfer -f 1 @paradigm --to tbs1ptpt3ackx6v0ya6hahdzcfn7eqrf7w3d6gcsg8xenwzv97gh763qq6le8fw 
✓ Transaction 277a116d7151857afb576f084e5ec16aeb947e023504fb3d3bede30a27e83931
 - Transfer @paradigm
   Recipient: tbs1ptpt3ackx6v0ya6hahdzcfn7eqrf7w3d6gcsg8xenwzv97gh763qq6le8fw

spaces:~/git/spaced-spacesops$ spaces send -f=1 10000000 --to=tbs1ptpt3ackx6v0ya6hahdzcfn7eqrf7w3d6gcsg8xenwzv97gh763qq6le8fw
✓ Transaction eab641ba3d9129c3fa0de6187212d3c1721dd50de19b4ea7b4b17e3593d5007e
 - Send 
   Amount: 10000000
   Recipient: tb1ptpt3ackx6v0ya6hahdzcfn7eqrf7w3d6gcsg8xenwzv97gh763qqut3g26
spaces:~/git/spaced-spacesops$ spacesd getnewspaceaddress
tbs1pl77ggf00al8uzm853q83nclylmclwykhwlvgu5pmnwjruhyrxkvquvk4f6
spaces:~/git/spaced-spacesops$ spaces send -f=1 10000000 --to=tbs1pl77ggf00al8uzm853q83nclylmclwykhwlvgu5pmnwjruhyrxkvquvk4f6
✓ Transaction 16b75c048efe6ce3e62a92e2d30aa8afbce8a022543827bd6f4ad7dbe5cdb7a6
 - Send 
   Amount: 10000000
   Recipient: tb1pl77ggf00al8uzm853q83nclylmclwykhwlvgu5pmnwjruhyrxkvq6c762w

spaces:~/git/spaced-spacesops$ spaces commit --root 7cd033f4acc41d9a2f975d21bf582a3fa1717da530b6cb089cb2ac7d96100ff1 @nostrops
⚠️ could not estimate fee rate
spaces:~/git/spaced-spacesops$ spaces commit -f 2 --root 7cd033f4acc41d9a2f975d21bf582a3fa1717da530b6cb089cb2ac7d96100ff1 @nostrops
⚠️ commit: sptr sptr1h7z038zgryny7vhky404sj7cxpmx3quv8ew0aaf7wzwkvc4qytksx5wh2c doesn't exists for space @nostrops - have you created it?
spaces:~/git/spaced-spacesops$ spaces operate -f 2 @nostrops
Assigning space to sptr sptr12feuhllyf7at9vgr9e5r955mvtevyc2gd3x6c3h3zekumpshg3aq4ad9nm
✓ Transaction 9f895d931d46e13479450403dea4ac0881c1b843269842a6c8d95daa5be3f0cd
 - Renew @nostrops
Creating UTXO for sptr sptr12feuhllyf7at9vgr9e5r955mvtevyc2gd3x6c3h3zekumpshg3aq4ad9nm
✓ Transaction 1aa075ad87a77fd289339ddfe36db7fe6fabb668126b267e2249a2154fa62924
Space should be operational once txs are confirmed

spaces createptr -f 2 51203d41043d7c365d5e4ec4a53c0d727d40e8e6022278eb455ddd94722039de15aa 010012736F6D657468696E67406E6F7374726F7073023F6E707562316D757475756D38786470677461796C71353365736530686C636867656E7A67337771776867766434647365393236763768686B73307168736A3303167773733A2F2F72656C61792E7072696D616C2E6E6574 (56 bytes) // Failed

spaces:~/git/spaced-spacesops$ spaces createptr -f 2 51203d41043d7c365d5e4ec4a53c0d727d40e8e6022278eb455ddd94722039de15aa 010012736F6D657468696E67406E6F7374726F7073011E687474703A2F2F37302E3235312E3230392E3230372F6170692D646F6373 (44 bytes) // Failed
Creating sptr: sptr1dkvaf0ccm4gmrxdfdn3kzvl2yghml85gu6sux86d29ywzzf3q67squf942
⚠️ Transaction failed to broadcast
message: scriptpubkey
rpc_code: -26

Attempted actions:
spaces:~/git/spaced-spacesops$ spaces createptr -f 2 51203d41043d7c365d5e4ec4a53c0d727d40e8e6022278eb455ddd94722039de15aa 010012736F6D657468696E67406E6F7374726F7073 (21 bytes) // OK
Creating sptr: sptr1dkvaf0ccm4gmrxdfdn3kzvl2yghml85gu6sux86d29ywzzf3q67squf942
✓ Transaction d62831e6a89fb46218b2ffe0795a9e24866b520eaf01d6d0ec6eff36b9d5c57d

spaces getptr sptr1dkvaf0ccm4gmrxdfdn3kzvl2yghml85gu6sux86d29ywzzf3q67squf942

// nothing@nostrops
spaces:~/git/spaced-spacesops$ spaces createptr -f 2 512035007eefe6de3f274db3dbb307c63e67c3fe750403fff3326548995017de1c61 0100106E6F7468696E67406E6F7374726F7073
Creating sptr: sptr1q7f76u6uauqh0pl0ka7w36xpwhmqlqgphmp53ye4c635jn49tg5s3uevy9
✓ Transaction 0a59850b271ca16189ea6c36c37b313e6ba41896fba6c65797cadcc6e7817058

spaces:~/git/spaced-spacesops$ spaces commit -f 2 --root 6c60fdf339452780fc262d7c54bfa63d9e904e32497fc4c283064ffe968830cf @nostrops
✓ Transaction 296fdcf909406e2f4c9a1037ecd8b248abf9fd601d1df11d2d0fb21c8cff7c9f

// Create ptr for everything@nostrops // Sparrow WDK_Quickstart_P2TR Account: Spaces
spaces createptr -f 2 b5c2fa5e1c187f6b2ebb2302ff4e9b81c765445ac2eaee21210fa2b4e6027857 01001365766572797468696E67406E6F7374726F7073

spaces createptr -f 2 16afe871f1400856620c0d73ecd6b2ec3386c3e1fdb4778f71425fb1221b9e39
spaces createptr -f 2 e7368f29139fbc97cb2fcec7c2243a5d0646219bff3e81a0c8964ddd85fc0354

// Includes vacuum@nostrops
spaces:~/git/spaced-spacesops$ spaces commit --root 5d14c2c2f5d54ee30bc4faee18e16ecb8486dc263b38ffab2cf241f74ffb22ef @nostrops
✓ Transaction f8f178b3754a4cefe911f31368bda1e0e0fde83f9d4ca34c3280fdc7d0dad9b7

// 5120892e97e5102abde86d06061e71772b696924335501b69063c1fb136b76440404
spaces createptr -f 2 5120892e97e5102abde86d06061e71772b696924335501b69063c1fb136b76440404

// Ptr for vacuum@nostrops
spaces:~/git/spaced-spacesops$ spaces createptr -f 2 5120892e97e5102abde86d06061e71772b696924335501b69063c1fb136b76440404
Creating sptr: sptr1x88hcaanckx8z5swm3x65v5wcvwyl3gauh6umgkcrmndv6phwf2ssxxhym
✓ Transaction 2617cd9338b408dffeb878d52904132f862b897d1b4d7bf59978bf17cfe756f2

/// Rebuilt from Buffrr's latest
// Ptr for admin@nostrops
spaces createptr -f 2 51201d6b8f8b484bc533cfc5c6348a78b49e653289b092996bc659451181dddd5339
spaces:~/git/spaced-spacesops$ spaces createptr -f 2 51201d6b8f8b484bc533cfc5c6348a78b49e653289b092996bc659451181dddd5339
Creating sptr: sptr13vht3dfz7c2d3qlxj7ynna6daz8cen8ew9y646k0ry0ulrs79hgqgamjc2
✓ Transaction 69252444ed6a6bc4a3c283afe418bc6ba55e9c041089eaff4d049f49cb76a0d7

// Commit proof has containing opstrich@nostrops

c2fc8f46185cfc2b340e644d7b760efab4cab2933b557466a2c0f5e6be768dc0
spaces commit -f 2 --root c2fc8f46185cfc2b340e644d7b760efab4cab2933b557466a2c0f5e6be768dc0 @nostrops
spaces commit --root c2fc8f46185cfc2b340e644d7b760efab4cab2933b557466a2c0f5e6be768dc0 @nostrops
spaces:~/git/spaced-spacesops$ spaces commit -f 2 @nostrops c2fc8f46185cfc2b340e644d7b760efab4cab2933b557466a2c0f5e6be768dc0
⚠️ channel closed

opstrich@nostrops
Public Key
    1f2a73f4b6fb14b4d4675219df138c52f0de95f65d4b18aa2c7f8a739815e4f6
51201f2a73f4b6fb14b4d4675219df138c52f0de95f65d4b18aa2c7f8a739815e4f6
spaces createptr -f 2 51201f2a73f4b6fb14b4d4675219df138c52f0de95f65d4b18aa2c7f8a739815e4f6

spaces:~/git/spaced-spacesops$ spaces createptr -f 2 51201f2a73f4b6fb14b4d4675219df138c52f0de95f65d4b18aa2c7f8a739815e4f6
Creating sptr: sptr1wryaaqwu2t9c9kacltasckj5j4hmlxfu6ulu5fuh33yrsa22kwaq8t9hlj
⚠️ channel closed

// Waited, restarted spaced
spaces:~/git/spaced-spacesops$ spaces createptr -f 2 51201f2a73f4b6fb14b4d4675219df138c52f0de95f65d4b18aa2c7f8a739815e4f6
Creating sptr: sptr1wryaaqwu2t9c9kacltasckj5j4hmlxfu6ulu5fuh33yrsa22kwaq8t9hlj
✓ Transaction 715b212635ab9811aac097387445148e26bf0b381b2dd4fb0cfca9c680885c09

// Now have @nomad operating

// generation@nomad 5120669cb87f78e7d6923012a29b9988242db99130c093fd976630df62f16eeca275
spaces createptr -f 3 5120669cb87f78e7d6923012a29b9988242db99130c093fd976630df62f16eeca275

spaces:~/git/spaced-subspaces$ spaces createptr -f 3 5120669cb87f78e7d6923012a29b9988242db99130c093fd976630df62f16eeca275
Creating sptr: sptr1244z0kuykyn2pcajupsmfvn86rqm5pgfts6jmyf0xjw4zzwz5fes728wrm
✓ Transaction 909954062786ff394752cbc5a561a85f22e0092285eca232efc482a0920bfefe

spaces:~/git/spaced-subspaces$ spaces getptr sptr1244z0kuykyn2pcajupsmfvn86rqm5pgfts6jmyf0xjw4zzwz5fes728wrm | jq .
{
  "txid": "909954062786ff394752cbc5a561a85f22e0092285eca232efc482a0920bfefe",
  "n": 0,
  "id": "sptr1244z0kuykyn2pcajupsmfvn86rqm5pgfts6jmyf0xjw4zzwz5fes728wrm",
  "data": null,
  "last_update": 112141,
  "value": 1007,
  "script_pubkey": "5120669cb87f78e7d6923012a29b9988242db99130c093fd976630df62f16eeca275"
}

// Create ptr for wandering@nomad BEFORE the proof hash is committed.
spaces createptr -f 3 --data=01000F77616E646572696E67406E6F6D61640123687474703A2F2F37302E3235312E3230392E3230373A383838382F6170692D646F6373023F6E707562316D757475756D38786470677461796C71353365736530686C636867656E7A67337771776867766434647365393236763768686B73307168736A3300167773733A2F2F72656C61792E7072696D616C2E6E6574 51201793acbbf64789afc8e7ceb1dd33adbd0c7a2aaa0106e00829253d7da8635da0

spaces:~/git/spaced-spacesops$ spaces createptr -f 3 --data=01000F77616E646572696E67406E6F6D61640123687474703A2F2F37302E3235312E3230392E3230373A383838382F6170692D646F6373023F6E707562316D757475756D38786470677461796C71353365736530686C636867656E7A67337771776867766434647365393236763768686B73307168736A3300167773733A2F2F72656C61792E7072696D616C2E6E6574 51201793acbbf64789afc8e7ceb1dd33adbd0c7a2aaa0106e00829253d7da8635da0
Creating sptr: sptr1vhqy5ct8xej7sc4qj5flfhfwtsk0y0ejrl3ptfhus8l3t88d5vvqhfu7zl
✓ Transaction 8b09e9e5de1cc3ded9fc1c86255403e4ea09c1bd5623d113786a06453a0bb24a



spaces:~/git/spaced-spacesops$ spaces getdelegation @nomad
"sptr1quzngdh4dl3k96kt5eytjvvhm5myexyucryjt4t5g8e2nwzdehhq6sru4c"


spaces setrawfallback -f 2 sptr1quzngdh4dl3k96kt5eytjvvhm5myexyucryjt4t5g8e2nwzdehhq6sru4c 010006406E6F6D61640123687474703A2F2F37302E3235312E3230392E3230373A383838382F6170692D646F6373023F6E707562316D757475756D38786470677461796C71353365736530686C636867656E7A67337771776867766434647365393236763768686B73307168736A3300167773733A2F2F72656C61792E7072696D616C2E6E6574

setrawfallback -f 2 @nomad 010006406E6F6D61640123687474703A2F2F37302E3235312E3230392E3230373A383838382F6170692D646F6373023F6E707562316D757475756D38786470677461796C71353365736530686C636867656E7A67337771776867766434647365393236763768686B73307168736A3300167773733A2F2F72656C61792E7072696D616C2E6E6574

<!-- I think I messed up @nomad by delegating to the wrong pointer.  Need to fix it. -->
// Swithching to @did
spaces:~/git/spaced-spacesops$ spaces delegate -f 2 @did
Delegating space @did
✓ Transaction fcda5e01c12eb961088fe885c8c490a87b54a016cc3386ea2428dedc112680e6
 - Renew @did
Space delegation should be complete once tx is confirmed

spaces commit -f 2 --root 8f81d8c22f652aa7e20006bcebcbaac21e8dce448639a78b277f265559563584 @did

spaces createptr -f 3 --data=01000875736572406469640123687474703A2F2F37302E3235312E3230392E3230373A383838382F6170692D646F6373 5120aca68227f4d3117dfc5e5ebd844265cc528bdcc18c11431aab106d0b5611ff2b

spaces:~/git/spaced-spacesops$ spaces createptr -f 3 --data=01000875736572406469640123687474703A2F2F37302E3235312E3230392E3230373A383838382F6170692D646F6373 5120aca68227f4d3117dfc5e5ebd844265cc528bdcc18c11431aab106d0b5611ff2b
Creating sptr: sptr16jdzsrml2hu4ndscqnahlpr6ea0g0c2phz7w9a2vxak78zqrqmpssmdukl
✓ Transaction 69c8d8295e539c94e930565206cd4236e7c016992a5521b7842c7f7ada6e6558

spaces:~/git/spaced-spacesops$ spaces createptr -f 2 --data=01000961646D696E406469640123687474703A2F2F37302E3235312E3230392E3230373A383838382F6170692D646F6373051A6469643A6274633A783230722D6179617A2D7171746C2D6C6A6B 51204294c843b3edf47240d6b4532372bbcacf33946a8b94f22a98a25099955dbd90
Creating sptr: sptr1ur89nczzheactvtgamlpl6hp2ghh3mh6q62km642ql5u3ujyyhrstv3z28
✓ Transaction ffe43bc0dc3ded9e97a0e7782962c6cfae8bbeffe0abdd357beff69fa7dcf062

spaces commit -f 2 @did 8f81d8c22f652aa7e20006bcebcbaac21e8dce448639a78b277f265559563584
spaces:~/git/spaced-spacesops$ spaces commit -f 2 @did 8f81d8c22f652aa7e20006bcebcbaac21e8dce448639a78b277f265559563584
✓ Transaction bcc8e1ca2fc7920fc70f3c440de8c1d3bebcd7500297ebfb8b372d2c98d68240

spaces commit -f 2 @did 50912e78a92a0e76f41b69e5925dec307a9c12d41177478fa2afeb8dae9c0855
spaces:~/git/spaced-spacesops$ spaces commit -f 2 @did 50912e78a92a0e76f41b69e5925dec307a9c12d41177478fa2afeb8dae9c0855
✓ Transaction 0eeff1fd5994459b1b78bb17d53f56c42c563fcccdc320c8b95e5d575a6b55b2

// none@did
spaces createptr -f 2 --data=0100086E6F6E6540646964023F6E707562316D757475756D38786470677461796C71353365736530686C636867656E7A67337771776867766434647365393236763768686B73307168736A330124687474703A2F2F37302E3235312E3230392E3230373A383838382F6170692D646F63732F032D7773733A2F2F72656C61792E7072696D616C2E6E65742F2C7773733A2F2F72656C61792E64616D75732E696F2F051A6469643A6274633A783230722D6179617A2D7171746C2D6C6A6B093F5468697320697320612074657374206F662067726561746572207468616E203830206865782062797465732E2041637475616C206C656E677468203235342E 51208826605f3e05882e22c8409eed007fc319d64a80a1038b5d3713cd928f762675

spaces:~/git/spaced-spacesops$ spaces createptr -f 2 --data=0100086E6F6E6540646964023F6E707562316D757475756D38786470677461796C71353365736530686C636867656E7A67337771776867766434647365393236763768686B73307168736A330124687474703A2F2F37302E3235312E3230392E3230373A383838382F6170692D646F63732F032D7773733A2F2F72656C61792E7072696D616C2E6E65742F2C7773733A2F2F72656C61792E64616D75732E696F2F051A6469643A6274633A783230722D6179617A2D7171746C2D6C6A6B093F5468697320697320612074657374206F662067726561746572207468616E203830206865782062797465732E2041637475616C206C656E677468203235342E 51208826605f3e05882e22c8409eed007fc319d64a80a1038b5d3713cd928f762675
Creating sptr: sptr1h6sgdhpg9pfc6ua3ycy4hvtzr4rhyyqglkd6c6xtukv8uc2ewjrss32t8z
✓ Transaction 5b0451901753ef78d8e176fa77979c71d0f999ac395bd0b5e1618b0c78fcd793

bitcoin-cli -testnet4 -rpcuser=iroxnnkko -rpcpassword=p3T9xW9u3WSxvV3oJdV -getinfo
bitcoin-cli getmempoolentry 5b0451901753ef78d8e176fa77979c71d0f999ac395bd0b5e1618b0c78fcd793

bitcoin-cli -testnet4 -rpcuser=iroxnnkko -rpcpassword=p3T9xW9u3WSxvV3oJdV getmempoolentry 5b0451901753ef78d8e176fa77979c71d0f999ac395bd0b5e1618b0c78fcd793

bitcoin-cli -testnet4 -rpcuser=iroxnnkko -rpcpassword=p3T9xW9u3WSxvV3oJdV getrawtransaction 5b0451901753ef78d8e176fa77979c71d0f999ac395bd0b5e1618b0c78fcd793

bitcoin-cli -testnet4 -rpcuser=iroxnnkko -rpcpassword=p3T9xW9u3WSxvV3oJdV sendrawtransaction 5b0451901753ef78d8e176fa77979c71d0f999ac395bd0b5e1618b0c78fcd793

spaces:~/git/spaced-spacesops$ spaces commit -f 2 @did 8f81d8c22f652aa7e20006bcebcbaac21e8dce448639a78b277f265559563584
✓ Transaction 04546ae078b67c590a0c9c247ae4095c231791e988a14b354c43771483081311

spaces:~/git/spaced-spacesops$ spacesd delegate -f 2 @pubkey
Delegating space @pubkey
✓ Transaction 24e1cb0a09c17c662765fa590282fa79b91f885e498e3ab5e74b8db392052f07
 - Renew @pubkey
Space delegation should be complete once tx is confirmed

e1a0d72648c8bd2fa3b3dc300c37088ebbc7a5acb3903d005f9c1e2498f41b10
spacesd commit -f 2 @pubkey e1a0d72648c8bd2fa3b3dc300c37088ebbc7a5acb3903d005f9c1e2498f41b10
spaces:~/git/spaced-spacesops$ spacesd commit -f 2 @pubkey e1a0d72648c8bd2fa3b3dc300c37088ebbc7a5acb3903d005f9c1e2498f41b10
✓ Transaction 3eed2038c8115cc8632f7f9dc55fee67c307785713be835641331d8b26b1b599 12379
https://mempool.space/testnet4/tx/3eed2038c8115cc8632f7f9dc55fee67c307785713be835641331d8b26b1b599

spaces:~/git/spaced-spacesops$ spacesd commit -f 2 @pubkey 4125905401fa971f5b3f3f7dcd13622d53ea4e31d8be29d78df1c5e9c768d19b
✓ Transaction b69a26b24371c0b25078f6d27acd46d5a4cb99055d9989634c8444df77689295 12450

spacesd getcommitment @pubkey | jq .
{
  "state_root": "4125905401fa971f5b3f3f7dcd13622d53ea4e31d8be29d78df1c5e9c768d19b",
  "prev_root": null,
  "history_hash": "4125905401fa971f5b3f3f7dcd13622d53ea4e31d8be29d78df1c5e9c768d19b",
  "block_height": 112450
}

spaces:~/git/spaced-spacesops$ spacesd commit -f 2 @pubkey 7c48c474e4620da079ffe4e9b7f9f4a58d15cbf150fe1b2d3c153a3946a252f4
✓ Transaction bccc6eb3292bbc5f61f53ede035f6ae9fe0cff2387f3474af2a817872e07135d



spaces:~/git/spaced-spacesops$ spaces delegate -f 2 @usdt
Delegating space @usdt
✓ Transaction 60e6c684e32506430fd6b609bdaf79670773f09b8629342fc36b8f4646aaa7b9
 - Renew @usdt
Space delegation should be complete once tx is confirmed

spaces:~/git/spaced-spacesops$ spaces delegate -f 2 @xaut
Delegating space @xaut
✓ Transaction 3c56adf8eb15254bb22d535f0a2e29e0ed2ec3987ceb1ce535cc71c607c20ddb
 - Renew @xaut
Space delegation should be complete once tx is confirmed


$ spacesops getnewspaceaddress
tbs1pwg7q298j0u8qa94763ddtwase0qcwddk8r7m9r2kj8yfznwks30qaze2es

spaces:~/git/spaced-spacesops$ spaces transfer -f 10 @spacesops --to tbs1pwg7q298j0u8qa94763ddtwase0qcwddk8r7m9r2kj8yfznwks30qaze2es --data 01000A407370616365736F7073011668747470733A2F2F7370616365736F70732E636F6D2F091853504143455320504C4154464F524D204F50455241544F52
✓ Transaction 02ff23c85386f1e1990c92241b959acf0f75d417d5116c2d1087b99a80934baa
 - Transfer @spacesops
   Recipient: tbs1pwg7q298j0u8qa94763ddtwase0qcwddk8r7m9r2kj8yfznwks30qaze2es

spaces:~/git/spaced-spacesops$ spaces delegate -f 2 @btc
Delegating space @btc
✓ Transaction b69fa43729e00d2362162fa37b4125b239d1a9fddc52bab87f0e948f7233ad8f
 - Renew @btc
Space delegation should be complete once tx is confirmed



spaces:~/git/spaced-spacesops$ spaces getspace @usdt
{
  "covenant": {
    "data": null,
    "expire_height": 161962,
    "type": "transfer"
  },
  "n": 1,
  "name": "@usdt",
  "script_pubkey": "51209383a3e20f4867d034a3c19e0c1ec401f077d35fd2984078480a6187ec0786bc",
  "txid": "d2f8533acca6b5012b6c1d9ec1f83a21857866e1b76e85e0fdb985533da4bcfb",
  "value": 666
}


spaces:~/git/spaced-spacesops$ spaces createptr -f 100 --data 0100054075736474024435313230393338336133653230663438363764303
33461336331396530633165633430316630373764333566643239383430373834383061363138376563303738366263 51209383a3e20f4867d034a3c19
e0c1ec401f077d35fd2984078480a6187ec0786bc
Creating sptr: sptr1qd3plnnykcz7g0pg4ckevzm3gug2lx9uccw5wxusdlfwfhq3wrxqrd4geh
✓ Transaction f9ea6237a1dbd485bc5d03cbc8e163882278cd9b7d03cc8efb433a78ff39d6b4

spaces:~/git/spaced-spacesops$ spaces authorize -f 500 --to="@spacesops" @usdt
⚠️ transfer: PTR 'sptr1qd3plnnykcz7g0pg4ckevzm3gug2lx9uccw5wxusdlfwfhq3wrxqrd4geh' not found or not owned

// @xaut
spaces:~/git/spaced-spacesops$ spaces createptr -f 100 --data 010005407861757402443531323062383832343938316430643932643264353262623736373331613365363637313336363764326332396131333130613030346637626230376138636265643230 5120b8824981d0d92d2d52bb76731a3e66713667d2c29a1310a004f7bb07a8cbed20
Creating sptr: sptr1vd62gasnf7vac6xr9ehuk235meg0qqyvdf0l2ly9qtwa2uagckkszz29qy
✓ Transaction b910b6bd4bf68ce2019fb00027443e00fa83b39353656e2889f16722da3af8db

// Wait

spaces authorize -f 500 --to=@spacesops @usdt
5120b8824981d0d92d2d52bb76731a3e66713667d2c29a1310a004f7bb07a8cbed20
5120.............................b8821d0d92d2d52bb767317bb07a8cbed20

spaces:~/git/spaced-spacesops$ spaces authorize -f 500 --to=@spacesops @usdt
✓ Transaction 73674728bad678334528d15b5478d6a18b4d7bcc6976265b0b5c0313f838e52a
spaces:~/git/spaced-spacesops$ spaces authorize -f 500 --to=@spacesops @xaut
✓ Transaction e6762c2ee4e7b9e633bbeedfb1adc20c721f09e5f38b5b9aec221863852061a1
spaces:~/git/spaced-spacesops$ spaces authorize -f 500 --to=@spacesops @btc
✓ Transaction 5f35a4dabf321e6031ef09e76731733007d6555f97f12447275e792a6fcf207f


spaces:~/git/spaced-spacesops$ spaces send -f 10 1000 --to @spacesops
✓ Transaction 719a09dcfdf3232d2f8e1c2aa8d181514d8be5dcbd7f908a3bb6e53b3bed38db
 - Send 
   Amount: 1000
   Recipient: tb1pwg7q298j0u8qa94763ddtwase0qcwddk8r7m9r2kj8yfznwks30qmk396y

spaces:~/git/spaced-spacesops$ spaces send -f 10 1001 --to @spacesops --memo "@xaut tasks"
✓ Transaction 64c12bbe4aa0a133d13e127ee339b83e099d17b8ade9cd1c7f39ead87e21b155
 - Send 
   Amount: 1001
   Recipient: tb1pwg7q298j0u8qa94763ddtwase0qcwddk8r7m9r2kj8yfznwks30qmk396y

spaces:~/git/spaced-spacesops$ spaces commit -f 10 @tabconf 37cb130c6c7b45ef1ef7dc99814865a418a98a8dc8f0711091836c2106f211d7
✓ Transaction c19c15bedb16ebfcfb9c67f5598bdee85fe5f0c52db574e9ebc4f86fbe5924b1

spaces:~/git/spaced-spacesops$ spaces commit -f 10 @tabconf 38f44384adac3b24e79144e77175ac58a6610f4ab0e1552064a74425dbb736b4
✓ Transaction 0869994cbaa59ec9fc1b58a192349d7d67fd4d77ad17d0e68ba178f1ffbc8c35

spaces:~/git/spaced-spacesops$ spaces getcommitment @tabconf | jq .
{
  "state_root": "37cb130c6c7b45ef1ef7dc99814865a418a98a8dc8f0711091836c2106f211d7",
  "prev_root": null,
  "history_hash": "37cb130c6c7b45ef1ef7dc99814865a418a98a8dc8f0711091836c2106f211d7",
  "block_height": 114011

// Started over with tabconf

spaces:~/git/spaced-spacesops$ spaces commit -f 10 @tabconf 11bbd74ee3602523becc4bfd4cab34e6d2af1b119c39e0a25f7ae7be7
f747870
✓ Transaction ec386954b5228b2fbfc01c325b41af2e443c368af92b5908ee1b36d906b50243

<!-- unknown@tabconf -->
spaces:~/git/spaced-spacesops$ spaces createptr -f 10 --data 01000F756E6B6E6F776E40746162636F6E66 5120bafd5c51adb3c034dd8f0b23
a18013690a1683f3964cc3040b49c2e304401145
Creating sptr: sptr1ykqpk2rtckj95dgap92f4fs7mn6aln0ahnq3fq7jzdr30ceg7cdqnpunj2
✓ Transaction 0aaa558fdbebe429461620544722df0988b71f622b6f322dfa4e9ab06c4cdc59

spaces:~/git/spaced-spacesops$ spaces createptr -f 10 --data 01000F756E6B6E6F776E40746162636F6E66 5120452a07dcb2c2ab079ac2d08f65db6a14b596a1298a371c8bd61679200cb58752
Creating sptr: sptr1rfvr44q6w9ak9fd0rks6v5a0v065agtuc5qwkyq8dehcsgxpaxsssa7rlc
✓ Transaction 348ae7fbae6a438f971c0d533323f7133ded6f2f17dc3629064174725c91add9

// Proof containing known@tabconf
spaces:~/git/spaced-spacesops$ spaces commit -f 10 @tabconf 17e64c1f4db7f7aa0734547088506b4c2e6f82eff4f35f36cd0b172875972dbd
✓ Transaction ac7bbeba9faba0705be5b4b6b24ffeec297520ffef613c379d8e203bcf91e910

// known@tabconf
spaces:~/git/spaced-spacesops$ spaces createptr -f 10 --data 01000D6B6E6F776E40746162636F6E66011E687474703A2F2F37302E3235312E3230392E3230372F6170692D646F6373 5120d9d96c98d1a21b45a962c77d4e448adc0de60dc13b7d56f3603d4ae9d3acfba3
Creating sptr: sptr1z5fu9gsrvhgj74alq829n2z7pq6u9y5ae856gxkdxjzdk9myh50qgx5zaj
✓ Transaction a92901cbc8b021e80ba9554ebfacdfb89cd0cee2e00db62fdeb820ed543d9867

spaces:~/git/spaced-spacesops$ spaces getspace @tabconf
{
  "covenant": {
    "data": null,
    "expire_height": 158549,
    "type": "transfer"
  },
  "n": 1,
  "name": "@tabconf",
  "script_pubkey": "5120b54d49b0433bc3bdac234ff6818a1f8e800056a6e6c0c5a8ccbdfc3c4545290a",
  "txid": "ec2a2e8713850711d27b3eb6bd9e937b7c779a3500b28bcc97c881dd24e40c60",
  "value": 666
}

// @usdc get the script pubkey
spaces:~/git/spaced-spacesops$ spaces getspace @usdc
{
  "covenant": {
    "data": null,
    "expire_height": 161962,
    "type": "transfer"
  },
  "n": 1,
  "name": "@usdc",
  "script_pubkey": "5120e17a0aa9ce71153e1adb401b1c8f3afa6a1d401066815df28ab5d4e84014621f",
  "txid": "f5db5843e15afb44abff33f5aacb275b555709bf93cf1aa685eafe9a72c43072",
  "value": 666
}

// @usdc create the sptr from the script pubkey
spaces:~/git/spaced-spacesops$ spaces createptr -f 10 5120e17a0aa9ce71153e1adb401b1c8f3afa6a1d401066815df28ab5d4e84014621f
Creating sptr: sptr16yxrh2x04yhhxrw2qjyc7v60x2ey2q4858wnw7g3ylzyxz4pzm0qarf4lv
✓ Transaction a014e15811db8351403ce719faed065c41e550317436581a27626f09731fed5e

0100054075736463

spaces:~/git/spaced-spacesops$ spaces getptr sptr16yxrh2x04yhhxrw2qjyc7v60x2ey2q4858wnw7g3ylzyxz4pzm0qarf4lv | jq .
{
  "txid": "a014e15811db8351403ce719faed065c41e550317436581a27626f09731fed5e",
  "n": 0,
  "id": "sptr16yxrh2x04yhhxrw2qjyc7v60x2ey2q4858wnw7g3ylzyxz4pzm0qarf4lv",
  "data": null,
  "last_update": 117835,
  "value": 1007,
  "script_pubkey": "5120e17a0aa9ce71153e1adb401b1c8f3afa6a1d401066815df28ab5d4e84014621f"
}

spaces setrawfallback -f 10 sptr16yxrh2x04yhhxrw2qjyc7v60x2ey2q4858wnw7g3ylzyxz4pzm0qarf4lv 0100054075736463
spaces setrawfallback -f 10 @usdc 0100054075736463 // Not working.


spaces:~/git/spaced-spacesops$ spaces setrawfallback -f 10 sptr16yxrh2x04yhhxrw2qjyc7v60x2ey2q4858wnw7g3ylzyxz4pzm0qarf4lv 0100054075736463
✓ Transaction 0163778d0865210fc9601d5b8b4bef8c667e1987b4db998c14cc2a004a1da6b0 //working

010000000001025eed1f73096f62271a5836743150e5415c06edfa19e73c405183db1158e114a00000000000fdffffff59dc4c6cb09a4efa2d326f2b621fb78809df22475420164629e4ebdb8f55aa0a0200000000fdffffff03ef0300000000000022512019438be7adbcbf9c617cc59cb497169423ff20c7075b8aad21cf54e3744593a500000000000000000b6a510801000540757364639491970000000000225120e82bf86c2fdd9b7d1bc275f907ed1efce3eb86442eef148f0827b8c8389fe8cd01400b36e849372eba933bd97f3b927b8bea7854a39764d7a7652443ef3d59af9984ef195bdc149d83ad1d49ee1ed593d9288de4a4ff1c896db6d50a49b951cdb7a501402033258aeb2181cd8e62987b52c3476796295f3fe7f0ade5b007016230e527f3750ca32b39aebc0cc5d988b55630e6144a2dd7f1454d6051f78dd0b1203fc90e39086169

spaces:~/git/spaced-spacesops$ spaces getptr sptr16yxrh2x04yhhxrw2qjyc7v60x2ey2q4858wnw7g3ylzyxz4pzm0qarf4lv | jq .
{
  "txid": "0163778d0865210fc9601d5b8b4bef8c667e1987b4db998c14cc2a004a1da6b0",
  "n": 0,
  "id": "sptr16yxrh2x04yhhxrw2qjyc7v60x2ey2q4858wnw7g3ylzyxz4pzm0qarf4lv",
  "data": "0100054075736463",
  "last_update": 117911,
  "value": 1007,
  "script_pubkey": "512019438be7adbcbf9c617cc59cb497169423ff20c7075b8aad21cf54e3744593a5"
}


// known@tabconf
spaces getptr sptr1z5fu9gsrvhgj74alq829n2z7pq6u9y5ae856gxkdxjzdk9myh50qgx5zaj | jq .
{
  "txid": "a92901cbc8b021e80ba9554ebfacdfb89cd0cee2e00db62fdeb820ed543d9867",
  "n": 0,
  "id": "sptr1z5fu9gsrvhgj74alq829n2z7pq6u9y5ae856gxkdxjzdk9myh50qgx5zaj",
  "data": "01000d6b6e6f776e40746162636f6e66011e687474703a2f2f37302e3235312e3230392e3230372f6170692d646f6373",
  "last_update": 117835,
  "value": 1007,
  "script_pubkey": "5120d9d96c98d1a21b45a962c77d4e448adc0de60dc13b7d56f3603d4ae9d3acfba3"
}

spaces:~/git/spaced-spacesops$ spaces getptr sptr1z5fu9gsrvhgj74alq829n2z7pq6u9y5ae856gxkdxjzdk9myh50qgx5zaj | jq .
{
  "txid": "1bbb0f3b4b9a58db907cedc611942f5fc736768fff443e23cc71dfba98d503b8",
  "n": 0,
  "id": "sptr1z5fu9gsrvhgj74alq829n2z7pq6u9y5ae856gxkdxjzdk9myh50qgx5zaj",
  "data": "01000d6b6e6f776e40746162636f6e66011e687474703a2f2f37302e3235312e3230392e3230372f6170692d646f6373",
  "last_update": 117952,
  "value": 1007,
  "script_pubkey": "5120f2631102f6e3afb37a997ffb9b5d1ad144447d4ad7652cab29784ed095abb1ff"
}


// Need a way to request a SPTR from the operator. Give them a quote like when purchaing a subspace. Wait for payment.
// This presumes the operator has already created the sptr and the client has it.
// Compose a sovereign update for known@tabconf tx: a92901cbc8b021e80ba9554ebfacdfb89cd0cee2e00db62fdeb820ed543d9867
// Create an RPC call to spaced to query the sptr. /api/sptr/sptr1z...50qgx5zaj to get tx id.
// Need the UTXO from the existing sptr 
// Need an address from account 1 controlled by known@tabconf tb1p7f33zqhkuwhmx75e0laekhg669zygl226ajje2ef0p8dp9dtk8lsmwvmh5
// Need the new hex data 01000D6B6E6F776E40746162636F6E66011E687474703A2F2F37302E3235312E3230392E3230372F6170692D646F63730917466972737420736F7665726569676E207570646174652E
// Need another UTXO from account 0 to fund the transaction


space-cli createptr -f 10 --data 01000D6B6E6F776E40746162636F6E66011E687474703A2F2F37302E3235312E3230392E3230372F6170692D646F6373 5120d9d96c98d1a21b45a962c77d4e448adc0de60dc13b7d56f3603d4ae9d3acfba3
Creating sptr: sptr1z5fu9gsrvhgj74alq829n2z7pq6u9y5ae856gxkdxjzdk9myh50qgx5zaj
✓ Transaction a92901cbc8b021e80ba9554ebfacdfb89cd0cee2e00db62fdeb820ed543d9867

space-cli getptr sptr1z5fu9gsrvhgj74alq829n2z7pq6u9y5ae856gxkdxjzdk9myh50qgx5zaj | jq .

txid: a92901cbc8b021e80ba9554ebfacdfb89cd0cee2e00db62fdeb820ed543d9867 // known@tabconf http://70.251.209.207/api-docs
data=01000D6B6E6F776E40746162636F6E66011E687474703A2F2F37302E3235312E3230392E3230372F6170692D646F6373

txid: 1bbb0f3b4b9a58db907cedc611942f5fc736768fff443e23cc71dfba98d503b8 // + First sovereign update.
data=01000D6B6E6F776E40746162636F6E66011E687474703A2F2F37302E3235312E3230392E3230372F6170692D646F63730917466972737420736F7665726569676E207570646174652E

txid: ebfaa3c2715f0e89fc188e9dc6dbaa79037458ce9058195153294b2ea3d8f118 // + Sovereign_Update
data=01000D6B6E6F776E40746162636F6E66011E687474703A2F2F37302E3235312E3230392E3230372F6170692D646F63730910536F7665726569676E5F557064617465

space-cli getptr sptr1z5fu9gsrvhgj74alq829n2z7pq6u9y5ae856gxkdxjzdk9myh50qgx5zaj | jq .
{
  "data": "01000d6b6e6f776e40746162636f6e66011e687474703a2f2f37302e3235312e3230392e3230372f6170692d646f6373",
  "id": "sptr1z5fu9gsrvhgj74alq829n2z7pq6u9y5ae856gxkdxjzdk9myh50qgx5zaj",
  "last_update": 117982,
  "n": 0,
  "parsed": {
    "records": [
      {
        "name": "Handle",
        "type": 0,
        "value": "known@tabconf"
      },
      {
        "name": "Owner URI",
        "type": 1,
        "value": "http://70.251.209.207/api-docs"
      }
    ],
    "version": 1
  },
  "script_pubkey": "51206aa95f964e571958f761906563851367d24f411ee24914f1e427ef8fed4a600c",
  "txid": "ebfaa3c2715f0e89fc188e9dc6dbaa79037458ce9058195153294b2ea3d8f118",
  "value": 1007
}

curl -X POST http://testuser:SomeRisk84@127.0.0.1:7224 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"walletsignschnorr","params":["main","@rad","48656c6c6f"],"id":1}'
