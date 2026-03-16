use bitcoin::Network;

pub const PTR_MAINNET_HEIGHT : u32 = 922_777;
pub const PTR_TESTNET4_HEIGHT : u32 = 100_008;
pub const PTR_REGTEST_HEIGHT : u32 = 0;

pub const COMMITMENT_FINALITY_INTERVAL : u32 = 144;

pub fn ptrs_start_height(network: &Network) -> u32 {
    match network {
        Network::Bitcoin => PTR_MAINNET_HEIGHT,
        Network::Testnet => PTR_TESTNET4_HEIGHT,
        Network::Regtest => PTR_REGTEST_HEIGHT,
        _ => panic!("unsupported network {}", network)
    }
}
