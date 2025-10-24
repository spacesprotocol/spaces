# Spaces on Bitcoin

Checkout [releases](https://github.com/spacesprotocol/spaces/releases) for an immediately usable binary version of this software.


## Work on Subspaces

Spaces is live on mainnet. Subspaces is live on testnet4, and development work is happening on the [subspaces branch](https://github.com/spacesprotocol/spaces/tree/subspaces).


## What does it do?

Spaces are sovereign Bitcoin identities. They leverage the existing infrastructure and security of Bitcoin without requiring a new blockchain or any modifications to Bitcoin itself [learn more](https://spacesprotocol.org).

`spaced` is a tiny layer that connects to Bitcoin Core over RPC and scans transactions relevant to the protocol.

`space-cli` is a Bitcoin wallet that supports opening auctions, bidding and registering spaces.

## Quick Start

Paste the following into your terminal to install the latest version of Spaces:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://install.spacesprotocol.org | sh
```

## Documentation

Visit [docs](https://spacesprotocol.org/) to learn how to get started.


## Build from source

To build it from source:

```sh
git clone https://github.com/spacesprotocol/spaced && cd spaced
cargo install --path client --locked
```

Make sure it's in your path

```sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Verify installation

```
spaced --version
space-cli --version
```

## Development setup on testnet4

### Setup

First, download Bitcoin Core and set it up to connect to `testnet4` using these steps:

```sh
mkdir $HOME/bitcoin-testnet4

# Create a configuration file with RPC credentials
echo "rpcuser=testnet4" > $HOME/bitcoin-testnet4/bitcoin.conf
echo "rpcpassword=testnet4" >> $HOME/bitcoin-testnet4/bitcoin.conf

# Start Bitcoin Core specifying testnet4 network
bitcoind -testnet4 -datadir=$HOME/bitcoin-testnet4
```

Next, run spaced with the following:
```sh
spaced --chain testnet4 --bitcoin-rpc-user testnet4 --bitcoin-rpc-password testnet4
```

## Project Structure


| Package  | Requires std    | Description                                                                                     |
|----------|-----------------|-------------------------------------------------------------------------------------------------|
| client   | Yes             | Bitcoin consensus client and wallet service                                                     |
| wallet   | Yes (no-std WIP) | Wallet library for building spaces transactions                                                 |
| protocol | No              | Protocol consensus library                                                                      |
| veritas  | No              | Stateless verifier library for mobile and other resource constrained devices with wasm support. | 



## License

Spaces is released under the terms of the MIT license. See LICENSE for more information or see https://opensource.org/licenses/MIT.
