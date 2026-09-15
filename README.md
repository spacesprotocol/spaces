# Spaces on Bitcoin

Checkout [releases](https://github.com/spacesprotocol/spaces/releases) for an immediately usable binary version of this software.


## What does it do?

Spaces are sovereign Bitcoin identities. They leverage the existing infrastructure and security of Bitcoin without requiring a new blockchain or any modifications to Bitcoin itself [learn more](https://spacesprotocol.org).

`spaced` is a tiny layer that connects to Bitcoin Core over RPC and scans transactions relevant to the protocol.

`space-cli` is a Bitcoin wallet that supports opening auctions, bidding and registering spaces.

## Quick Start

Paste the following into your terminal to install the latest version of Spaces:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://get.spacesprotocol.org | sh
```

## Documentation

Visit [docs](https://spacesprotocol.org/) to learn how to get started.


## Build from source

To build it from source:

```sh
git clone https://github.com/spacesprotocol/spaces && cd spaces
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

## Running

`spaced` connects to a Bitcoin Core node over RPC. Start Bitcoin Core with RPC
credentials configured, then run:

```sh
spaced --bitcoin-rpc-user <user> --bitcoin-rpc-password <password>
```

It defaults to `mainnet`; pass `--chain <network>` to use another network. See the
[docs](https://spacesprotocol.org/) for full setup.

## Project Structure


| Package     | Description                                                            |
|-------------|-----------------------------------------------------------------------|
| client      | Spaces client (`spaced`) and CLI (`space-cli`)                        |
| wallet      | Wallet library for building spaces transactions                       |
| protocol    | Core protocol types and consensus rules                               |
| nums        | Numeric identifier extension                                          |
| sip7        | Signed Inscribed Packets (SIP-7): signed resource-record payloads     |
| borsh_utils | Borsh serialization helpers for Bitcoin primitives                    |
| checkpoint  | Checkpoint loader and builder                                         |



## License

Spaces is released under the terms of the MIT license. See LICENSE for more information or see https://opensource.org/licenses/MIT.
