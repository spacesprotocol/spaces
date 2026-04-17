# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## [0.1.0](https://github.com/spacesprotocol/spaces/releases/tag/spaces_client-v0.1.0) - 2026-04-17

### Bug Fixes

- Fix cookie on first run
- Fix list_wallets for no wallets

### Build

- Builder httpclient for auth

### Chore

- Set up release-plz and strict CI

### Getblockmeta

- Allow request by height ([#73](https://github.com/spacesprotocol/spaces/pull/73))

### Style

- Fix clippy 1.95 warnings from collapsible_if and related lints
- Apply rustfmt to later edits missed by initial pass
