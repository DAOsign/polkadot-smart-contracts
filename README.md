# DAOsign Ink! Proofs Smart Contracts

## Overview
DAOsign is a decentralized platform for agreements with publicly verifiable and authorized cryptographic proofs-of-signature designed for DAOs. For a more in-depth overview of DAOsign proofs, you can refer to [this document](./docs/DAOsign%20Proofs%20Technical%20Design.pdf).

## How to Use These Contracts for DAOsign Proofs Verification
There are two contracts in this repository:
- [DAOsign EIP712](./contracts/daosign_eip712/)
- [DAOsign App](./contracts/daosign_app/)

DAOsign EIP712 is a helper contract used by the DAOsign App contract, facilitating the verification of EIP-712 signatures tailored specifically to the DAOsign App contract.

Meanwhile, the DAOsign App contract is the primary DAOsign smart contract that stores all proofs: Proof-of-Authority, Proof-of-Signature, and Proof-of-Agreement. This contract also allows users to validate DAOsign-generated proofs.

To validate a DAOsign-generated proof, follow these steps:
1. **Ensure that the proof was stored on Polkadot.** If an agreement creator has chosen to store agreement proofs on another chain or only in IPFS, you can validate only Proof-of-Authority. This is because Proof-of-Signature and Proof-of-Agreement have links to Proof-of-Authority, so it must be stored in the smart contract to validate them.
2. **Open a deployed DAOsign App in a block explorer and locate the desired `validate` function.** There are three validate functions (one for each proof): `validate_signed_proof_of_authority`, `validate_signed_proof_of_signature`, and `validate_signed_proof_of_agreement`.
3. **Call the desired validate function with signed proof data as a function parameter.** The output of this function will be either `true` - the proof is valid, or `false` - the proof is invalid. If you have an invalid proof, don't hesitate to contact [DAOsign support](https://daosign.org/#contactus) to resolve the issue.

## Prerequisites

### Install Dependencies
```
npm i
```

### Build
```
npm run build
```

## Test

### Build and Test with Docker
1. `docker build -t daosign-proofs .`
2. `docker run -d -p 9944:9944 --name daosign-proofs daosign-proofs`
3. `docker exec -it daosign-proofs npm run test`

### E2E Tests (Typescript)
1. Install loclal node binary file with `npm run node:install`
2. Start a local node with `npm run node:start`
3. Test with `npm run test`

### Unit Tests (Rust)
1. `cd contracts/<daosign_app|daosign_eip712>`
2. `cargo test` to test or `cargo test -- --nocapture` to test and see `debug_println!` output

Note: to run unit tests for `daosign_eip712`, one has to comment out the following `derive`:
```
#[ink(storage)]
// #[derive(Debug)]
pub struct DAOsignEIP712 {
```


## Other

### Developer Docs
To see developer docs in your browser simply run:
```
npm run docs
```

### Linting
```
cargo fmt
```

### Project Structure
To learn more about repo structure read [https://docs.astar.network/docs/build/wasm/swanky-suite/cli](https://docs.astar.network/docs/build/wasm/swanky-suite/cli).
