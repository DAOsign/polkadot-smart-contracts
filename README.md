# DAOsign Ink! Proofs Smart Contracts

## Overview
DAOsign is a decentralized platform for agreements with publicly verifiable and authorized cryptographic proofs-of-signature designed for DAOs. For a more in-depth overview of DAOsign proofs, you can refer to [this document](./docs/DAOsign%20Proofs%20Technical%20Design.pdf).

This repository contains two smart contracts:
- <a href="./contracts/daosign_app/" target="_blank">DAOsign App</a>
- <a href="./contracts/daosign_eip712/" target="_blank">DAOsign EIP712</a>

### DAOsign EIP712
DAOsign EIP712 is a helper contract used by the DAOsign App contract, facilitating the verification of EIP-712 signatures tailored specifically to the DAOsign App contract.

### DAOsign App
Meanwhile, the DAOsign App contract is the primary DAOsign smart contract that stores all proofs: Proof-of-Authority, Proof-of-Signature, and Proof-of-Agreement. This contract also allows users to validate DAOsign-generated proofs.

## Table of Contents
- [DAOsign Ink! Proofs Smart Contracts](#daosign-ink-proofs-smart-contracts)
  - [Overview](#overview)
    - [DAOsign EIP712](#daosign-eip712)
    - [DAOsign App](#daosign-app)
  - [Table of Contents](#table-of-contents)
  - [Docs](#docs)
  - [How to Use These Contracts for DAOsign Proofs Verification](#how-to-use-these-contracts-for-daosign-proofs-verification)
    - [Ensure that the proof was stored on Polkadot](#ensure-that-the-proof-was-stored-on-polkadot)
    - [Open a deployed DAOsign App in a block explorer and locate the desired `validate` function](#open-a-deployed-daosign-app-in-a-block-explorer-and-locate-the-desired-validate-function)
    - [Call the desired validate function with signed proof data as a function parameter](#call-the-desired-validate-function-with-signed-proof-data-as-a-function-parameter)
  - [Prerequisites](#prerequisites)
    - [Install Dependencies](#install-dependencies)
    - [Build](#build)
  - [Testing](#testing)
    - [Unit Tests](#unit-tests)
      - [DAOsign App](#daosign-app-1)
      - [DAOsign EIP712](#daosign-eip712-1)
    - [Integration Tests](#integration-tests)
    - [With Docker](#with-docker)
    - [Locally](#locally)
  - [Other](#other)
    - [Developer Docs](#developer-docs)
    - [Linting](#linting)

## Docs
Documentation is located at https://daosign.github.io/polkadot-smart-contracts/daosign_app.
To see the docs directly for each contract, please follow these links:
- <a href="https://daosign.github.io/polkadot-smart-contracts/daosign_app/daosign_app/struct.DAOsignApp.html" target="_blank">DAOsign App</a>
- <a href="https://daosign.github.io/polkadot-smart-contracts/daosign_eip712/daosign_eip712/struct.DAOsignEIP712.html" target="_blank">DAOsign EIP712</a>

## How to Use These Contracts for DAOsign Proofs Verification
To validate a DAOsign-generated proof, follow these steps:

### Ensure that the proof was stored on Polkadot
If an agreement creator has chosen to store agreement proofs on another chain or only in IPFS, you can validate only Proof-of-Authority. This is because Proof-of-Signature and Proof-of-Agreement have links to Proof-of-Authority, so it must be stored in the smart contract to validate them.

### Open a deployed DAOsign App in a block explorer and locate the desired `validate` function
There are three validate functions (one for each proof): `validate_signed_proof_of_authority`, `validate_signed_proof_of_signature`, and `validate_signed_proof_of_agreement`.

### Call the desired validate function with signed proof data as a function parameter
The output of this function will be either `true` - the proof is valid, or `false` - the proof is invalid. If you have an invalid proof, don't hesitate to [open an issue](https://github.com/DAOsign/polkadot-smart-contracts/issues) and our team will do our best to solve the problem.

## Prerequisites

To get started with the project, you should first follow a few steps. After cloning this repository, open your Terminal and navigate to the project root. From there, run the following commands one by one.

### Install Dependencies
```
npm i
```

### Build
```
npm run build
```

## Testing

DAOsign features three ways of ensuring contract quality:

- Unit tests for every smart contract
- Integration tests to be run both locally and with a dedicated Docker file
- Manual review of the code

### Unit Tests
Our unit tests are located within each of the contract's own files.

These unit tests cover every single Ink! function inside every contract to ensure contracts code quality.

You can test each smart contract from its directory by running `cargo test` command.

The full step-by-step guide to run unit tests is as follows:

1. In the root directory of the project, open a Terminal and run `cd contracts/<daosign_app|daosign_eip712>` to go to the subdirectory of the contract you want to run tests for.
2. Once in directory, run `cargo test` to run unit tests for this contract or `cargo test -- --nocapture` to both run the unit tests and see `debug_println!` output (used for development purposes).

Note: to run unit tests for `daosign_eip712`, one has to comment out the following `derive` in the `contracts/daosign_eip712/lib.rs` file:
```
#[ink(storage)]
// #[derive(Debug)]
pub struct DAOsignEIP712 {
```

The expected output of the unit tests is the following:

#### DAOsign App
```
    Finished test [unoptimized + debuginfo] target(s) in 0.11s
     Running unittests src/lib.rs (/Users/mkushka/Documents/Work/CIDT/projects/daosign/polkadot-smart-contracts/target/debug/deps/daosign_app-ac3157320f39121e)

running 6 tests
test daosign_app::tests::test_get_proof_of_authority ... ok
test daosign_app::tests::test_store_proof_of_authority ... ok
test daosign_app::tests::test_get_proof_of_signature ... ok
test daosign_app::tests::test_store_proof_of_signature ... ok
test daosign_app::tests::test_get_proof_of_agreement ... ok
test daosign_app::tests::test_store_proof_of_agreement ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests daosign_app

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

#### DAOsign EIP712
```
    Finished test [unoptimized + debuginfo] target(s) in 0.05s
     Running unittests src/lib.rs (/Users/mkushka/Documents/Work/CIDT/projects/daosign/polkadot-smart-contracts/target/debug/deps/daosign_eip712-a4f3a41616886efa)

running 8 tests
test daosign_eip712::tests::hash_proof_of_signature ... ok
test daosign_eip712::tests::constructor ... ok
test daosign_eip712::tests::hash_proof_of_authority ... ok
test daosign_eip712::tests::hash_proof_of_agreement ... ok
test daosign_eip712::tests::recover_proof_of_signature ... ok
test daosign_eip712::tests::recover_proof_of_agreement ... ok
test daosign_eip712::tests::recover_proof_of_authority ... ok
test daosign_eip712::tests::recover ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests daosign_eip712

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Integration Tests

To use integration tests not only for Ink! but for other languages as well, we have decided to use Typescript for this purpose. The framework that allowed that is Swanky Suite about which you can read more [here](https://docs.astar.network/docs/build/wasm/swanky-suite/cli).

For the convenience of the end-user, we have provided two ways to run integration tests: with Docker or locally. A more detailed description of how to do that please see below.

### With Docker
Running tests with Docker is easy but to do that you want to make sure you have Docker installed on your computer, and it's running.

To run integration tests with Docker, you should follow 3 easy steps.

1. Firstly, you have to build the Docker image. To do that, in the root folder of the project, open a Terminal and run `docker build -t daosign-proofs .`
2. Secondly, run the image that will contain the project with all environment set up for you. Just run `docker run -d -p 9944:9944 --name daosign-proofs daosign-proofs` in your Terminal.
3. Lastly, in the Terminal run `docker exec -it daosign-proofs npm run test` to execute integration tests.

The expected output should be the following:

```
DAOsignApp Tests
    Lifecycle
      ✔ #1 (107ms)


  1 passing (565ms)
```

### Locally
What can be run with Docker can also be replicated locally. To run integration tests locally you should:

1. To start with, you should install a local node binary file by running in the Terminal from the root of the project `npm run node:install`.
2. Then, from the root directory start a local node with `npm run node:start` command. This should start a local Polkadot node that may look like the following:
```
2024-01-25 10:23:51 Swanky Node    
2024-01-25 10:23:51 ✌️  version 1.6.0-e5e6b8f914b    
2024-01-25 10:23:51 ❤️  by Astar Network, 2022-2024    
2024-01-25 10:23:51 📋 Chain specification: Development    
2024-01-25 10:23:51 🏷  Node name: soggy-border-9490    
2024-01-25 10:23:51 👤 Role: FULL    
2024-01-25 10:23:51 💾 Database: RocksDb at /Users/mkushka/Library/Application Support/swanky-node/chains/dev/db/full    
2024-01-25 10:23:51 ⛓  Native runtime: swanky-node-3 (swanky-node-1.tx1.au1)    
2024-01-25 10:23:51 Using default protocol ID "sup" because none is configured in the chain specs    
2024-01-25 10:23:51 🏷  Local node identity is: 12D3KooWSfyJajqMrzkMN2okFREr8SLsGj2aprq6R8jvkV3x4m7H    
2024-01-25 10:23:51 💻 Operating system: macos    
2024-01-25 10:23:51 💻 CPU architecture: aarch64    
2024-01-25 10:23:51 📦 Highest known block at #266    
2024-01-25 10:23:51 〽️ Prometheus exporter started at 127.0.0.1:9615    
2024-01-25 10:23:51 Running JSON-RPC HTTP server: addr=127.0.0.1:9933, allowed origins=["http://localhost:*", "http://127.0.0.1:*", "https://localhost:*", "https://127.0.0.1:*", "https://polkadot.js.org", "https://contracts-ui.substrate.io/"]    
2024-01-25 10:23:51 Running JSON-RPC WS server: addr=127.0.0.1:9944, allowed origins=["http://localhost:*", "http://127.0.0.1:*", "https://localhost:*", "https://127.0.0.1:*", "https://polkadot.js.org", "https://contracts-ui.substrate.io/"]    
2024-01-25
```
3. Lastly, to run integration tests, open a new tab in your Terminal (make sure you're still in the root directory of the project), and simply run the `npm test` command. The output you should see is the same of the running tests in Docker.

## Other

### Developer Docs
To see the developer docs in your browser simply run:
```
npm run docs
```

### Linting
To unify the code style in the project run:
```
cargo fmt
```
