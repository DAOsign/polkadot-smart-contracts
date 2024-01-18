# DAOsign Ink! Proofs Smart Contracts

To learn more about repo structure read [https://docs.astar.network/docs/build/wasm/swanky-suite/cli](https://docs.astar.network/docs/build/wasm/swanky-suite/cli)

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


## Linting
```
cargo fmt
```
