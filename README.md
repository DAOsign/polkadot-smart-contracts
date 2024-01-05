# DAOsign Ink! Proofs Smart Contracts

To learn more about repo structure read [https://docs.astar.network/docs/build/wasm/swanky-suite/cli](https://docs.astar.network/docs/build/wasm/swanky-suite/cli)

## Build and Run with Docker
1. `docker build -t daosign-proofs .`
2. `docker run -d -p 9944:9944 --name daosign-proofs daosign-proofs`
3. `docker exec -it daosign-proofs yarn test`

### Install Dependencies
```
yarn
```

### Build
```
yarn build
```

### E2E Tests (Typescript)

1. Start a node with `yarn node`
2. Test with `yarn test`

### Unit Tests (Rust)
1. `yarn build`
2. `cd contracts/<daosign_app|daosign_eip712>`
3. `cargo test` to test or `cargo test -- --nocapture` to test and see `debug_println!` output

### Lint (Rust)
```
cargo fmt
```
