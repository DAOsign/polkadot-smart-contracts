# DAOsign Ink! Proofs Smart Contracts

To learn more about repo structure read [https://docs.astar.network/docs/build/wasm/swanky-suite/cli](https://docs.astar.network/docs/build/wasm/swanky-suite/cli)

## Build and Run with Docker
1. `docker build -t daosign-proofs .`
2. `docker run -d -p 9944:9944 --name daosign-proofs daosign-proofs`
3. `docker exec -it daosign-proofs npm run test`

### Install Dependencies
```
npm i
```

### Build
```
npm run build
```

### E2E Tests (Typescript)

1. Download `swanky-node` from [here](https://github.com/inkdevhub/swanky-node/releases) and put it in the project's `bin` folder.
2. Install node file with `npm run node:install`
3. Start a node with `npm run node:start`
4. Test with `npm run test`

### Unit Tests (Rust)
1. `npm run build`
2. `cd contracts/<daosign_app|daosign_eip712>`
3. `cargo test` to test or `cargo test -- --nocapture` to test and see `debug_println!` output

### Lint (Rust)
```
cargo fmt
```
