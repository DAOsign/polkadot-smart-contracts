# polkadot-smart-contracts

## How to use repo
Read: [https://docs.astar.network/docs/build/wasm/swanky-suite/cli](https://docs.astar.network/docs/build/wasm/swanky-suite/cli)

## Lint
```
cargo fmt
```

## Build
```
yarn build
```

## E2E Tests (Typescript)

1. Start a node with `yarn node`
2. Test with `yarn test`

## Unit Tests (Rust)
`cargo test` to test or `cargo test -- --nocapture` to test and see `debug_println!` output
