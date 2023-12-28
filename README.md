# polkadot-smart-contracts

## How to use repo
Read: [https://docs.astar.network/docs/build/wasm/swanky-suite/cli](https://docs.astar.network/docs/build/wasm/swanky-suite/cli)

## Lint
```
cargo fmt
```

## Build
```
cargo contract build
```

## Test
Normal
```
cargo test
```

With `debug_println!` output
```
cargo test -- --nocapture
```