# Demo Rollup ![Time - ~5 mins](https://img.shields.io/badge/Time-~5_mins-informational)

This is a demo full node running a simple Sovereign SDK rollup on [EigenDA](https://www.eigenda.xyz/) testnet.

<p align="center">
  <img width="50%" src="../../docs/assets/discord-banner.png">
  <br>
  <i>Stuck, facing problems, or unsure about something?</i>
  <br>
  <i>Join our <a href="https://discord.gg/kbykCcPrcA">Discord</a> and ask your questions in <code>#support</code>!</i>
</p>

## What is This?

This demo shows how to integrate a State Transition Function (STF) with a Data Availability (DA) layer. The code in this repository corresponds to running a full-node of the rollup, which executes every transaction.

By swapping out or modifying the imported state transition function, you can customize this example full-node to run arbitrary logic. This particular example relies on the state transition exported by [`demo-stf`](../demo-rollup/stf/). If you want to understand how to build your own state transition function, check out at the docs in that package.

### Configure the rollup

Update the `[da]` section in the `examples/demo-rollup/eigenda_rollup_config.toml`.

Update the `ROLLUP_BATCH_NAMESPACE_RAW` and `ROLLUP_PROOF_NAMESPACE_RAW` in `examples/const-rollup-config/src/lib.rs` to some arbitrary addresses that are going to be used as a namespaces for the blobs.

Update the `genesis_height` in `examples/demo-rollup/eigenda_rollup_config.toml` and `genesis_da_height` in `examples/test-data/genesis/demo/eigenda/chain_state.json`. The new value should be the block height of the **finalized** block on the Ethereum.

### Start the Rollup Full Node

Make sure you're still in the `examples/demo-rollup` directory. 

Delete any existing data:
```
make clean
```

Before starting the node ensure that the EigenDa proxy is running (make sure to [deposit ETH in the payment vault contract](https://docs.eigencloud.xyz/products/eigenda/integrations-guides/quick-start/v2/#on-chain-setup) for on-demand dispersals):

```bash
docker run --rm -d -p 3100:3100 ghcr.io/layr-labs/eigenda-proxy:2.2.1 --storage.dispersal-backend v2 --storage.backends-to-enable v2 --eigenda.v2.network sepolia_testnet --eigenda.v2.cert-verifier-router-or-immutable-verifier-addr 0x58D2B844a894f00b7E6F9F492b9F43aD54Cd4429 --eigenda.v2.eth-rpc wss://ethereum-sepolia-rpc.publicnode.com --eigenda.v2.signer-payment-key-hex <KEY_WITH_DEPOSIT_IN_PAYMENT_VAULT>
```

Now run the demo-rollup full node, as shown below. You will see it consuming blocks. The node can be executed in three different modes.

Run the node with proving skipped:
```sh
SKIP_GUEST_BUILD=true SOV_PROVER_MODE=skip cargo run --release
```

Run the rollup verifier in a zkVM executor.
```sh
SOV_PROVER_MODE=execute cargo run --release
```

Run the rollup verifier and create a SNARK of execution.
```sh
SOV_PROVER_MODE=prove cargo run --release
```
