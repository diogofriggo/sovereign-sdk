use schemars::JsonSchema;

use crate::spec::EthereumAddress;

/// EigenDA relevant contracts.
#[derive(Debug, Clone, JsonSchema, PartialEq)]
pub struct EigenDaContracts {
    // TODO: Docs
    pub registry_coordinator: EthereumAddress,
    // TODO: Docs
    pub delegation_manager: EthereumAddress,
    // TODO: Docs
    pub bls_apt_registry: EthereumAddress,
    // TODO: Docs
    pub stake_registry: EthereumAddress,
}

/// Configuration for the [`EigenDaService`].
#[derive(Debug, JsonSchema, PartialEq)]
pub struct EigenDaConfig {
    /// URL of the Ethereum RPC node.
    pub ethereum_rpc_url: String,
    /// URL of the EigenDA proxy node.
    pub proxy_url: String,
    /// Private key of the sequencer. The account with corresponding private key
    /// is used by the sequencer to persist the certificates to Ethereum.
    /// Expected private key in the HEX format.
    pub sequencer_signer: String,
    /// EigenDA relevant contracts.
    pub contracts: EigenDaContracts,
}
