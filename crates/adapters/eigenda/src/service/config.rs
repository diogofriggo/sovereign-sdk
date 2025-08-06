use schemars::JsonSchema;

use crate::spec::EthereumAddress;

/// Configuration for the [`crate::service::EigenDaService`].
#[derive(Debug, JsonSchema, PartialEq)]
pub struct EigenDaConfig {
    /// URL of the Ethereum RPC node.
    pub ethereum_rpc_url: String,
    /// The number of compute units per second for the provider. Used in cases
    /// when the Ethereum node is hosted at providers like Alchemy that track
    /// compute units used when making a requests. If None, it means the node is
    /// not tracking compute units.
    pub ethereum_compute_units: Option<u64>,
    /// The maximal number of times we retry requests to the node before
    /// returning the error.
    pub ethereum_max_retry_times: Option<u32>,
    /// The initial backoff in milliseconds used when retrying Ethereum
    /// requests. It is increased on each subsequent retry.
    pub ethereum_initial_backoff: Option<u64>,
    /// Maximal number of responses that the cache stores. The
    pub ethereum_max_cache_items: Option<u32>,
    /// URL of the EigenDA proxy node.
    pub proxy_url: String,
    /// The initial backoff in milliseconds used when retrying EigenDA proxy
    /// requests. It is increased on each subsequent retry.
    pub proxy_min_retry_delay: Option<u64>,
    /// The maximal backoff in milliseconds used when retrying EigenDA proxy requests.
    pub proxy_max_retry_delay: Option<u64>,
    /// The maximal number of times we retry requests to the EigenDA proxy
    /// before returning the error.
    pub proxy_max_retry_times: Option<u64>,
    /// Private key of the sequencer. The account with corresponding private key
    /// is used by the sequencer to persist the certificates to Ethereum.
    /// Expected private key in the HEX format.
    pub sequencer_signer: String,
    /// EigenDA relevant contracts.
    pub contracts: EigenDaContracts,
}

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
