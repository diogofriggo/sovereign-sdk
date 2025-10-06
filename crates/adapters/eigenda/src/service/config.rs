use core::fmt::{Debug, Formatter};

use eigenda_ethereum::provider::EigenDaProviderConfig;
use eigenda_proxy::EigenDaProxyConfig;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Configuration for the EigenDA service.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct EigenDaConfig {
    /// Private key of the sequencer. The account with corresponding private key
    /// is used by the sequencer to persist the certificates to Ethereum.
    /// Expected private key in the HEX format.
    pub signer: String,

    /// EigenDA provider configuration
    pub provider: EigenDaProviderConfig,

    /// EigenDA proxy configuration
    pub proxy: EigenDaProxyConfig,
}

impl Debug for EigenDaConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EigenDaConfig")
            .field("signer", &"[REDACTED]")
            .field("provider", &self.provider)
            .field("proxy", &self.proxy)
            .finish()
    }
}
