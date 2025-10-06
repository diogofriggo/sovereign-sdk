pub mod proxy;
pub mod tracing;

use std::str::FromStr;

use eigenda_ethereum::provider::EigenDaProviderConfig;
use eigenda_ethereum::provider::Network;
use eigenda_proxy::EigenDaProxyConfig;
use sov_eigenda_adapter::service::config::EigenDaConfig;
use sov_eigenda_adapter::service::{EigenDaService, EigenDaServiceError};
use sov_eigenda_adapter::spec::{NamespaceId, RollupParams};
use sov_eigenda_adapter::verifier::EigenDaVerifier;
use sov_rollup_interface::da::DaVerifier;

pub static SEQUENCER_SIGNER: &str =
    "0x354945e623e9a9070ef2be9dec2a71c49784a6e8348f4bfb6ace91622df91d83";
pub static ROLLUP_BATCH_NAMESPACE: &str = "0xaa20cC3C0Cae6aDC23659aE5E8488dE2098932ab";
pub static ROLLUP_PROOF_NAMESPACE: &str = "0xbb7F59238c5FEe337c003dfae48f5d04C1307AC9";
pub static CERT_RECENCY_WINDOW: u64 = 3200;

pub async fn setup_adapter(
    url: String,
) -> Result<(EigenDaService, EigenDaVerifier), EigenDaServiceError> {
    let config = EigenDaConfig {
        signer: SEQUENCER_SIGNER.to_string(),
        provider: EigenDaProviderConfig {
            network: Network::Sepolia,
            rpc_url: "wss://ethereum-sepolia-rpc.publicnode.com".to_string(),
            compute_units: None,
            max_retry_times: None,
            initial_backoff: None,
        },
        proxy: EigenDaProxyConfig {
            url,
            min_retry_delay: None,
            max_retry_delay: None,
            max_retry_times: None,
        },
    };
    let params = RollupParams {
        rollup_batch_namespace: NamespaceId::from_str(ROLLUP_BATCH_NAMESPACE).unwrap(),
        rollup_proof_namespace: NamespaceId::from_str(ROLLUP_PROOF_NAMESPACE).unwrap(),
        cert_recency_window: CERT_RECENCY_WINDOW,
    };

    let service = EigenDaService::new(config, params).await?;
    let verifier = EigenDaVerifier::new(params);

    Ok((service, verifier))
}
