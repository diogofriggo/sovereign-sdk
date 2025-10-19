//! A simple rollup that uses the Sovereign SDK.
//!
//! See the README for more information.
// TODO: #![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::str::FromStr;

use sov_celestia_adapter::types::Namespace;
use sov_modules_api::macros::config_value;

mod mock_rollup;
pub use mock_rollup::*;

mod mock_nomt_rollup;
pub use mock_nomt_rollup::*;

mod external_mock_rollup;
pub use external_mock_rollup::*;

mod celestia_rollup;
pub use celestia_rollup::*;

mod celestia_nomt_rollup;
pub use celestia_nomt_rollup::*;

mod eigenda_rollup;
pub use eigenda_rollup::*;

mod eigenda_nomt_rollup;
pub use eigenda_nomt_rollup::*;

mod zk;
use sov_eigenda_adapter::spec::NamespaceId;
pub use zk::*;

/// The Celestia namespace where the rollup stores its data
/// You can change this constant by modifying CELESTIA_BATCH_NAMESPACE in constants.toml
pub const CELESTIA_ROLLUP_BATCH_NAMESPACE: Namespace =
    Namespace::const_v0(config_value!("CELESTIA_BATCH_NAMESPACE"));

/// The Celestia namespace where the rollup stores zk proofs in
/// You can change this constant by modifying CELESTIA_PROOF_NAMESPACE in constants.toml
pub const CELESTIA_ROLLUP_PROOF_NAMESPACE: Namespace =
    Namespace::const_v0(config_value!("CELESTIA_PROOF_NAMESPACE"));

/// The EigenDA namespace where the rollup stores its data
/// You can change this constant by modifying EIGENDA_BATCH_NAMESPACE in constants.toml
pub const EIGENDA_ROLLUP_BATCH_NAMESPACE: NamespaceId =
    NamespaceId::from_bytes(config_value!("EIGENDA_BATCH_NAMESPACE"));

/// The EigenDA namespace where the rollup stores zk proofs in
/// You can change this constant by modifying EIGENDA_PROOF_NAMESPACE in constants.toml
pub const EIGENDA_ROLLUP_PROOF_NAMESPACE: NamespaceId =
    NamespaceId::from_bytes(config_value!("EIGENDA_PROOF_NAMESPACE"));

/// Recency window of an EigenDa certificaten, used for certificate verification
pub const EIGENDA_CERT_RECENCY_WINDOW: u64 = config_value!("EIGENDA_CERT_RECENCY_WINDOW");

// TODO: https://github.com/Sovereign-Labs/sovereign-sdk-wip/issues/387
fn eth_dev_signer() -> sov_ethereum::Signers {
    sov_ethereum::Signers::new(vec![secp256k1::SecretKey::from_str(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )
    .unwrap()])
}
