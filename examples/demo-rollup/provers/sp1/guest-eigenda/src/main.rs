#![no_main]
sp1_zkvm::entrypoint!(main);

use demo_stf::runtime::Runtime;
use demo_stf::StfVerifier;
use sov_address::MultiAddressEvm;
use sov_eigenda_adapter::spec::{EigenDaSpec, NamespaceId, RollupParams};
use sov_eigenda_adapter::verifier::EigenDaVerifier;
use sov_mock_zkvm::MockZkvm;
use sov_modules_api::configurable_spec::ConfigurableSpec;
use sov_modules_api::execution_mode::Zk;
use sov_modules_api::macros::config_value;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_rollup_interface::da::DaVerifier;
use sov_sp1_adapter::guest::SP1Guest;
use sov_sp1_adapter::SP1;
use sov_state::ZkStorage;

pub const EIGENDA_ROLLUP_BATCH_NAMESPACE: NamespaceId =
    NamespaceId::from_bytes(config_value!("EIGENDA_BATCH_NAMESPACE"));
pub const EIGENDA_ROLLUP_PROOF_NAMESPACE: NamespaceId =
    NamespaceId::from_bytes(config_value!("EIGENDA_PROOF_NAMESPACE"));
pub const EIGENDA_CERT_RECENCY_WINDOW: u64 = config_value!("EIGENDA_CERT_RECENCY_WINDOW");

pub fn main() {
    let guest = SP1Guest::new();
    let storage = ZkStorage::new();
    let stf: StfBlueprint<
        ConfigurableSpec<EigenDaSpec, SP1, MockZkvm, MultiAddressEvm, Zk>,
        Runtime<_>,
    > = StfBlueprint::new();

    let rollup_params = RollupParams {
        rollup_batch_namespace: EIGENDA_ROLLUP_BATCH_NAMESPACE,
        rollup_proof_namespace: EIGENDA_ROLLUP_PROOF_NAMESPACE,
        cert_recency_window: EIGENDA_CERT_RECENCY_WINDOW,
    };

    let stf_verifier =
        StfVerifier::<_, _, _, SP1, MockZkvm>::new(stf, EigenDaVerifier::new(rollup_params));

    stf_verifier
        .run_block(guest, storage)
        .expect("Prover must be honest");
}
