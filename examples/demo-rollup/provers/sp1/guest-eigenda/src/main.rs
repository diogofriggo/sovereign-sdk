#![no_main]
sp1_zkvm::entrypoint!(main);

use const_rollup_config::{
    CERT_RECENCY_WINDOW, ROLLUP_BATCH_NAMESPACE_RAW, ROLLUP_PROOF_NAMESPACE_RAW,
};
use demo_stf::StfVerifier;
use demo_stf::runtime::Runtime;
use sov_address::MultiAddressEvm;
use sov_eigenda_adapter::spec::{EigenDaSpec, NamespaceId, RollupParams};
use sov_eigenda_adapter::verifier::EigenDaVerifier;
use sov_mock_zkvm::MockZkvm;
use sov_modules_api::configurable_spec::ConfigurableSpec;
use sov_modules_api::execution_mode::Zk;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_rollup_interface::da::DaVerifier;
use sov_sp1_adapter::SP1;
use sov_sp1_adapter::guest::SP1Guest;
use sov_state::ZkStorage;

pub fn main() {
    let guest = SP1Guest::new();
    let storage = ZkStorage::new();
    let stf: StfBlueprint<
        ConfigurableSpec<EigenDaSpec, SP1, MockZkvm, MultiAddressEvm, Zk>,
        Runtime<_>,
    > = StfBlueprint::new();

    let rollup_params = RollupParams {
        rollup_batch_namespace: NamespaceId::from(ROLLUP_BATCH_NAMESPACE_RAW),
        rollup_proof_namespace: NamespaceId::from(ROLLUP_PROOF_NAMESPACE_RAW),
        cert_recency_window: CERT_RECENCY_WINDOW,
    };

    let stf_verifier =
        StfVerifier::<_, _, _, SP1, MockZkvm>::new(stf, EigenDaVerifier::new(rollup_params));

    stf_verifier
        .run_block(guest, storage)
        .expect("Prover must be honest");
}
