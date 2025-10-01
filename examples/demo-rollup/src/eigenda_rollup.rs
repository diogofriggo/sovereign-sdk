use std::sync::Arc;

use async_trait::async_trait;
use demo_stf::runtime::Runtime;
use sov_address::{EthereumAddress, FromVmAddress, MultiAddressEvm};
use sov_db::ledger_db::LedgerDb;
use sov_db::storage_manager::NativeStorageManager;
use sov_eigenda_adapter::service::EigenDaService;
use sov_eigenda_adapter::spec::{EigenDaSpec, RollupParams};
use sov_eigenda_adapter::verifier::EigenDaVerifier;
use sov_ethereum::EthRpcConfig;
use sov_mock_zkvm::{MockCodeCommitment, MockZkvm, MockZkvmHost};
use sov_modules_api::configurable_spec::ConfigurableSpec;
use sov_modules_api::execution_mode::Native;
use sov_modules_api::rest::StateUpdateReceiver;
use sov_modules_api::{NodeEndpoints, Spec, Storage, SyncStatus, ZkVerifier};
use sov_modules_rollup_blueprint::pluggable_traits::PluggableSpec;
use sov_modules_rollup_blueprint::proof_sender::SovApiProofSender;
use sov_modules_rollup_blueprint::{
    FullNodeBlueprint, RollupBlueprint, SequencerCreationReceipt, WalletBlueprint,
};
use sov_risc0_adapter::host::Risc0Host;
use sov_risc0_adapter::Risc0;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::execution_mode::WitnessGeneration;
use sov_rollup_interface::zk::aggregated_proof::CodeCommitment;
use sov_sequencer::{ProofBlobSender, Sequencer};
use sov_stf_runner::processes::{ParallelProverService, ProverService, RollupProverConfig};
use sov_stf_runner::RollupConfig;

use crate::{eth_dev_signer, CERT_RECENCY_WINDOW, ROLLUP_BATCH_NAMESPACE, ROLLUP_PROOF_NAMESPACE};

/// Rollup with EigenDa
#[derive(Default)]
pub struct EigenDaDemoRollup<M> {
    phantom: std::marker::PhantomData<M>,
}

type EigenDaRollupSpec<M> = ConfigurableSpec<EigenDaSpec, Risc0, MockZkvm, MultiAddressEvm, M>;

impl RollupBlueprint<Native> for EigenDaDemoRollup<Native>
where
    EigenDaRollupSpec<Native>: PluggableSpec,
    <EigenDaRollupSpec<Native> as Spec>::Address: FromVmAddress<EthereumAddress>,
{
    type Spec = EigenDaRollupSpec<Native>;
    type Runtime = Runtime<Self::Spec>;
}

impl RollupBlueprint<WitnessGeneration> for EigenDaDemoRollup<WitnessGeneration>
where
    EigenDaRollupSpec<WitnessGeneration>: PluggableSpec,
    <EigenDaRollupSpec<WitnessGeneration> as Spec>::Address: FromVmAddress<EthereumAddress>,
{
    type Spec = EigenDaRollupSpec<Native>;
    type Runtime = Runtime<Self::Spec>;
}

#[async_trait]
impl FullNodeBlueprint<Native> for EigenDaDemoRollup<Native> {
    type DaService = EigenDaService;

    type StorageManager =
        NativeStorageManager<EigenDaSpec, <EigenDaRollupSpec<Native> as Spec>::Storage>;

    type ProverService = ParallelProverService<
        <Self::Spec as Spec>::Address,
        <<Self::Spec as Spec>::Storage as Storage>::Root,
        <<Self::Spec as Spec>::Storage as Storage>::Witness,
        Self::DaService,
        <Self::Spec as Spec>::InnerZkvm,
        <Self::Spec as Spec>::OuterZkvm,
    >;

    type ProofSender = SovApiProofSender<Self::Spec>;

    fn create_outer_code_commitment(
        &self,
    ) -> <<Self::ProverService as ProverService>::Verifier as ZkVerifier>::CodeCommitment {
        MockCodeCommitment::default()
    }

    async fn create_endpoints(
        &self,
        state_update_receiver: StateUpdateReceiver<<Self::Spec as Spec>::Storage>,
        sync_status_receiver: tokio::sync::watch::Receiver<SyncStatus>,
        shutdown_receiver: tokio::sync::watch::Receiver<()>,
        ledger_db: &LedgerDb,
        sequencer: &SequencerCreationReceipt<Self::Spec>,
        _da_service: &Self::DaService,
        rollup_config: &RollupConfig<<Self::Spec as Spec>::Address, Self::DaService>,
    ) -> anyhow::Result<NodeEndpoints> {
        sov_modules_rollup_blueprint::register_endpoints::<Self, _>(
            state_update_receiver.clone(),
            sync_status_receiver,
            shutdown_receiver,
            ledger_db,
            sequencer,
            rollup_config,
        )
        .await
    }

    async fn create_da_service(
        &self,
        rollup_config: &RollupConfig<<Self::Spec as Spec>::Address, Self::DaService>,
        _shutdown_receiver: tokio::sync::watch::Receiver<()>,
    ) -> Self::DaService {
        EigenDaService::new(
            rollup_config.da.clone(),
            RollupParams {
                rollup_batch_namespace: ROLLUP_BATCH_NAMESPACE,
                rollup_proof_namespace: ROLLUP_PROOF_NAMESPACE,
                cert_recency_window: CERT_RECENCY_WINDOW,
            },
        )
        .await
        .expect("EigenDaService configuration is valid")
    }

    async fn sequencer_additional_apis<Seq>(
        &self,
        sequencer: Arc<Seq>,
        _rollup_config: &RollupConfig<<Self::Spec as Spec>::Address, Self::DaService>,
    ) -> anyhow::Result<NodeEndpoints>
    where
        Seq: Sequencer<Spec = Self::Spec, Rt = Self::Runtime, Da = Self::DaService>,
    {
        let eth_signer = eth_dev_signer();
        let eth_rpc_config = EthRpcConfig { eth_signer };

        Ok(NodeEndpoints {
            jsonrpsee_module: sov_ethereum::get_ethereum_rpc(eth_rpc_config, sequencer)
                .remove_context(),
            ..Default::default()
        })
    }

    async fn create_prover_service(
        &self,
        prover_config: RollupProverConfig<Risc0>,
        rollup_config: &RollupConfig<<Self::Spec as Spec>::Address, Self::DaService>,
        _da_service: &Self::DaService,
    ) -> Self::ProverService {
        let (elf, prover_config_disc) = prover_config.split();
        let inner_vm = Risc0Host::new(*elf);

        let outer_vm = MockZkvmHost::new_non_blocking();

        let rollup_params = RollupParams {
            rollup_batch_namespace: ROLLUP_BATCH_NAMESPACE,
            rollup_proof_namespace: ROLLUP_PROOF_NAMESPACE,
            cert_recency_window: CERT_RECENCY_WINDOW,
        };

        let da_verifier = EigenDaVerifier::new(rollup_params);

        ParallelProverService::new_with_default_workers(
            inner_vm,
            outer_vm,
            da_verifier,
            prover_config_disc,
            CodeCommitment::default(),
            rollup_config.proof_manager.prover_address,
        )
    }

    fn create_storage_manager(
        &self,
        rollup_config: &RollupConfig<<Self::Spec as Spec>::Address, Self::DaService>,
    ) -> anyhow::Result<Self::StorageManager> {
        NativeStorageManager::new(&rollup_config.storage.path)
    }

    fn create_proof_sender(
        &self,
        _rollup_config: &RollupConfig<<Self::Spec as Spec>::Address, Self::DaService>,
        sequence_number_provider: Arc<dyn ProofBlobSender>,
    ) -> anyhow::Result<Self::ProofSender> {
        Ok(Self::ProofSender::new(sequence_number_provider))
    }
}

impl WalletBlueprint<Native> for EigenDaDemoRollup<Native> {}
