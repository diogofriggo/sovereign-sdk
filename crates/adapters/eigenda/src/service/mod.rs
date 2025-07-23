pub mod config;
mod ethereum;

pub use crate::eigenda::types::{StandardCommitment, StandardCommitmentParseError};
use crate::service::config::{EigenDaConfig, EigenDaContracts};
use crate::spec::EthereumAddress;

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use alloy_consensus::{SidecarBuilder, SimpleCoder};
use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_network::TransactionBuilder;
use alloy_network::TransactionBuilder4844;
use alloy_primitives::B256;
use alloy_provider::Provider;
use alloy_provider::{DynProvider, ProviderBuilder};
use alloy_rpc_types_eth::Transaction;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use alloy_transport::{RpcError, TransportErrorKind};
use async_trait::async_trait;
use futures::future::{join_all, try_join4};
use reth_trie_common::AccountProof;
use reth_trie_common::proof::ProofVerificationError;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{BlobReaderTrait, DaProof};
use sov_rollup_interface::{
    common::HexHash,
    da::{BlockHeaderTrait, DaSpec, RelevantBlobs, RelevantProofs, Time},
    node::da::{DaService, SlotData, SubmitBlobReceipt},
};
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::time::sleep;
use tracing::{debug, instrument, warn};

use crate::eigenda::proxy::{ProxyClient, ProxyError};
use crate::service::ethereum::extract_certificate;
use crate::spec::{Blob, BlobWithSender, NamespaceId, RollupParams, TransactionWithBlob};
use crate::verifier::{EigenDaCompletenessProof, EigenDaInclusionProof};
use crate::{
    spec::{EigenDaSpec, EthereumBlockHeader, EthereumHash},
    verifier::EigenDaVerifier,
};

/// Possible errors that can happen when using [`EigenDaService`].
#[derive(Debug, Error)]
pub enum EigenDaServiceError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Error received from the EigenDA proxy: {0}")]
    ProxyError(#[from] ProxyError),

    #[error("Error received from the Ethereum node: {0}")]
    EthereumRpcError(#[from] RpcError<TransportErrorKind>),
}

/// EigenDaService is responsible for interacting with the EigenDA data availability layer.
/// It provides functionality to submit blobs (data) to EigenDA and interfaces with Ethereum
/// for block information and finality status.
#[derive(Clone)]
pub struct EigenDaService {
    /// Client for interacting with the EigenDA proxy node
    // TODO: Add retrying strategy
    proxy: ProxyClient,
    /// Provider for interacting with an Ethereum node
    // TODO: Add retrying strategy
    // TODO: Add caching? `CacheProvider`
    ethereum: DynProvider,
    /// The account to which we are storing the certificates of the batch blobs
    rollup_batch_namespace: NamespaceId,
    /// The account to which we are storing the certificates of the proof blobs
    rollup_proof_namespace: NamespaceId,
    /// Private key of the sequencer. It is used to sign the transactions
    /// persisting the certificates to Ethereum
    sequencer_signer: PrivateKeySigner,
    /// EigenDA relevant contracts
    contracts: EigenDaContracts,
}

impl EigenDaService {
    /// Initialize new [`EigenDaService`] with provided [`EigenDaConfig`] and [`RollupParams`].
    pub async fn new(
        config: EigenDaConfig,
        params: RollupParams,
    ) -> Result<Self, EigenDaServiceError> {
        if params.rollup_batch_account == params.rollup_proof_account {
            return Err(EigenDaServiceError::Configuration(
                "Namespaces should not be equal".to_string(),
            ));
        }

        let proxy = ProxyClient::new(config.proxy_url)?;

        let sequencer_signer = LocalSigner::from_str(&config.sequencer_signer)
            .map_err(|err| EigenDaServiceError::Configuration(err.to_string()))?;
        let ethereum = ProviderBuilder::new()
            .wallet(sequencer_signer.clone())
            .connect(&config.ethereum_rpc_url)
            .await?
            .erased();

        Ok(Self {
            proxy,
            ethereum,
            rollup_batch_namespace: params.rollup_batch_account,
            rollup_proof_namespace: params.rollup_proof_account,
            sequencer_signer,
            contracts: config.contracts,
        })
    }

    /// Submit a blob to the EigenDA.
    #[instrument(skip_all)]
    async fn submit_blob_to_namespace(
        &self,
        blob: &[u8],
        namespace: NamespaceId,
    ) -> Result<SubmitBlobReceipt<EthereumHash>, anyhow::Error> {
        // Submit blob to the EigenDA
        let certificate = self.proxy.store_blob(blob).await?;
        debug!(?certificate, "Certificate was received by EigenDa");

        // Persist certificate to the ethereum
        let da_transaction_id = self.submit_certificate(&certificate, namespace).await?;
        debug!(
            th_hash = %da_transaction_id,
            "Certificate was submitted to Ethereum"
        );

        // TODO: Check how should the blob_hash be actually computed. Is it ok
        // to use the transaction id?
        let blob_hash = HexHash::new(da_transaction_id.into());

        Ok(SubmitBlobReceipt {
            blob_hash,
            da_transaction_id,
        })
    }

    /// Submit the certificate to the ethereum
    async fn submit_certificate(
        &self,
        certificate: &StandardCommitment,
        namespace: NamespaceId,
    ) -> Result<EthereumHash, EigenDaServiceError> {
        let bytes = certificate.to_rlp_bytes();
        let sidecar = SidecarBuilder::<SimpleCoder>::from_slice(&bytes);
        let sidecar = sidecar
            .build()
            .expect("the sidecar builder is configured correctly");

        let tx = TransactionRequest::default()
            // This is technically not needed. Because the `from` field is
            // automatically filled with the signer's address. We are specifying
            // it explicitly for the readability.
            .with_from(self.sequencer_signer.address())
            .with_to(namespace.into())
            .with_blob_sidecar(sidecar);

        let transaction = self.ethereum.send_transaction(tx).await?;
        Ok(transaction.tx_hash().to_owned().into())
    }

    /// Iterate over transactions in the block and fetch EigenDA certificate
    /// with the blob data.
    async fn extract_transactions_with_blob(
        &self,
        transactions: Vec<Transaction>,
    ) -> Result<Vec<TransactionWithBlob>, EigenDaServiceError> {
        let transactions_fut = transactions
            .into_iter()
            .map(|tx| {
                let proxy = &self.proxy;
                async move {
                    // TODO: Add a limit of reference block depth after which
                    // the certificate is ignored. This is prevention so that
                    // the attacker can't force the sequencer to fetch a long
                    // ancestors chain history.
                    let blob = if let Some(certificate) = extract_certificate(&tx) {
                        Some(Blob {
                            data: proxy.get_blob(&certificate).await?,
                            certificate,
                        })
                    } else {
                        None
                    };

                    Ok::<_, ProxyError>(TransactionWithBlob {
                        transaction: tx,
                        blob,
                    })
                }
            })
            .collect::<Vec<_>>();

        let transactions = join_all(transactions_fut)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        Ok(transactions)
    }

    /// Fetch ancestors from the earliest referenced block to the current
    /// height. The returned ancestors are contiguous. The first ancestor is the
    /// earliest referenced block, the last ancestor is the parent of the block
    /// on the `current_height`.
    async fn fetch_ancestors(
        &self,
        referenced_blocks: &HashSet<u64>,
        current_height: u64,
    ) -> Result<Vec<AncestorMetadata>, EigenDaServiceError> {
        // If no referenced blocks, we don't need any ancestors.
        let Some(&earliest_reference) = referenced_blocks.iter().min() else {
            return Ok(vec![]);
        };

        let fetch_ancestors_fut =
            (earliest_reference..current_height)
                .step_by(1)
                .map(|height| async move {
                    let block = self
                        .ethereum
                        .get_block_by_number(height.into())
                        .await?
                        .unwrap();

                    // Retrieve additional data only if the block is referenced by some certificate
                    let data = if referenced_blocks.contains(&height) {
                        Some(self.fetch_ancestor_state(height).await?)
                    } else {
                        None
                    };

                    Ok::<_, EigenDaServiceError>(AncestorMetadata {
                        header: EthereumBlockHeader::from(block.header),
                        data,
                    })
                });

        let ancestors = join_all(fetch_ancestors_fut)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ancestors)
    }

    /// Fetches the relavant state used at certificate creation. This state is
    /// later used to verify the EigenDA certificate construction.
    async fn fetch_ancestor_state(
        &self,
        block_height: u64,
    ) -> Result<AncestorStateData, EigenDaServiceError> {
        // TODO: Specify correct storage keys
        let registry_coordinator_fut = self
            .ethereum
            .get_proof(self.contracts.registry_coordinator.into(), vec![])
            .number(block_height)
            .into_future();

        // TODO: Specify correct storage keys
        let delegation_manager_fut = self
            .ethereum
            .get_proof(self.contracts.delegation_manager.into(), vec![])
            .number(block_height)
            .into_future();

        // TODO: Specify correct storage keys
        let bls_apt_registry_fut = self
            .ethereum
            .get_proof(self.contracts.bls_apt_registry.into(), vec![])
            .number(block_height)
            .into_future();

        // TODO: Specify correct storage keys
        let stake_registry_fut = self
            .ethereum
            .get_proof(self.contracts.stake_registry.into(), vec![])
            .number(block_height)
            .into_future();

        let (registry_coordinator, delegation_manager, bls_apt_registry, stake_registry) =
            try_join4(
                registry_coordinator_fut,
                delegation_manager_fut,
                bls_apt_registry_fut,
                stake_registry_fut,
            )
            .await?;

        Ok(AncestorStateData {
            registry_coordinator: AccountProof::from(registry_coordinator),
            delegation_manager: AccountProof::from(delegation_manager),
            bls_apt_registry: AccountProof::from(bls_apt_registry),
            stake_registry: AccountProof::from(stake_registry),
        })
    }
}

#[async_trait]
impl DaService for EigenDaService {
    /// A handle to the types used by the DA layer.
    type Spec = EigenDaSpec;

    /// [`serde`]-compatible configuration data for this [`DaService`]. Parsed
    /// from TOML.
    type Config = EigenDaConfig;

    /// The verifier for this DA layer.
    type Verifier = EigenDaVerifier;

    /// A DA layer block, possibly excluding some irrelevant information.
    type FilteredBlock = EthereumBlock;

    /// The error type for fallible methods.
    type Error = anyhow::Error;

    /// Fetch the block at the given height, waiting for one to be mined if necessary.
    ///
    /// The returned block may not be final, and can be reverted without a consensus violation.
    /// Calls to this method for the same height are allowed to return different results.
    /// Should always returns the block at that height on the best fork.
    async fn get_block_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error> {
        let number = BlockNumberOrTag::Number(height);

        // Poll until the requested block is mined
        let poll_interval = Duration::from_secs(10);
        let block = loop {
            match self.ethereum.get_block_by_number(number).full().await {
                Ok(Some(block)) => break block,
                Ok(None) => {
                    sleep(poll_interval).await;
                    continue;
                }
                Err(err) => {
                    warn!(?err, "error occurred while getting the block");
                    continue;
                }
            }
        };

        let header = EthereumBlockHeader::try_from(block.header.clone())?;

        // Iterate over transactions in the block and fetch sequencer relevant data
        let transactions = self
            .extract_transactions_with_blob(block.into_transactions_vec())
            .await?;

        // Block heights referenced by the certificates persisted in the block.
        // The number of ancestors we'll fetch depends on this earliest
        // reference.
        let referenced_blocks = transactions
            .iter()
            .flat_map(|t| {
                t.blob
                    .as_ref()
                    .map(|b| b.certificate.reference_block() as u64)
            })
            .collect::<HashSet<_>>();
        let ancestors = self.fetch_ancestors(&referenced_blocks, height).await?;

        Ok(EthereumBlock {
            ancestors,
            header,
            transactions,
        })
    }

    /// Fetch the [`DaSpec::BlockHeader`] of the last finalized block.
    /// If there's no finalized block yet, it should return an error.
    async fn get_last_finalized_block_header(
        &self,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error> {
        let block = BlockId::finalized();
        let block = self
            .ethereum
            .get_block(block)
            .await?
            .ok_or_else(|| anyhow::anyhow!("No finalized block"))?;

        Ok(EthereumBlockHeader::try_from(block.header)?)
    }

    /// Fetch the head block of the most popular fork.
    ///
    /// More like utility method, to provide better user experience
    async fn get_head_block_header(
        &self,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error> {
        let block = BlockId::latest();
        let block = self
            .ethereum
            .get_block(block)
            .await?
            .ok_or_else(|| anyhow::anyhow!("No finalized block"))?;

        Ok(EthereumBlockHeader::try_from(block.header)?)
    }

    /// Extract the relevant transactions from a block. For example, this method might return
    /// all of the blob transactions from a set rollup namespaces on Celestia.
    fn extract_relevant_blobs(
        &self,
        block: &Self::FilteredBlock,
    ) -> RelevantBlobs<<Self::Spec as DaSpec>::BlobTransaction> {
        let proof_blobs = block.extract_relevant_blobs(self.rollup_proof_namespace);
        let batch_blobs = block.extract_relevant_blobs(self.rollup_batch_namespace);

        RelevantBlobs {
            proof_blobs,
            batch_blobs,
        }
    }

    /// Generate a proof that the relevant blob transactions have been extracted correctly from the DA layer
    /// block.
    async fn get_extraction_proof(
        &self,
        block: &Self::FilteredBlock,
        blobs: &RelevantBlobs<<Self::Spec as DaSpec>::BlobTransaction>,
    ) -> RelevantProofs<
        <Self::Spec as DaSpec>::InclusionMultiProof,
        <Self::Spec as DaSpec>::CompletenessProof,
    > {
        let proof = block.get_extraction_proof(self.rollup_proof_namespace);
        let batch = block.get_extraction_proof(self.rollup_batch_namespace);

        RelevantProofs { proof, batch }
    }

    /// Send a transaction directly to the DA layer.
    /// This method is infallible: the SubmitBlobReceipt is returned via the `oneshot::Receiver` after the blob is posted to the DA.
    async fn send_transaction(
        &self,
        blob: &[u8],
    ) -> oneshot::Receiver<
        Result<SubmitBlobReceipt<<Self::Spec as DaSpec>::TransactionId>, Self::Error>,
    > {
        let (tx, rx) = oneshot::channel();
        let result = self
            .submit_blob_to_namespace(blob, self.rollup_batch_namespace)
            .await;
        tx.send(result).expect("receiver exists");

        rx
    }

    /// Sends a proof to the DA layer.
    /// This method is infallible: the SubmitBlobReceipt is returned via the `oneshot::Receiver` after the blob is posted to the DA.
    async fn send_proof(
        &self,
        aggregated_proof_data: &[u8],
    ) -> oneshot::Receiver<
        Result<SubmitBlobReceipt<<Self::Spec as DaSpec>::TransactionId>, Self::Error>,
    > {
        let (tx, rx) = oneshot::channel();
        let result = self
            .submit_blob_to_namespace(aggregated_proof_data, self.rollup_proof_namespace)
            .await;
        tx.send(result).expect("receiver exists");

        rx
    }

    /// Fetches all proofs at a specified block height.
    async fn get_proofs_at(&self, height: u64) -> Result<Vec<Vec<u8>>, Self::Error> {
        let block = self.get_block_at(height).await?;
        let blobs = block.extract_relevant_blobs(self.rollup_proof_namespace);
        let proofs = blobs
            .into_iter()
            .map(|mut b| b.full_data().to_vec())
            .collect::<Vec<Vec<u8>>>();

        Ok(proofs)
    }

    /// Returns a [`DaSpec::Address`] that signs blobs submitted by this instance of [`DaService`]
    async fn get_signer(&self) -> <Self::Spec as DaSpec>::Address {
        EthereumAddress::from(self.sequencer_signer.address())
    }
}

/// Contains data needed to validate the certificate using the ancestor as the
/// reference block. It also contains proofs used to verify the data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AncestorStateData {
    registry_coordinator: AccountProof,
    delegation_manager: AccountProof,
    bls_apt_registry: AccountProof,
    stake_registry: AccountProof,
}

impl AncestorStateData {
    /// Verifies the data against the state root.
    pub fn verify(&self, state_root: B256) -> Result<(), ProofVerificationError> {
        self.registry_coordinator.verify(state_root)?;
        self.delegation_manager.verify(state_root)?;
        self.bls_apt_registry.verify(state_root)?;
        self.stake_registry.verify(state_root)?;

        Ok(())
    }

    /// Extract the data.
    ///
    /// NOTE: The data extracted is not verified.
    pub fn extract(&self) -> Result<(), ()> {
        // TODO: Extract the data from proofs to some struct used to verify the
        // certificate. You need the corect storage keys here again.
        todo!()
    }
}

/// Data tracked for the specific ancestor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AncestorMetadata {
    // Header for the ancestor block.
    header: EthereumBlockHeader,
    // The data needed to validate the certificate referencing this ancestor.
    // It's `Some` only in cases when we have a certificate that references this
    // ancestor. If there is no certificate referencing the ancestor the data is
    // `None`.
    data: Option<AncestorStateData>,
}

/// An Ethereum block containing relevant information.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EthereumBlock {
    /// List of ancestor blocks. The first ancestor in a list is the earliest
    /// reference block from which the values for certificate creation were
    /// sourced. The last header in a list is a parent of this block.
    ancestors: Vec<AncestorMetadata>,
    /// The current block header.
    header: EthereumBlockHeader,
    /// Tranasctions included in this block.
    transactions: Vec<TransactionWithBlob>,
}

impl EthereumBlock {
    /// Extract all rollup's blobs (indicated by namespace) from this block.
    pub fn extract_relevant_blobs(&self, namespace: NamespaceId) -> Vec<BlobWithSender> {
        self.transactions
            .iter()
            .filter_map(|tx| {
                let recovered = tx.transaction.as_recovered();
                let sender = recovered.signer();
                let tx_hash = recovered.hash().to_owned();

                namespace
                    .contains(&tx.transaction)
                    .then(|| tx.blob.clone())
                    .and_then(|blob| {
                        blob.map(|blob| BlobWithSender::new(sender, tx_hash, blob.data))
                    })
            })
            .collect::<Vec<_>>()
    }

    /// Get the inclusion and completeness proofs pair for rollup's blobs (indicated by namespace)
    /// contained in this block.
    pub fn get_extraction_proof(
        &self,
        namespace: NamespaceId,
    ) -> DaProof<EigenDaInclusionProof, EigenDaCompletenessProof> {
        let maybe_relevant_txs = self
            .transactions
            .iter()
            .filter(|tx| namespace.contains(&tx.transaction))
            .cloned()
            .collect();

        DaProof {
            inclusion_proof: EigenDaInclusionProof::new(namespace, &self.transactions),
            completeness_proof: EigenDaCompletenessProof::new(maybe_relevant_txs),
        }
    }
}

impl SlotData for EthereumBlock {
    type BlockHeader = EthereumBlockHeader;

    fn hash(&self) -> [u8; 32] {
        self.header.hash().into()
    }

    fn header(&self) -> &Self::BlockHeader {
        &self.header
    }

    fn timestamp(&self) -> Time {
        self.header.time()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sov_rollup_interface::{da::DaVerifier, node::da::DaService};

    use crate::{
        eigenda::proxy::tests::start_proxy,
        service::{
            EigenDaConfig, EigenDaService, EigenDaServiceError,
            ethereum::tests::{MiningKind, mine_block, start_ethereum_dev_node},
        },
        spec::{NamespaceId, RollupParams},
        verifier::EigenDaVerifier,
    };

    use super::EigenDaContracts;

    #[tokio::test]
    async fn submit_extract_verify_e2e() {
        let (proxy_url, _proxy_container) = start_proxy().await.unwrap();
        let (ethereum_rpc_url, _anvil_container) =
            start_ethereum_dev_node(MiningKind::Manual).await.unwrap();

        let service = setup_service(proxy_url, ethereum_rpc_url.clone())
            .await
            .unwrap();
        let verifier = EigenDaVerifier::new(RollupParams {
            rollup_batch_account: service.rollup_batch_namespace,
            rollup_proof_account: service.rollup_proof_namespace,
        });

        let blobs = [vec![123; 123], vec![15; 45], vec![8; 1234], vec![2; 1]];
        let proofs = [vec![43; 87], vec![112; 135], vec![2; 994], vec![1; 1]];

        // Post the rollup data to the network
        for blob in blobs {
            service
                .send_transaction(&blob)
                .await
                .await
                .unwrap()
                .unwrap();
        }
        for proof in proofs {
            service.send_proof(&proof).await.await.unwrap().unwrap();
        }

        // Mine the block
        mine_block(&ethereum_rpc_url, 1).await.unwrap();

        // Extract rollup data from the block
        let block_height = 1;
        let block = service.get_block_at(block_height).await.unwrap();
        let blobs = service.extract_relevant_blobs(&block);
        let proofs = service.get_extraction_proof(&block, &blobs).await;

        // Simulate we're sending this to zkvm
        let header = risc0_zkvm::serde::to_vec(&block.header).unwrap();
        let blobs = risc0_zkvm::serde::to_vec(&blobs).unwrap();
        let proofs = risc0_zkvm::serde::to_vec(&proofs).unwrap();

        // Receive on zkvm side
        let header = risc0_zkvm::serde::from_slice(&header).unwrap();
        let blobs = risc0_zkvm::serde::from_slice(&blobs).unwrap();
        let proofs = risc0_zkvm::serde::from_slice(&proofs).unwrap();

        // Verify
        verifier
            .verify_relevant_tx_list(&header, &blobs, proofs)
            .unwrap();
    }

    async fn setup_service(
        proxy_url: String,
        ethereum_rpc_url: String,
    ) -> Result<EigenDaService, EigenDaServiceError> {
        // ! These keys should not be used in production. They are the keys used
        // by Anvil node for the predefined accounts. !
        let sequencer_signer =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();
        let rollup_batch_account =
            NamespaceId::from_str("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();
        let rollup_proof_account =
            NamespaceId::from_str("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC").unwrap();

        let config = EigenDaConfig {
            ethereum_rpc_url,
            proxy_url,
            sequencer_signer,
            contracts: EigenDaContracts {
                registry_coordinator: todo!(),
                delegation_manager: todo!(),
                bls_apt_registry: todo!(),
                stake_registry: todo!(),
            },
        };
        let params = RollupParams {
            rollup_batch_account,
            rollup_proof_account,
        };

        EigenDaService::new(config, params).await
    }
}
