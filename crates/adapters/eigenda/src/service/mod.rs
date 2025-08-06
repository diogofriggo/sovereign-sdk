pub mod config;

pub use crate::eigenda::types::{StandardCommitment, StandardCommitmentParseError};
use crate::ethereum::EthereumTransactionExt;
use crate::ethereum::provider::{EthereumProviders, init_ethereum_provider};
use crate::service::config::{EigenDaConfig, EigenDaContracts};
use crate::spec::{AncestorMetadata, AncestorStateData, EthereumAddress};

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;
use std::u64;

use alloy_consensus::TxEip4844;
use alloy_consensus::transaction::SignerRecoverable;
use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_network::TransactionBuilder;
use alloy_provider::Provider;
use alloy_rpc_types_eth::Transaction;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use alloy_transport::{RpcError, TransportErrorKind};
use async_trait::async_trait;
use futures::future::{join_all, try_join4};
use reth_trie_common::AccountProof;
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
use crate::spec::{BlobWithSender, NamespaceId, RollupParams, TransactionWithBlob};
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

    #[error("Ancestor at height ({0}) is missing")]
    AncestorMissing(u64),
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
    ethereum: EthereumProviders,
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
        if params.rollup_batch_namespace == params.rollup_proof_namespace {
            return Err(EigenDaServiceError::Configuration(
                "Namespaces should not be equal".to_string(),
            ));
        }

        let sequencer_signer = LocalSigner::from_str(&config.sequencer_signer)
            .map_err(|err| EigenDaServiceError::Configuration(err.to_string()))?;
        let ethereum = init_ethereum_provider(&config, sequencer_signer.clone()).await?;

        let proxy = ProxyClient::new(config.proxy_url)?;

        Ok(Self {
            proxy,
            ethereum,
            rollup_batch_namespace: params.rollup_batch_namespace,
            rollup_proof_namespace: params.rollup_proof_namespace,
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

        let tx = TransactionRequest::default()
            // This is technically not needed. Because the `from` field is
            // automatically filled with the signer's address. We are specifying
            // it explicitly for the readability.
            .with_from(self.sequencer_signer.address())
            .with_to(namespace.into())
            .with_input(bytes);

        let transaction = self.ethereum.wallet.send_transaction(tx).await?;
        Ok(transaction.tx_hash().to_owned().into())
    }

    /// Iterate over transactions in the block and fetch EigenDA certificate
    /// with the blob data.
    async fn extract_transactions_with_blob(
        &self,
        transactions: Vec<Transaction>,
    ) -> Result<Vec<(TransactionWithBlob, Option<u64>)>, EigenDaServiceError> {
        // TODO: Add a limit of reference block depth after which the
        // certificate is ignored. This is prevention so that the attacker can't
        // force the sequencer to fetch a long ancestry chain history.
        //
        // Note: Have in mind that the completeness proof will still contain the
        // certificate. Which is why we should also handle it there. Hmm. What
        // would be the right approach for handling this case?
        let transactions_fut = transactions
            .into_iter()
            .map(|tx| {
                let proxy = &self.proxy;
                async move {
                    let mut referenced_block = None;
                    let transaction = tx.into_inner().map_eip4844(|a| TxEip4844::from(a));

                    let blob = match transaction.extract_certificate() {
                        Some(certificate) => {
                            referenced_block.replace(certificate.reference_block());
                            // TODO: Handle cases when certificate in the
                            // transaction is of valid format. But the EigenDA
                            // doesn't have the blob requested. That can be
                            // achieved by publishing the malicious certificate
                            // to the Ethereum that is in correct format but was
                            // not generated by the EigenDA. The extraction
                            // process shouldn't fail.
                            Some(proxy.get_blob(&certificate).await?)
                        }
                        None => None,
                    };

                    let transaction_with_blob = TransactionWithBlob { transaction, blob };
                    Ok::<_, ProxyError>((transaction_with_blob, referenced_block))
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
                        .cached
                        .get_block_by_number(height.into())
                        .await?
                        .ok_or_else(|| EigenDaServiceError::AncestorMissing(height))?;

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

    /// Fetches the relevant state used at certificate creation. This state is
    /// later used to verify the EigenDA certificate construction.
    async fn fetch_ancestor_state(
        &self,
        block_height: u64,
    ) -> Result<AncestorStateData, EigenDaServiceError> {
        // TODO: Specify correct storage keys
        let registry_coordinator_fut = self
            .ethereum
            .cached
            .get_proof(self.contracts.registry_coordinator.into(), vec![])
            .number(block_height)
            .into_future();

        // TODO: Specify correct storage keys
        let delegation_manager_fut = self
            .ethereum
            .cached
            .get_proof(self.contracts.delegation_manager.into(), vec![])
            .number(block_height)
            .into_future();

        // TODO: Specify correct storage keys
        let bls_apt_registry_fut = self
            .ethereum
            .cached
            .get_proof(self.contracts.bls_apt_registry.into(), vec![])
            .number(block_height)
            .into_future();

        // TODO: Specify correct storage keys
        let stake_registry_fut = self
            .ethereum
            .cached
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

        Ok(AncestorStateData::new(
            AccountProof::from(registry_coordinator),
            AccountProof::from(delegation_manager),
            AccountProof::from(bls_apt_registry),
            AccountProof::from(stake_registry),
        ))
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
    /// Should always return the block at that height on the best fork.
    async fn get_block_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error> {
        let number = BlockNumberOrTag::Number(height);

        // Poll until the requested block is mined
        let poll_interval = Duration::from_secs(10);
        let block = loop {
            match self
                .ethereum
                .cached
                .get_block_by_number(number)
                .full()
                .await
            {
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
        // The number of ancestors we'll fetch depends on the earliest
        // reference.
        let referenced_blocks = transactions
            .iter()
            .flat_map(|(_, referenced_block)| *referenced_block)
            .collect::<HashSet<_>>();
        let ancestors = self.fetch_ancestors(&referenced_blocks, height).await?;

        let transactions = transactions
            .into_iter()
            .map(|(transaction, _)| transaction)
            .collect::<Vec<_>>();

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
            .cached
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
            .cached
            .get_block(block)
            .await?
            .ok_or_else(|| anyhow::anyhow!("No finalized block"))?;

        Ok(EthereumBlockHeader::try_from(block.header)?)
    }

    /// Extract the relevant transactions from a block.
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
        _blobs: &RelevantBlobs<<Self::Spec as DaSpec>::BlobTransaction>,
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

/// An Ethereum block containing relevant information.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EthereumBlock {
    /// List of ancestor blocks. The first ancestor in a list is the earliest
    /// reference block from which the values for certificate creation were
    /// sourced. The last header in a list is a parent of this block.
    pub ancestors: Vec<AncestorMetadata>,
    /// The current block header.
    pub header: EthereumBlockHeader,
    /// Transactions included in this block.
    pub transactions: Vec<TransactionWithBlob>,
}

impl EthereumBlock {
    /// Extract all rollup's blobs (indicated by namespace) from this block.
    pub fn extract_relevant_blobs(&self, namespace: NamespaceId) -> Vec<BlobWithSender> {
        self.transactions
            .iter()
            .filter_map(|tx| {
                namespace
                    .contains(&tx.transaction)
                    .then(|| tx.blob.clone().map(|blob| (&tx.transaction, blob)))
                    .flatten()
            })
            .filter_map(|(tx, blob)| {
                let sender = tx.recover_signer().ok()?;
                let tx_hash = tx.hash().to_owned();

                Some(BlobWithSender::new(sender, tx_hash, blob))
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
            inclusion_proof: EigenDaInclusionProof::new(maybe_relevant_txs),
            completeness_proof: EigenDaCompletenessProof::new(
                self.ancestors.clone(),
                self.transactions.clone(),
            ),
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
