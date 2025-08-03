use crate::{
    eigenda::types::StandardCommitment,
    ethereum::EthereumTransactionExt,
    spec::{
        AncestorMetadata, BlobWithSender, EigenDaSpec, EthereumAddress, EthereumBlockHeader,
        EthereumHash, NamespaceId, TransactionWithBlob,
    },
};
use alloy_consensus::{proofs::calculate_transaction_root, transaction::SignerRecoverable};
use alloy_primitives::B256;
use eigenda_cert_verifier::error::CertVerificationError;
use reth_trie_common::proof::ProofVerificationError;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{
    BlobReaderTrait, DaSpec, DaVerifier, RelevantBlobs, RelevantProofs,
};
use thiserror::Error;
use tracing::warn;

/// Errors that may occur when verifying with the [`EigenDaVerifier`].
#[derive(Debug, Error)]
pub enum VerifierError {
    #[error(transparent)]
    CompletenessError(#[from] CompletenessProofError),

    #[error(transparent)]
    InclusionError(#[from] InclusionProofError),
}

/// A verifier verifies that rollup transactions are indeed included in the
/// block, that no rollup tx from the block is missing and that blobs were
/// extracted correctly.
#[derive(Debug, Clone)]
pub struct EigenDaVerifier {
    batch_namespace: NamespaceId,
    proof_namespace: NamespaceId,
}

impl EigenDaVerifier {
    pub fn verify_transactions(
        &self,
        block_header: &EthereumBlockHeader,
        namespace: NamespaceId,
        blobs_with_senders: &[BlobWithSender],
        completeness_proof: EigenDaCompletenessProof,
        inclusion_proof: EigenDaInclusionProof,
    ) -> Result<(), VerifierError> {
        // Verify completeness proof, proving that all transactions in a
        // specified set are in the block
        let proven_transactions = completeness_proof.verify(block_header)?;

        // Verify that the provided `relevant_blobs` are the only ones that
        // contain rollup data, and that they are correctly build from the block
        inclusion_proof.verify(namespace, &proven_transactions, blobs_with_senders)?;

        Ok(())
    }
}

impl DaVerifier for EigenDaVerifier {
    type Spec = EigenDaSpec;

    type Error = VerifierError;

    fn new(params: <Self::Spec as DaSpec>::ChainParams) -> Self {
        EigenDaVerifier {
            proof_namespace: params.rollup_proof_namespace,
            batch_namespace: params.rollup_batch_namespace,
        }
    }

    fn verify_relevant_tx_list(
        &self,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
        relevant_blobs: &RelevantBlobs<<Self::Spec as DaSpec>::BlobTransaction>,
        relevant_proofs: RelevantProofs<
            <Self::Spec as DaSpec>::InclusionMultiProof,
            <Self::Spec as DaSpec>::CompletenessProof,
        >,
    ) -> Result<(), Self::Error> {
        // Verify the `proof` namespace
        self.verify_transactions(
            block_header,
            self.proof_namespace,
            &relevant_blobs.proof_blobs,
            relevant_proofs.proof.completeness_proof,
            relevant_proofs.proof.inclusion_proof,
        )?;
        // Verify the `batch` namespace
        self.verify_transactions(
            block_header,
            self.batch_namespace,
            &relevant_blobs.batch_blobs,
            relevant_proofs.batch.completeness_proof,
            relevant_proofs.batch.inclusion_proof,
        )?;

        Ok(())
    }
}

/// Errors that may occur when verifying the [`EigenDaCompletenessProof`].
#[derive(Debug, Error)]
pub enum CompletenessProofError {
    #[error("Incorrect ancestry chain")]
    IncorrectAncestry,

    #[error("Ancestor missing, height({0})")]
    AncestorMissing(u64),

    #[error("Ancestor data missing, height({0})")]
    AncestorDataMissing(u64),

    #[error("Recomputed merkle root ({0}) doesn't match the one in header ({1})")]
    MerkleRootMismatch(B256, B256),

    #[error("Certificate mismatch")]
    CertificateMismatch,

    #[error("Error occurred while verifying the Ethereum account proof: {0}")]
    ProofVerificationError(#[from] ProofVerificationError),

    #[error("Error occurred while verifying EigenDA certificate: {0}")]
    CertVerificationError(#[from] CertVerificationError),
}

/// A proof of completeness of the transactions in the block.
///
/// This proof holds all the transactions from the block, in order. It also
/// holds ancestors which are guaranteed to be contiguous and represent a direct
/// ancestor chain of the block.
#[derive(Debug, Serialize, Deserialize)]
pub struct EigenDaCompletenessProof {
    ancestors: Vec<AncestorMetadata>,
    transactions: Vec<TransactionWithBlob>,
}

impl EigenDaCompletenessProof {
    /// Create a new completeness proof.
    pub fn new(ancestors: Vec<AncestorMetadata>, transactions: Vec<TransactionWithBlob>) -> Self {
        Self {
            ancestors,
            transactions,
        }
    }

    /// Get the [`AncestorMetadata`] for the specific referenced block.
    pub fn get_ancestor(
        &self,
        current_height: u64,
        referenced_height: u64,
    ) -> Option<&AncestorMetadata> {
        // Check that the referenced height is always smaller from the current_height
        if current_height <= referenced_height {
            return None;
        }

        // Safety: We know that the referenced_height is always smaller from current_height.
        let diff = current_height - referenced_height;
        let ancestors_len = self.ancestors.len() as u64;

        // Check that the referenced height is in the vector
        if ancestors_len < diff {
            return None;
        }

        // Safety: We know that the `diff` <= `ancestors_len`
        let index = (ancestors_len - diff) as usize;
        Some(&self.ancestors[index])
    }

    /// Verify certificate against the data from the specific ancestor and
    /// verify data blob against the verified certificate.
    fn verify_blob(
        &self,
        header: &EthereumBlockHeader,
        certificate: StandardCommitment,
        blob: &[u8],
    ) -> Result<(), CompletenessProofError> {
        // Get the referenced ancestor by the certificate. If this returns
        // an error it means there must be a logic error when prefilling the
        // ancestors vector. Here the referenced ancestor with its data
        // should always be available.
        let referenced_height = certificate.reference_block();
        let ancestor = self
            .get_ancestor(header.as_ref().number, referenced_height)
            .ok_or_else(|| CompletenessProofError::AncestorMissing(referenced_height))?
            .data
            .as_ref()
            .ok_or_else(|| CompletenessProofError::AncestorDataMissing(referenced_height))?;

        // TODO: Verify the certificate.

        // TODO: We also need to verify the `blob` against the
        // certificate. Doing that we have a full validated chain of data.

        Ok(())
    }

    /// Verify that the proof holds the complete list of transactions for a
    /// block. Verify that the blobs retrieved based on the certificates are
    /// correct.
    ///
    /// Upon success, the proof returns a vector of transactions that were
    /// proven to represent a whole transaction set of a specific block.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - ancestry chain is not continuous
    ///   - the header is not a direct descendant of the ancestry chain
    ///   - state data of the specific ancestor is incorrect
    ///   - recomputed transaction_root is different from the root in the header
    ///   - validation of certificate and blob fails
    pub fn verify(
        self,
        header: &EthereumBlockHeader,
    ) -> Result<Vec<TransactionWithBlob>, CompletenessProofError> {
        // Iterate through the ancestors and check their parent/child
        // relationships. If the direct ancestry is not valid, the error is
        // returned. In case when we have no ancestors the `last_ancestor` is None.
        let last_ancestor = self.ancestors.iter().try_fold(
            None,
            |parent: Option<&AncestorMetadata>, maybe_child| {
                // If there is no parent to check against, we set the ancestry as valid
                let valid_ancestry = parent
                    .and_then(|parent| Some(parent.header.is_parent(&maybe_child.header)))
                    .unwrap_or(true);

                if valid_ancestry {
                    Ok(Some(maybe_child))
                } else {
                    Err(CompletenessProofError::IncorrectAncestry)
                }
            },
        )?;

        // Check if last ancestor is our actual parent
        if let Some(ancestor) = last_ancestor {
            if !ancestor.header.is_parent(header) {
                return Err(CompletenessProofError::IncorrectAncestry);
            }
        }

        // Validate the data state of the ancestor blocks
        for ancestor in &self.ancestors {
            if let Some(data) = &ancestor.data {
                data.verify(ancestor.header.as_ref().state_root)?;
            }
        }

        // Verify that the proof holds the complete list of transactions for the block
        let transactions = self
            .transactions
            .iter()
            .map(|t| &t.transaction)
            .collect::<Vec<_>>();
        let calculated_transactions_root = calculate_transaction_root(&transactions);
        if calculated_transactions_root != header.as_ref().transactions_root {
            return Err(CompletenessProofError::MerkleRootMismatch(
                calculated_transactions_root,
                header.as_ref().transactions_root,
            ));
        }

        // Validate the EigenDA certificates and data blobs
        for tx_with_blob in &self.transactions {
            let certificate = tx_with_blob.transaction.extract_certificate();

            match (certificate, &tx_with_blob.blob) {
                (Some(certificate), Some(blob)) => {
                    // Verify certificate and blob
                    self.verify_blob(header, certificate, &blob)?;
                }
                (Some(certificate), None) => {
                    // This can happen in cases when the ethereum transaction
                    // contains a valid formatted certificate that was not
                    // recognized by the EigenDA when fetching the blob data
                    warn!(
                        ?certificate,
                        "Transaction holds a certificate without a corresponding blob"
                    );
                }
                (None, Some(_blob)) => {
                    // Safety: This is a logic error. The blobs are fetched
                    // based on the certificates in the transactions. That means
                    // we should never have a blob, without the certificate in
                    // the transaction.
                    unreachable!();
                }
                (None, None) => {
                    // The transaction is not relevant for the rollup
                    continue;
                }
            }
        }

        Ok(self.transactions)
    }
}

/// Errors that may occur when verifying the [`EigenDaInclusionProof`].
#[derive(Debug, Error)]
pub enum InclusionProofError {
    #[error("Transaction ({0}) in proof wasn't part of the completeness proof")]
    NotProvenTransaction(B256),

    #[error("Proof incomplete, some relevant transactions are missing")]
    ProofIncomplete,

    #[error("Blob missing for transaction ({0})")]
    MissingBlob(B256),

    #[error("Additional blob ({0}) provided, irrelevant for the rollup")]
    IrrelevantBlob(B256),

    #[error("Transaction has incorrect sender ({1}), expected ({0})")]
    IncorrectSender(EthereumAddress, EthereumAddress),

    #[error("Transaction has incorrect hash ({1}), expected ({0})")]
    IncorrectBlobHash(EthereumHash, EthereumHash),

    #[error("Malformed data for transaction ({0})")]
    IncorrectBlobData(EthereumHash),
}

/// A proof of inclusion of the rollup transactions from the block.
///
/// This proof holds all transactions from the block which may be relevant to
/// the rollup, in order. The proof will check if the rollup's transactions are
/// the only one in block within rollup's namespace and if they are correctly
/// extracted from the block.
#[derive(Debug, Serialize, Deserialize)]
pub struct EigenDaInclusionProof {
    transactions: Vec<TransactionWithBlob>,
}

impl EigenDaInclusionProof {
    /// Create a new inclusion proof from a complete and ordered list of
    /// transactions that can be relevant for the rollup.
    pub fn new(maybe_relevant_txs: Vec<TransactionWithBlob>) -> Self {
        Self {
            transactions: maybe_relevant_txs,
        }
    }

    /// Verify that the proof holds transactions extracted from all transactions
    /// within given namespace, no more, no less.
    fn verify_transactions(
        &self,
        namespace: NamespaceId,
        proven_transactions: &[TransactionWithBlob],
    ) -> Result<(), InclusionProofError> {
        // Transaction hashes related to the transactions in the proof
        let mut transaction_hashes = self.transactions.iter().map(|tx| tx.transaction.hash());

        // Transactions in a namespace extracted from the transactions that were
        // already proven to be a complete set.
        let mut namespace_transaction_hashes = proven_transactions
            .iter()
            .filter(|tx| namespace.contains(&tx.transaction))
            .map(|tx| tx.transaction.hash());

        loop {
            match (
                transaction_hashes.next(),
                namespace_transaction_hashes.next(),
            ) {
                // Compare hash from proof with proven one
                (Some(hash), Some(proven_hash)) => {
                    if hash != proven_hash {
                        return Err(InclusionProofError::NotProvenTransaction(*hash));
                    }
                }
                // Extra transactions in proof
                (Some(hash), None) => {
                    return Err(InclusionProofError::NotProvenTransaction(*hash));
                }
                // Proof is missing a transaction
                (None, Some(_)) => return Err(InclusionProofError::ProofIncomplete),
                // Done
                (None, None) => return Ok(()),
            }
        }
    }

    /// Verify that the given `blobs_with_senders` list form a complete set of
    /// rollup's batches in a single block, and that all supplied transactions
    /// are correctly extracted from that block.
    ///
    /// The proof accepts all transactions previously verified for completeness
    /// in the block. Based on that, the proof will verify if the list of its
    /// transactions forms complete namespace i.e. if there are no transactions
    /// in the block with the same namespace not included in proof.
    ///
    /// Then, since the proof holds all the transactions part of the namespace,
    /// we can check those transactions against the provided transactions in the
    /// `blobs_with_senders` list. Each transaction is checked for data and
    /// sender equality, in order they appear.
    ///
    /// TODO: Add errors that can happen
    pub fn verify(
        &self,
        namespace: NamespaceId,
        proven_transactions: &[TransactionWithBlob],
        blobs_with_senders: &[BlobWithSender],
    ) -> Result<(), InclusionProofError> {
        // Verify transactions contained by the proof
        self.verify_transactions(namespace, proven_transactions)?;

        let mut blobs_with_senders = blobs_with_senders.iter();
        let mut proven_relevant_transactions = self.transactions.iter().flat_map(|tx| {
            let hash = EthereumHash::from(*tx.transaction.hash());
            let blob = tx.blob.as_ref()?;

            let sender = tx.transaction.recover_signer().ok()?;
            let sender = EthereumAddress::from(sender);
            Some((hash, sender, blob))
        });

        // Compare proven transactions to the provided transactions represented
        // as blobs with senders
        loop {
            let (hash, sender, blob, provided) = match (
                proven_relevant_transactions.next(),
                blobs_with_senders.next(),
            ) {
                (Some((hash, sender, blob)), Some(provided)) => (hash, sender, blob, provided),
                // `blob_with_sender` not provided
                (Some((hash, ..)), None) => {
                    return Err(InclusionProofError::MissingBlob(*hash));
                }
                // Missing transaction for the provided `blob_with_sender``
                (None, Some(provided)) => {
                    return Err(InclusionProofError::IrrelevantBlob(*provided.hash()));
                }
                // We are finished
                (None, None) => break,
            };

            // Check if sender is the same
            if sender != provided.sender {
                return Err(InclusionProofError::IncorrectSender(
                    sender,
                    provided.sender,
                ));
            }

            // Check if hash is the same
            if hash != provided.hash() {
                return Err(InclusionProofError::IncorrectBlobHash(
                    hash,
                    provided.hash(),
                ));
            }

            // Check if data read by the rollup was correct
            let consumed_data = provided.verified_data();
            if consumed_data.is_empty() {
                // Nothing to check
                continue;
            }
            if consumed_data.len() > blob.len() {
                // Provided transaction has more data than original one
                return Err(InclusionProofError::IncorrectBlobData(hash));
            }
            if consumed_data[..] != blob[..consumed_data.len()] {
                // Data mismatch
                return Err(InclusionProofError::IncorrectBlobData(hash));
            }
        }

        Ok(())
    }
}
