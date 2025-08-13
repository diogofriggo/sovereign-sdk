use sov_rollup_interface::da::BlockHeaderTrait;
use thiserror::Error;

use super::types::StandardCommitment;
use crate::spec::{AncestorMetadata, EthereumBlockHeader};

#[derive(Debug, Error)]
pub enum CertificateVerificationError {
    #[error("The recency window was missed, inclusion_height ({0}), recency height ({1})")]
    RecencyWindowMissed(u64, u64),

    #[error("Ancestor data missing")]
    AncestorDataMissing,
}

/// Certificate recency validation
///
/// https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#1-rbn-recency-validation
pub fn verify_cert_recency(
    header: &EthereumBlockHeader,
    cert: &StandardCommitment,
    cert_recency_window: u64,
) -> Result<(), CertificateVerificationError> {
    let referenced_height = cert.reference_block();
    let inclusion_height = header.height();

    let recency_height = referenced_height + cert_recency_window;
    if inclusion_height > recency_height {
        return Err(CertificateVerificationError::RecencyWindowMissed(
            inclusion_height,
            recency_height,
        ));
    }

    Ok(())
}

/// Certificate validation
///
/// https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#2-cert-validation
pub fn verify_cert(
    header: &EthereumBlockHeader,
    ancestor: &AncestorMetadata,
    _cert: &StandardCommitment,
) -> Result<(), CertificateVerificationError> {
    let _current_height = header.height() as u32;
    let _ancestor_data = ancestor
        .data
        .as_ref()
        .ok_or_else(|| CertificateVerificationError::AncestorDataMissing)?;

    // TODO: Verify the certificate against the ancestor data
    // let _cert_referenced_data = ancestor_data.extract(&cert, current_height);

    Ok(())
}

#[derive(Debug, Error)]
pub enum BlobVerificationError {}

/// Blob validation against the certificate
///
/// https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#3-blob-validation
pub fn verify_blob(
    _certificate: &StandardCommitment,
    _blob: &[u8],
) -> Result<(), BlobVerificationError> {
    // TODO: Verify the blob against the certificate. Doing that we have a
    // full validated chain of data

    Ok(())
}
