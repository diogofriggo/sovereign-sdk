//! Rollup-specific EigenDA verification utilities
//!
//! This module provides rollup-specific verification functions that complement the core
//! EigenDA cryptographic verification primitives with rollup integration requirements.
//!
//! ## Verification Functions
//!
//! This module provides two key verification utilities:
//!
//! 1. **[`verify_cert_recency`]** - Certificate recency validation
//! 2. **[`verify_blob`]** - Blob commitment verification
//!
//! ### Certificate Recency Validation
//!
//! [`verify_cert_recency`] ensures certificates are used within an acceptable time window to prevent
//! stale certificate attacks. It validates that the certificate's reference block
//! is recent enough relative to the current inclusion block according to rollup parameters.
//!
//! This is a rollup-specific check that uses Ethereum block headers and rollup
//! configuration parameters.
//!
//! ### Blob Verification
//!
//! [`verify_blob`] validates that blob data matches the cryptographic commitment in the certificate
//! using KZG polynomial commitments. This function serves as a convenient wrapper around
//! the core blob verification primitives.
//!
//! ## Certificate Validation
//!
//! Note that comprehensive certificate validation (BLS signatures, stake verification, etc.)
//! is handled directly through the core [`eigenda::verification::cert`] module in conjunction
//! with Ethereum state data extraction from the [`crate::spec`] module.
//!
//! ## Architecture
//!
//! This module focuses on rollup integration concerns:
//! - Ethereum block header compatibility with Sovereign SDK
//! - Rollup parameter integration (recency windows)
//! - Convenient wrapper functions for common verification operations
//!
//! The core cryptographic verification is delegated to the `eigenda` crate.
//!
//! ## References
//!
//! - [EigenDA Integration Specification](https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html)
//! - [Sovereign SDK Documentation](https://docs.sovereign.xyz/)

use eigenda::cert::StandardCommitment;
use eigenda::verification::blob::error::BlobVerificationError;
use eigenda::verification::blob::{self};
use eigenda::verification::cert::error::CertVerificationError;
use sov_rollup_interface::da::BlockHeaderTrait;
use tracing::instrument;

use crate::spec::EthereumBlockHeader;

/// Validate certificate recency to prevent stale certificate attacks
///
/// Ensures that the certificate's reference block is recent enough relative to
/// the inclusion block. This prevents attackers from using old certificates
/// with outdated operator sets.
///
/// # Arguments
/// * `header` - Ethereum block header where the certificate is being included
/// * `referenced_height` - Block height referenced by the certificate
/// * `cert_recency_window` - Maximum allowed age of the certificate in blocks
///
/// # Returns
/// `Ok(())` if the certificate is within the recency window
///
/// # Errors
/// Returns [`CertVerificationError::RecencyWindowMissed`] if the certificate
/// is too old relative to the inclusion block.
///
/// # Reference
/// [EigenDA Specification - RBN Recency Validation](https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#1-rbn-recency-validation)
pub fn verify_cert_recency(
    header: &EthereumBlockHeader,
    referenced_height: u64,
    cert_recency_window: u64,
) -> Result<(), CertVerificationError> {
    let inclusion_height = header.height();

    let recency_height = referenced_height + cert_recency_window;
    if inclusion_height > recency_height {
        return Err(CertVerificationError::RecencyWindowMissed(
            inclusion_height,
            recency_height,
        ));
    }

    Ok(())
}

/// Validate encoded payload against certificate commitment
///
/// Verifies that the provided encoded payload matches the cryptographic
/// commitment contained in the certificate using KZG polynomial commitments.
///
/// # Arguments
/// * `cert` - Certificate containing the blob commitment
/// * `encoded_payload` - Encoded payload to validate
///
/// # Returns
/// `Ok(())` if the encoded payload matches the certificate commitment
///
/// # Errors
/// Returns [`BlobVerificationError`] if:
/// - Encoded payload doesn't match the commitment
/// - KZG proof verification fails
/// - Commitment is malformed
///
/// # Reference
/// [EigenDA Specification - Blob Validation](https://layr-labs.github.io/eigenda/integration/spec/6-secure-integration.html#3-blob-validation)
#[instrument(skip_all)]
pub fn verify_blob(
    cert: &StandardCommitment,
    encoded_payload: &[u8],
) -> Result<(), BlobVerificationError> {
    let blob_commitment = &cert
        .blob_inclusion_info()
        .blob_certificate
        .blob_header
        .commitment;

    blob::verify(blob_commitment, encoded_payload)
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Header;
    use eigenda::verification::cert::error::CertVerificationError;

    use crate::eigenda::verification::verify_cert_recency;
    use crate::spec::EthereumBlockHeader;

    /// Helper function to create a mock EthereumBlockHeader with a given height
    fn create_mock_header(height: u64) -> EthereumBlockHeader {
        let header = Header {
            number: height,
            ..Default::default()
        };
        let header = header;
        EthereumBlockHeader::from(header)
    }

    #[test]
    fn verify_cert_recency_success_cases() {
        // Test cases: (description, referenced_height, cert_recency_window, inclusion_height_offset)
        let test_cases = [
            ("exactly at window boundary", 100, 50, 50),
            ("well within window", 100, 50, 40),
            ("same block as reference", 100, 50, 0),
            ("zero window success", 100, 0, 0),
            ("large window", 1000, u64::MAX - 1000, 1000),
            ("edge case max values", u64::MAX - 100, 50, 25),
        ];

        for (description, referenced_height, cert_recency_window, inclusion_offset) in test_cases {
            let inclusion_height = referenced_height + inclusion_offset;
            let header = create_mock_header(inclusion_height);

            let result = verify_cert_recency(&header, referenced_height, cert_recency_window);
            assert_eq!(result, Ok(()), "{description}");
        }
    }

    #[test]
    fn verify_cert_recency_failure_cases() {
        // Test cases: (description, referenced_height, cert_recency_window, inclusion_height_offset)
        let test_cases = [
            ("one block past window", 100, 50, 51),
            ("far past window", 100, 50, 150),
            ("zero window failure", 100, 0, 1),
        ];

        for (description, referenced_height, cert_recency_window, inclusion_offset) in test_cases {
            let inclusion_height = referenced_height + inclusion_offset;
            let header = create_mock_header(inclusion_height);

            let err =
                verify_cert_recency(&header, referenced_height, cert_recency_window).unwrap_err();

            assert_eq!(
                err,
                CertVerificationError::RecencyWindowMissed(
                    inclusion_height,
                    referenced_height + cert_recency_window
                ),
                "{description}"
            );
        }
    }
}
