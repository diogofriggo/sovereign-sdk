use alloy_primitives::{
    Address, B256, Bytes, StorageKey, U256,
    aliases::{U96, U192},
    keccak256,
};
use alloy_sol_types::SolValue;
use eigenda_cert_verifier::{
    bitmap::Bitmap,
    error::CertVerificationError,
    hash::TruncatedB256,
    types::{
        BlockNumber, QuorumNumber, RelayKey, Stake, Version,
        history::{History, Update},
        solidity::{SecurityThresholds, StakeUpdate, VersionedBlobParams},
    },
};
use hashbrown::HashMap;
use reth_trie_common::StorageProof;
use thiserror::Error;

use super::types::StandardCommitment;

const RELAY_KEY_TO_RELAY_INFO_MAPPING_SLOT: u64 = 101u64;
const VERSIONED_BLOB_PARAMS_MAPPING_SLOT: u64 = 4;
const QUORUM_COUNT_VARIABLE_SLOT: u64 = 150;
const OPERATOR_BITMAP_HISTORY_MAPPING_SLOT: u64 = 152;
const QUORUM_UPDATE_BLOCK_NUMBER_MAPPING_SLOT: u64 = 155;
const STALE_STAKES_FORBIDDEN_VARIABLE_SLOT: u64 = 0;
const MIN_WITHDRAWAL_DELAY_BLOCKS_VARIABLE_SLOT: u64 = 157;
const APK_HISTORY_MAPPING_SLOT: u64 = 4;
const TOTAL_STAKE_HISTORY_MAPPING_SLOT: u64 = 1;
const OPERATOR_STAKE_HISTORY_MAPPING_SLOT: u64 = 2;
const SECURITY_THRESHOLDS_V2_VARIABLE_SLOT: u64 = 0;
const QUORUM_NUMBERS_REQUIRED_V2_VARIABLE_SLOT: u64 = 1;

pub mod contract {
    use alloy_primitives::StorageKey;

    use crate::eigenda::{
        extraction::{
            ApkHistoryExtractor, MinWithdrawalDelayBlocksExtractor, OperatorBitmapHistoryExtractor,
            OperatorStakeHistoryExtractor, QuorumCountExtractor, QuorumNumbersRequiredV2Extractor,
            QuorumUpdateBlockNumberExtractor, RelayKeyToRelayInfoExtractor,
            SecurityThresholdsV2Extractor, StaleStakesForbiddenExtractor, StorageKeyProvider,
            TotalStakeHistoryExtractor, VersionedBlobParamsExtractor,
        },
        types::StandardCommitment,
    };

    pub struct EigenDaRelayRegistry;

    impl EigenDaRelayRegistry {
        pub fn storage_keys(certificate: &StandardCommitment) -> Vec<StorageKey> {
            RelayKeyToRelayInfoExtractor::new(certificate).storage_keys()
        }
    }

    pub struct BlsSignatureChecker;

    impl BlsSignatureChecker {
        pub fn storage_keys(certificate: &StandardCommitment) -> Vec<StorageKey> {
            StaleStakesForbiddenExtractor::new(certificate).storage_keys()
        }
    }

    pub struct DelegationManager;

    impl DelegationManager {
        pub fn storage_keys(certificate: &StandardCommitment) -> Vec<StorageKey> {
            MinWithdrawalDelayBlocksExtractor::new(certificate).storage_keys()
        }
    }

    pub struct RegistryCoordinator;

    impl RegistryCoordinator {
        pub fn storage_keys(certificate: &StandardCommitment) -> Vec<StorageKey> {
            let quorum_count = QuorumCountExtractor::new(certificate).storage_keys();
            let quorum_bitmap_history =
                OperatorBitmapHistoryExtractor::new(certificate).storage_keys();
            let quorum_update_block_number =
                QuorumUpdateBlockNumberExtractor::new(certificate).storage_keys();

            [
                quorum_count,
                quorum_bitmap_history,
                quorum_update_block_number,
            ]
            .into_iter()
            .flatten()
            .collect()
        }
    }

    pub struct StakeRegistry;

    impl StakeRegistry {
        pub fn storage_keys(certificate: &StandardCommitment) -> Vec<StorageKey> {
            let operator_stake_history =
                OperatorStakeHistoryExtractor::new(certificate).storage_keys();
            let total_stake_history = TotalStakeHistoryExtractor::new(certificate).storage_keys();

            [operator_stake_history, total_stake_history]
                .into_iter()
                .flatten()
                .collect()
        }
    }

    pub struct BlsApkRegistry;

    impl BlsApkRegistry {
        pub fn storage_keys(certificate: &StandardCommitment) -> Vec<StorageKey> {
            ApkHistoryExtractor::new(certificate).storage_keys()
        }
    }

    pub struct EigenDaThresholdRegistry;

    impl EigenDaThresholdRegistry {
        pub fn storage_keys(certificate: &StandardCommitment) -> Vec<StorageKey> {
            VersionedBlobParamsExtractor::new(certificate).storage_keys()
        }
    }

    pub struct EigenDaCertVerifier;

    impl EigenDaCertVerifier {
        pub fn storage_keys(certificate: &StandardCommitment) -> Vec<StorageKey> {
            let security_thresholds =
                SecurityThresholdsV2Extractor::new(certificate).storage_keys();
            let required_quorum_numbers =
                QuorumNumbersRequiredV2Extractor::new(certificate).storage_keys();

            [security_thresholds, required_quorum_numbers]
                .into_iter()
                .flatten()
                .collect()
        }
    }
}

/// Helper functions for common storage key generation patterns
pub mod storage_key_helpers {
    use super::*;

    /// Generate a simple storage key from a slot number: keccak256(abi.encode(slot))
    pub fn simple_slot_key(slot: u64) -> StorageKey {
        let slot = U256::from(slot);
        keccak256(slot.abi_encode())
    }

    /// Generate storage key for a mapping: keccak256(abi.encode(key, slot))
    pub fn mapping_key(key: U256, slot: u64) -> StorageKey {
        let slot = U256::from(slot);
        keccak256((key, slot).abi_encode())
    }

    /// Generate storage key for dynamic array element: keccak256(keccak256(abi.encode(key, slot))) + index
    pub fn dynamic_array_key(key: U256, slot: u64, index: u32) -> StorageKey {
        let slot = U256::from(slot);
        let length_base = keccak256((key, slot).abi_encode());
        let data_base: U256 = keccak256(length_base).into();
        (data_base + U256::from(index)).into()
    }

    /// Generate nested mapping key for dynamic array:
    /// keccak256(abi.encode(second_key,    keccak256(abi.encode(first_key, slot))    )) + index
    pub fn nested_dynamic_array_key(
        first_key: U256,
        slot: u64,
        second_key: U256,
        index: u32,
    ) -> StorageKey {
        let slot = U256::from(slot);
        let b1 = keccak256((first_key, slot).abi_encode());
        let b2 = keccak256((second_key, b1).abi_encode());
        let data_base: U256 = keccak256(b2).into();
        (data_base + U256::from(index)).into()
    }
}

/// Helper functions for common data decoding operations
pub mod decode_helpers {
    use super::*;

    /// Find a storage proof by key and return error if missing
    pub fn find_required_proof<'a>(
        proofs: &'a [StorageProof],
        key: &StorageKey,
        variable_name: &'static str,
    ) -> Result<&'a StorageProof, ExtractionError> {
        find_proof(proofs, key).ok_or(ExtractionError::MissingData(variable_name))
    }

    /// Find a storage proof by key
    pub fn find_proof<'a>(
        proofs: &'a [StorageProof],
        key: &StorageKey,
    ) -> Option<&'a StorageProof> {
        proofs.iter().find(|proof| proof.key == *key)
    }

    /// Create an Update object from extracted block numbers and value
    pub fn create_update<T: Copy>(
        update_block: u32,
        next_update_block: u32,
        value: T,
    ) -> Result<Update<T>, ExtractionError> {
        Update::new(update_block, next_update_block, value)
            .map_err(ExtractionError::CertVerification)
    }

    /// Remove trailing zeros from a byte slice
    pub fn trim_trailing_zeros(bytes: &[u8]) -> &[u8] {
        let mut end = bytes.len();
        while end > 0 && bytes[end - 1] == 0 {
            end -= 1;
        }
        &bytes[..end]
    }
}

#[derive(Error, Debug)]
pub enum ExtractionError {
    #[error("Failed to extract {0}, data not found")]
    MissingData(&'static str),

    #[error("AbiEncode error: {0}")]
    AbiEncode(#[from] alloy_sol_types::Error),

    #[error("CertVerificationError error: {0}")]
    CertVerification(#[from] CertVerificationError),
}

pub trait StorageKeyProvider {
    fn storage_keys(&self) -> Vec<StorageKey>;
}

pub trait DataDecoder: StorageKeyProvider {
    type Output;

    fn decode_data(&self, storage_proofs: &[StorageProof])
    -> Result<Self::Output, ExtractionError>;
}

pub struct QuorumCountExtractor;

impl QuorumCountExtractor {
    pub fn new(_certificate: &StandardCommitment) -> Self {
        Self {}
    }
}

impl StorageKeyProvider for QuorumCountExtractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        vec![storage_key_helpers::simple_slot_key(
            QUORUM_COUNT_VARIABLE_SLOT,
        )]
    }
}

impl DataDecoder for QuorumCountExtractor {
    type Output = u8;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        let storage_key = &self.storage_keys()[0];
        let proof =
            decode_helpers::find_required_proof(storage_proofs, storage_key, "quorumCount")?;
        let quorum_count = proof.value.to::<u8>();
        Ok(quorum_count)
    }
}

pub struct StaleStakesForbiddenExtractor;

impl StaleStakesForbiddenExtractor {
    pub fn new(_certificate: &StandardCommitment) -> Self {
        Self {}
    }
}

impl StorageKeyProvider for StaleStakesForbiddenExtractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        vec![storage_key_helpers::simple_slot_key(
            STALE_STAKES_FORBIDDEN_VARIABLE_SLOT,
        )]
    }
}

impl DataDecoder for StaleStakesForbiddenExtractor {
    type Output = bool;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        let storage_key = &self.storage_keys()[0];
        let proof =
            decode_helpers::find_required_proof(storage_proofs, storage_key, "quorumCount")?;
        Ok(proof.value.is_zero())
    }
}

pub struct MinWithdrawalDelayBlocksExtractor;

impl MinWithdrawalDelayBlocksExtractor {
    pub fn new(_certificate: &StandardCommitment) -> Self {
        Self {}
    }
}

impl StorageKeyProvider for MinWithdrawalDelayBlocksExtractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        vec![storage_key_helpers::simple_slot_key(
            MIN_WITHDRAWAL_DELAY_BLOCKS_VARIABLE_SLOT,
        )]
    }
}

impl DataDecoder for MinWithdrawalDelayBlocksExtractor {
    type Output = u32;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        let storage_key = &self.storage_keys()[0];
        let proof =
            decode_helpers::find_required_proof(storage_proofs, storage_key, "quorumCount")?;
        let min_withdrawal_delay_blocks = proof.value.to::<u32>();
        Ok(min_withdrawal_delay_blocks)
    }
}

pub struct QuorumUpdateBlockNumberExtractor {
    pub signed_quorum_numbers: Bytes,
}

impl QuorumUpdateBlockNumberExtractor {
    pub fn new(certificate: &StandardCommitment) -> Self {
        Self {
            signed_quorum_numbers: certificate.signed_quorum_numbers().clone(),
        }
    }
}

impl StorageKeyProvider for QuorumUpdateBlockNumberExtractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        self.signed_quorum_numbers
            .iter()
            .map(|&quorum_number| {
                storage_key_helpers::mapping_key(
                    U256::from(quorum_number),
                    QUORUM_UPDATE_BLOCK_NUMBER_MAPPING_SLOT,
                )
            })
            .collect()
    }
}

impl DataDecoder for QuorumUpdateBlockNumberExtractor {
    type Output = HashMap<QuorumNumber, BlockNumber>;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        self.storage_keys()
            .iter()
            .zip(self.signed_quorum_numbers.iter())
            .map(|(storage_key, &quorum_number)| {
                decode_helpers::find_required_proof(
                    storage_proofs,
                    storage_key,
                    "quorumUpdateBlockNumber",
                )
                .map(|proof| {
                    let block_number = proof.value.to::<BlockNumber>();
                    (quorum_number, block_number)
                })
            })
            .collect()
    }
}

pub struct RelayKeyToRelayInfoExtractor {
    pub relay_keys: Vec<RelayKey>,
}

impl RelayKeyToRelayInfoExtractor {
    pub fn new(certificate: &StandardCommitment) -> Self {
        Self {
            relay_keys: certificate.relay_keys().to_vec(),
        }
    }
}

impl StorageKeyProvider for RelayKeyToRelayInfoExtractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        self.relay_keys
            .iter()
            .map(|&relay_key| {
                storage_key_helpers::mapping_key(
                    U256::from(relay_key),
                    RELAY_KEY_TO_RELAY_INFO_MAPPING_SLOT,
                )
            })
            .collect()
    }
}

impl DataDecoder for RelayKeyToRelayInfoExtractor {
    type Output = HashMap<RelayKey, Address>;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        self.storage_keys()
            .iter()
            .zip(self.relay_keys.iter())
            .map(|(storage_key, &relay_key)| {
                decode_helpers::find_required_proof(storage_proofs, storage_key, "relayKeyToInfo")
                    .map(|proof| (relay_key, Address::from_word(proof.value.into())))
            })
            .collect()
    }
}

pub struct VersionedBlobParamsExtractor {
    pub version: u16,
}

impl VersionedBlobParamsExtractor {
    pub fn new(certificate: &StandardCommitment) -> Self {
        Self {
            version: certificate.version(),
        }
    }
}

impl StorageKeyProvider for VersionedBlobParamsExtractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        let version = U256::from(self.version);
        vec![storage_key_helpers::mapping_key(
            version,
            VERSIONED_BLOB_PARAMS_MAPPING_SLOT,
        )]
    }
}

impl DataDecoder for VersionedBlobParamsExtractor {
    type Output = HashMap<Version, VersionedBlobParams>;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        let storage_key = &self.storage_keys()[0];
        let proof = decode_helpers::find_required_proof(
            storage_proofs,
            storage_key,
            "versionedBlobParams",
        )?;
        let le = proof.value.to_le_bytes::<9>();

        let key = self.version;
        let value = VersionedBlobParams {
            maxNumOperators: u32::from_le_bytes(le[0..4].try_into().unwrap()),
            numChunks: u32::from_le_bytes(le[4..8].try_into().unwrap()),
            codingRate: le[8],
        };
        let versioned_blob_params = HashMap::from([(key, value)]);
        Ok(versioned_blob_params)
    }
}

pub struct OperatorBitmapHistoryExtractor {
    pub non_signers_pk_hashes: Vec<B256>,
    pub non_signer_quorum_bitmap_indices: Vec<u32>,
}

impl OperatorBitmapHistoryExtractor {
    pub fn new(certificate: &StandardCommitment) -> Self {
        Self {
            non_signers_pk_hashes: certificate.non_signers_pk_hashes(),
            non_signer_quorum_bitmap_indices: certificate
                .non_signer_quorum_bitmap_indices()
                .to_vec(),
        }
    }
}

impl StorageKeyProvider for OperatorBitmapHistoryExtractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        self.non_signers_pk_hashes
            .iter()
            .zip(self.non_signer_quorum_bitmap_indices.iter())
            .map(|(&operator_id, &index)| {
                storage_key_helpers::dynamic_array_key(
                    operator_id.into(),
                    OPERATOR_BITMAP_HISTORY_MAPPING_SLOT,
                    index,
                )
            })
            .collect()
    }
}

impl DataDecoder for OperatorBitmapHistoryExtractor {
    type Output = HashMap<B256, History<Bitmap>>;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        self.storage_keys()
            .iter()
            .zip(self.non_signers_pk_hashes.iter())
            .zip(self.non_signer_quorum_bitmap_indices.iter())
            .map(|((&storage_key, &operator_id), &index)| {
                let proof = decode_helpers::find_required_proof(
                    storage_proofs,
                    &storage_key,
                    "_operatorBitmapHistory",
                )?;
                let le = proof.value.to_le_bytes::<32>();
                let update_block = u32::from_le_bytes(le[0..4].try_into().unwrap());
                let next_update_block = u32::from_le_bytes(le[4..8].try_into().unwrap());

                let quorum_bitmap = U192::from_le_bytes::<24>(le[8..32].try_into().unwrap());
                let [lo, mid, hi] = quorum_bitmap.into_limbs();
                let bitmap = Bitmap::new([lo, mid, hi, 0]);

                let update =
                    decode_helpers::create_update(update_block, next_update_block, bitmap)?;
                let history = HashMap::from([(index, update)]);

                Ok((operator_id.into(), History(history)))
            })
            .collect()
    }
}

pub struct ApkHistoryExtractor {
    pub signed_quorum_numbers: Bytes,
    pub quorum_apk_indices: Vec<u32>,
}

// TODO: make structs generic over lifetime
impl ApkHistoryExtractor {
    pub fn new(certificate: &StandardCommitment) -> Self {
        Self {
            signed_quorum_numbers: certificate.signed_quorum_numbers().clone(),
            quorum_apk_indices: certificate.quorum_apk_indices().to_vec(),
        }
    }
}

impl StorageKeyProvider for ApkHistoryExtractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        self.signed_quorum_numbers
            .iter()
            .zip(self.quorum_apk_indices.iter())
            .map(|(&signed_quorum_number, &index)| {
                storage_key_helpers::dynamic_array_key(
                    U256::from(signed_quorum_number),
                    APK_HISTORY_MAPPING_SLOT,
                    index,
                )
            })
            .collect()
    }
}

impl DataDecoder for ApkHistoryExtractor {
    type Output = HashMap<QuorumNumber, History<TruncatedB256>>;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        self.storage_keys()
            .iter()
            .zip(self.signed_quorum_numbers.iter())
            .zip(self.quorum_apk_indices.iter())
            .map(|((&storage_key, &signed_quorum_number), &index)| {
                let proof = decode_helpers::find_required_proof(
                    storage_proofs,
                    &storage_key,
                    "apkHistory",
                )?;
                let le = proof.value.to_le_bytes::<32>();

                let apk_hash_bytes: [u8; 24] = le[..24].try_into().unwrap();
                let apk_hash: TruncatedB256 = apk_hash_bytes.into();
                let update_block = u32::from_le_bytes(le[24..28].try_into().unwrap());
                let next_update_block = u32::from_le_bytes(le[28..32].try_into().unwrap());

                let update =
                    decode_helpers::create_update(update_block, next_update_block, apk_hash)?;
                let history = HashMap::from([(index, update)]);
                Ok((signed_quorum_number, History(history)))
            })
            .collect()
    }
}

pub struct TotalStakeHistoryExtractor {
    pub signed_quorum_numbers: Bytes,
    pub non_signer_total_stake_indices: Vec<u32>,
}

impl TotalStakeHistoryExtractor {
    pub fn new(certificate: &StandardCommitment) -> Self {
        Self {
            signed_quorum_numbers: certificate.signed_quorum_numbers().clone(),
            non_signer_total_stake_indices: certificate.non_signer_total_stake_indices().to_vec(),
        }
    }
}

impl StorageKeyProvider for TotalStakeHistoryExtractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        self.signed_quorum_numbers
            .iter()
            .zip(self.non_signer_total_stake_indices.iter())
            .map(|(&signed_quorum_number, &index)| {
                storage_key_helpers::dynamic_array_key(
                    U256::from(signed_quorum_number),
                    TOTAL_STAKE_HISTORY_MAPPING_SLOT,
                    index,
                )
            })
            .collect()
    }
}

impl DataDecoder for TotalStakeHistoryExtractor {
    type Output = HashMap<QuorumNumber, History<Stake>>;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        self.storage_keys()
            .iter()
            .zip(self.signed_quorum_numbers.iter())
            .zip(self.non_signer_total_stake_indices.iter())
            .map(|((&storage_key, &signed_quorum_number), &index)| {
                let proof = decode_helpers::find_required_proof(
                    storage_proofs,
                    &storage_key,
                    "_totalStakeHistory",
                )?;
                let le = proof.value.to_le_bytes::<32>();
                let stake_update = StakeUpdate {
                    updateBlockNumber: u32::from_le_bytes(le[0..4].try_into().unwrap()),
                    nextUpdateBlockNumber: u32::from_le_bytes(le[4..8].try_into().unwrap()),
                    stake: U96::from_le_bytes::<12>(le[8..20].try_into().unwrap()),
                };

                let stake = stake_update.stake.to::<U96>();
                let update = decode_helpers::create_update(
                    stake_update.updateBlockNumber,
                    stake_update.nextUpdateBlockNumber,
                    stake,
                )?;

                let history = HashMap::from([(index, update)]);
                Ok((signed_quorum_number, History(history)))
            })
            .collect()
    }
}

pub struct OperatorStakeHistoryExtractor {
    pub signed_quorum_numbers: Bytes,
    pub non_signers_pk_hashes: Vec<B256>,
    pub non_signer_stake_indices: Vec<Vec<u32>>,
}

impl OperatorStakeHistoryExtractor {
    pub fn new(certificate: &StandardCommitment) -> Self {
        Self {
            signed_quorum_numbers: certificate.signed_quorum_numbers().clone(),
            non_signers_pk_hashes: certificate.non_signers_pk_hashes(),
            non_signer_stake_indices: certificate.non_signer_stake_indices().to_vec(),
        }
    }
}

impl StorageKeyProvider for OperatorStakeHistoryExtractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        let mut storage_keys = vec![];

        for (&signed_quorum_number, stake_index_for_each_required_non_signer) in self
            .signed_quorum_numbers
            .iter()
            .zip(&self.non_signer_stake_indices)
        {
            for &operator_id in &self.non_signers_pk_hashes {
                // without peeking at the actual data it's impossible to associate indices with
                // any one non_signer so it's necessary to do this cartesian product. Storage keys
                // that map to non-existent data will return empty but won't fail
                for &stake_index in stake_index_for_each_required_non_signer {
                    let storage_key = storage_key_helpers::nested_dynamic_array_key(
                        operator_id.into(),
                        OPERATOR_STAKE_HISTORY_MAPPING_SLOT,
                        U256::from(signed_quorum_number),
                        stake_index,
                    );
                    storage_keys.push(storage_key);
                }
            }
        }

        storage_keys
    }
}

impl DataDecoder for OperatorStakeHistoryExtractor {
    type Output = HashMap<B256, HashMap<QuorumNumber, History<Stake>>>;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        let mut out: HashMap<B256, HashMap<QuorumNumber, History<Stake>>> = HashMap::new();

        for (&signed_quorum_number, stake_index_for_each_required_non_signer) in self
            .signed_quorum_numbers
            .iter()
            .zip(&self.non_signer_stake_indices)
        {
            for &operator_id in &self.non_signers_pk_hashes {
                // Same cartesian product is necessary as for the StorageKeyProvider impl
                for &stake_index in stake_index_for_each_required_non_signer {
                    let storage_key = storage_key_helpers::nested_dynamic_array_key(
                        operator_id.into(),
                        OPERATOR_STAKE_HISTORY_MAPPING_SLOT,
                        U256::from(signed_quorum_number),
                        stake_index,
                    );

                    let proof = decode_helpers::find_required_proof(
                        storage_proofs,
                        &storage_key,
                        "operatorStakeHistory",
                    )?;
                    let le = proof.value.to_le_bytes::<20>();
                    let stake_update = StakeUpdate {
                        updateBlockNumber: u32::from_le_bytes(le[0..4].try_into().unwrap()),
                        nextUpdateBlockNumber: u32::from_le_bytes(le[4..8].try_into().unwrap()),
                        stake: U96::from_le_bytes::<12>(le[8..20].try_into().unwrap()),
                    };

                    let stake = stake_update.stake.to::<U96>();
                    let update = decode_helpers::create_update(
                        stake_update.updateBlockNumber,
                        stake_update.nextUpdateBlockNumber,
                        stake,
                    )?;

                    let operator_id: B256 = operator_id.into();

                    out.entry(operator_id)
                        .or_default()
                        .entry(signed_quorum_number)
                        .or_insert_with(|| History(HashMap::new()))
                        .0
                        .insert(stake_index, update);
                }
            }
        }

        Ok(out)
    }
}

pub struct SecurityThresholdsV2Extractor;

impl SecurityThresholdsV2Extractor {
    pub fn new(_certificate: &StandardCommitment) -> Self {
        Self {}
    }
}

impl StorageKeyProvider for SecurityThresholdsV2Extractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        vec![storage_key_helpers::simple_slot_key(
            SECURITY_THRESHOLDS_V2_VARIABLE_SLOT,
        )]
    }
}

impl DataDecoder for SecurityThresholdsV2Extractor {
    type Output = SecurityThresholds;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        let storage_key = &self.storage_keys()[0];
        let proof =
            decode_helpers::find_required_proof(storage_proofs, storage_key, "quorumCount")?;

        let [confirmation_threshold, adversary_threshold] = proof.value.to_le_bytes::<2>();

        Ok(SecurityThresholds {
            confirmationThreshold: confirmation_threshold,
            adversaryThreshold: adversary_threshold,
        })
    }
}

pub struct QuorumNumbersRequiredV2Extractor;

impl QuorumNumbersRequiredV2Extractor {
    pub fn new(_certificate: &StandardCommitment) -> Self {
        Self {}
    }
}

impl StorageKeyProvider for QuorumNumbersRequiredV2Extractor {
    fn storage_keys(&self) -> Vec<StorageKey> {
        vec![storage_key_helpers::simple_slot_key(
            QUORUM_NUMBERS_REQUIRED_V2_VARIABLE_SLOT,
        )]
    }
}

impl DataDecoder for QuorumNumbersRequiredV2Extractor {
    type Output = Bytes;

    fn decode_data(
        &self,
        storage_proofs: &[StorageProof],
    ) -> Result<Self::Output, ExtractionError> {
        let storage_key = &self.storage_keys()[0];
        let proof =
            decode_helpers::find_required_proof(storage_proofs, storage_key, "quorumCount")?;

        // there can be at most 256 quorums
        let bytes = proof.value.to_le_bytes::<32>();

        // quorum numbers are ordered so it's safe (and necessary) to trim
        let bytes = decode_helpers::trim_trailing_zeros(&bytes);

        Ok(bytes.to_vec().into())
    }
}
