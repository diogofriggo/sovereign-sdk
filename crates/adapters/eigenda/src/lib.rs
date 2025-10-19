//! Sovereign SDK adapter for EigenDA data availability layer.
//!
//! This crate provides integration between Sovereign SDK rollups and EigenDA,
//! enabling efficient blob storage and verification on the EigenDA network.
//!
//! ## Architecture
//!
//! This is the main orchestration crate that coordinates several specialized crates:
//! - [`eigenda_ethereum`]: Handles Ethereum contract interaction and provider utilities
//! - [`eigenda_proxy`]: Manages communication with EigenDA proxy services
//! - [`eigenda_verification`]: Provides certificate parsing, state extraction, and cryptographic verification
//!
//! The main entry points are the [`service::EigenDaService`] and [`verifier::EigenDaVerifier`]
//! implementations that provide the Sovereign SDK integration.

#[cfg(feature = "native")]
/// Service layer implementing [`sov_rollup_interface::node::da::DaService`] trait for EigenDA integration.
///
/// Coordinates [`eigenda_ethereum`], [`eigenda_proxy`], and [`eigenda_verification`]
/// crates to provide complete data availability functionality including blob
/// retrieval, certificate extraction, and state proof generation.
pub mod service;

/// Core types and trait implementations for EigenDA data availability specification.
///
/// Defines the main [`spec::EigenDaSpec`] implementation and rollup configuration types
/// used throughout the adapter.
pub mod spec;

/// Cryptographic verification of transaction inclusion and completeness proofs.
///
/// Implements [`sov_rollup_interface::da::DaVerifier`] trait using [`eigenda_verification`] for certificate
/// validation and blob verification against EigenDA commitments.
pub mod verifier;
