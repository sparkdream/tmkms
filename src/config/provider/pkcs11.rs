//! Configuration for PKCS#11

use crate::{chain, config::provider::KeyType};
use secrecy::Secret;
use serde::Deserialize;
use std::path::PathBuf;

/// Configuration for the PKCS#11 provider
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pkcs11Config {
    /// Path to the PKCS#11 library middleware.
    pub library_path: PathBuf,
    /// The label of the token (slot) to use.
    pub token_label: String,
    /// Inline PIN for the token's slot.
    /// Prefix with `$` to expand an environment variable at startup
    /// (e.g. `pin = "$KMS_PKCS11_PIN"`). Mutually exclusive with `pin_file`.
    #[serde(default)]
    pub pin: Option<Secret<String>>,
    /// Path to a file whose contents are used as the PIN (whitespace is stripped).
    /// Mutually exclusive with `pin`.
    #[serde(default)]
    pub pin_file: Option<PathBuf>,
    /// Keys available from this provider
    #[serde(default)]
    pub keys: Vec<SigningKeyConfig>,
    /// Maximum number of seconds to wait for a PKCS#11 signing operation.
    /// If the HSM does not respond within this window the signing call fails
    /// with a timeout error instead of blocking indefinitely.
    /// Defaults to `None` (no timeout). Recommended to set in production.
    #[serde(default)]
    pub signing_timeout_secs: Option<u64>,
}

/// Configuration for a specific signing key on a PKCS#11 device
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyConfig {
    /// Type of key
    pub key_type: KeyType,
    /// The label (`CKA_LABEL`) of the private key object on the token.
    pub key_label: String,
    /// Optional `CKA_ID` of the key object on the token (raw bytes).
    /// Useful when multiple keys share the same label.
    #[serde(default)]
    pub key_id: Option<Vec<u8>>,
    /// Chain IDs this key is authorized to sign for
    pub chain_ids: Vec<chain::Id>,
}
