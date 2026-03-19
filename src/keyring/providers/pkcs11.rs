//! PKCS#11 provider signer

use crate::{
    chain,
    config::provider::{
        pkcs11::{Pkcs11Config, SigningKeyConfig},
        KeyType,
    },
    error::{Error, ErrorKind::*},
    keyring::{self, ed25519::Signature as Ed25519Signature, SigningProvider},
    prelude::*,
};
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    error::RvError,
    mechanism::{
        eddsa::{EddsaParams, EddsaSignatureScheme},
        Mechanism,
    },
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
};
use secrecy::ExposeSecret;
use signature::Signer;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use zeroize::Zeroizing;
use cometbft::{CometbftKey, PublicKey};

/// PKCS#11 token labels are fixed at 32 bytes in the `CK_TOKEN_INFO` struct.
const PKCS11_TOKEN_LABEL_MAX_LEN: usize = 32;

/// Create hardware-backed PKCS#11 signer objects from the given configuration
pub fn init(
    chain_registry: &mut chain::Registry,
    pkcs11_configs: &[Pkcs11Config],
) -> Result<(), Error> {
    info!("Initializing PKCS#11 provider");

    if pkcs11_configs.is_empty() {
        return Ok(());
    }

    // PKCS#11 libraries are global singletons: calling Pkcs11::initialize() twice within
    // the same process results in CKR_CRYPTOKI_ALREADY_INITIALIZED. Until multi-library
    // support is needed, enforce exactly one [[providers.pkcs11]] section to keep the
    // implementation simple and safe.
    if pkcs11_configs.len() != 1 {
        fail!(
            ConfigError,
            "expected one [[providers.pkcs11]] section in config, found: {}",
            pkcs11_configs.len()
        );
    }

    let config = &pkcs11_configs[0];

    // Validate token_label fits in PKCS#11's 32-byte CK_TOKEN_INFO label field.
    // A longer label can never match any real token and the mismatch is silent.
    if config.token_label.len() > PKCS11_TOKEN_LABEL_MAX_LEN {
        fail!(
            ConfigError,
            "PKCS#11 token_label '{}' is {} bytes, exceeding the {}-byte PKCS#11 limit; \
             shorten the label",
            config.token_label,
            config.token_label.len(),
            PKCS11_TOKEN_LABEL_MAX_LEN
        );
    }

    let signing_timeout = match config.signing_timeout_secs {
        Some(0) => fail!(
            ConfigError,
            "PKCS#11 signing_timeout_secs must be greater than zero"
        ),
        Some(secs) => Some(Duration::from_secs(secs)),
        None => None,
    };
    let pin = resolve_pin(config)?;
    let (pkcs11, slot) = open_pkcs11_slot(config)?;
    let session = open_session(&pkcs11, slot, &pin)?;
    let state = Arc::new(Mutex::new(SessionState {
        pkcs11,
        slot,
        pin,
        session,
    }));

    if config.keys.is_empty() {
        warn!("PKCS#11 provider is enabled but no keys are configured");
    }

    for key_config in &config.keys {
        // An empty label would match any key on the token — reject it early.
        if key_config.key_label.is_empty() {
            fail!(
                ConfigError,
                "PKCS#11 key_label must not be empty in [[providers.pkcs11.keys]]"
            );
        }

        let signer = Pkcs11Signer::new(state.clone(), key_config, signing_timeout)?;

        match key_config.key_type {
            KeyType::Account => {
                fail!(ConfigError, "PKCS#11 account keys (secp256k1) are not yet supported");
            }
            KeyType::Consensus => add_consensus_key(chain_registry, signer, key_config)?,
        }
    }

    Ok(())
}

/// Resolve the PIN from the config: inline value (with `$ENV_VAR` expansion) or a file.
/// Fails if neither or both of `pin` and `pin_file` are set.
fn resolve_pin(config: &Pkcs11Config) -> Result<Zeroizing<String>, Error> {
    match (&config.pin, &config.pin_file) {
        (Some(secret), None) => {
            let raw = secret.expose_secret();
            if let Some(var_name) = raw.strip_prefix('$') {
                std::env::var(var_name).map(Zeroizing::new).map_err(|_| {
                    format_err!(
                        ConfigError,
                        "env var ${} is not set (required for PKCS#11 PIN)",
                        var_name
                    )
                    .into()
                })
            } else {
                Ok(Zeroizing::new(raw.clone()))
            }
        }
        (None, Some(path)) => {
            // Resolve symlinks so we check and read the real file, preventing a
            // symlink at pin_file from silently redirecting to an unintended path.
            let canonical = path.canonicalize().map_err(|e| {
                format_err!(
                    IoError,
                    "failed to resolve PKCS#11 pin_file '{}': {}",
                    path.display(),
                    e
                )
            })?;

            // Best-effort permissions check: warn if the PIN file is readable by
            // group or others. This is a defence-in-depth hint — the actual read
            // below will fail with a clear error if the file is inaccessible.
            #[cfg(unix)]
            check_pin_file_permissions(&canonical);

            if canonical != path.as_path() {
                info!(
                    "PKCS#11 pin_file '{}' resolved to '{}'",
                    path.display(),
                    canonical.display()
                );
            }

            std::fs::read_to_string(&canonical)
                .map(|s| Zeroizing::new(s.trim().to_owned()))
                .map_err(|e| {
                    format_err!(
                        IoError,
                        "failed to read PKCS#11 pin_file '{}': {}",
                        path.display(),
                        e
                    )
                    .into()
                })
        }
        (Some(_), Some(_)) => fail!(
            ConfigError,
            "`pin` and `pin_file` are mutually exclusive in [[providers.pkcs11]]"
        ),
        (None, None) => fail!(
            ConfigError,
            "one of `pin` or `pin_file` must be set in [[providers.pkcs11]]"
        ),
    }
}

/// Emit a warning if `path` is readable by group or others.
///
/// Called as a best-effort check only — failures are logged at debug level
/// rather than propagated, because the subsequent file read will surface a
/// clearer error if the file is truly inaccessible.
#[cfg(unix)]
fn check_pin_file_permissions(path: &std::path::Path) {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Err(e) => {
            debug!(
                "could not stat PKCS#11 pin_file '{}': {}",
                path.display(),
                e
            );
        }
        Ok(metadata) => {
            let mode = metadata.mode();
            // Any group or other access (read, write, or execute)
            if mode & 0o077 != 0 {
                warn!(
                    "PKCS#11 pin_file '{}' has insecure permissions ({:04o}); \
                     restrict with: chmod 600 {}",
                    path.display(),
                    mode & 0o777,
                    path.display()
                );
            }
        }
    }
}

/// Add a consensus key (Ed25519) to the keychain
fn add_consensus_key(
    chain_registry: &mut chain::Registry,
    signer: Pkcs11Signer,
    config: &SigningKeyConfig,
) -> Result<(), Error> {
    let public_key = signer.public_key();

    let signer = keyring::ed25519::Signer::new(
        SigningProvider::Pkcs11,
        CometbftKey::ConsensusKey(public_key),
        Box::new(signer),
    );

    for chain_id in &config.chain_ids {
        chain_registry.add_consensus_key(chain_id, signer.clone())?;
    }

    Ok(())
}

/// Shared state for a PKCS#11 session, including everything needed to reconnect.
struct SessionState {
    pkcs11: Pkcs11,
    slot: Slot,
    /// PIN stored as a zeroizing string so it is wiped from memory on drop.
    pin: Zeroizing<String>,
    session: Session,
}

impl SessionState {
    /// Re-establish a lost or expired session with the HSM.
    fn reconnect(&mut self) -> Result<(), Error> {
        info!("PKCS#11 session lost; attempting to reconnect");
        self.session = open_session(&self.pkcs11, self.slot, &self.pin)?;
        Ok(())
    }
}

/// A clonable signing provider for PKCS#11 devices.
///
/// The private key `ObjectHandle` is intentionally NOT cached here.
/// Handles are session-scoped in PKCS#11: after a session is closed and
/// re-opened (reconnect), old handles become invalid. Looking up the handle
/// fresh on each sign call avoids stale-handle errors after reconnects.
#[derive(Clone)]
pub struct Pkcs11Signer {
    state: Arc<Mutex<SessionState>>,
    key_label: String,
    key_id: Option<Vec<u8>>,
    public_key: PublicKey,
    /// If set, signing operations that exceed this duration return an error
    /// instead of blocking indefinitely (e.g. when the HSM is hung or removed).
    signing_timeout: Option<Duration>,
    /// Shared flag set to `true` when a signing call times out while the
    /// background thread still holds the session mutex. Once set, all future
    /// `try_sign` calls return an immediate error instead of blocking on the
    /// mutex that the hung thread may still be holding. Restart tmkms to reset.
    session_hung: Arc<AtomicBool>,
}

impl Pkcs11Signer {
    /// Create a new PKCS#11 signer for a specific key.
    fn new(
        state_arc: Arc<Mutex<SessionState>>,
        config: &SigningKeyConfig,
        signing_timeout: Option<Duration>,
    ) -> Result<Self, Error> {
        let state = state_arc
            .lock()
            .map_err(|_| format_err!(PoisonError, "PKCS#11 session mutex is poisoned"))?;

        let key_id = config.key_id.as_deref();

        // Validate the private key exists and is permitted to sign.
        let private_key_object = find_single_key_object(
            &state.session,
            ObjectClass::PRIVATE_KEY,
            &config.key_label,
            key_id,
        )?;

        let sign_attrs = state
            .session
            .get_attributes(private_key_object, &[AttributeType::Sign])?;
        let can_sign = sign_attrs.iter().any(|a| matches!(a, Attribute::Sign(true)));
        if !can_sign {
            fail!(
                InvalidKey,
                "PKCS#11 private key '{}' does not have CKA_SIGN set to true",
                &config.key_label
            );
        }

        let public_key = fetch_public_key(&state.session, &config.key_label, key_id)?;

        drop(state);

        Ok(Self {
            state: state_arc,
            key_label: config.key_label.clone(),
            key_id: config.key_id.clone(),
            public_key,
            signing_timeout,
            session_hung: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Get the public key for this signer.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Execute the sign operation, holding the session mutex for the duration.
    ///
    /// Called either directly (no timeout) or from a background thread (timeout
    /// path). Reconnects only on session-expiry errors; other errors are
    /// propagated immediately without an unnecessary reconnect attempt.
    fn do_sign(&self, msg: &[u8]) -> Result<Ed25519Signature, signature::Error> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| format_err!(PoisonError, "PKCS#11 session mutex is poisoned"))
            .map_err(signature::Error::from_source)?;

        let mechanism = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519));
        let key_id = self.key_id.as_deref();

        // Attempt the full operation (find handle + sign). The handle lookup and
        // the sign call are combined so that any PKCS#11 session error — including
        // CKR_SESSION_HANDLE_INVALID from an expired session — triggers the
        // reconnect path. Non-session errors (e.g. key not found, CKA_SIGN=false)
        // are propagated immediately without an unnecessary reconnect.
        let signature_bytes =
            match sign_with_session(&state.session, &mechanism, &self.key_label, key_id, msg) {
                Ok(bytes) => bytes,
                Err(e) => {
                    if !is_session_error(&e) {
                        return Err(signature::Error::from_source(e));
                    }

                    warn!(
                        "PKCS#11 session error ({}); attempting to reconnect",
                        e
                    );
                    state
                        .reconnect()
                        .map_err(signature::Error::from_source)?;

                    // After reconnect, verify the public key on the HSM still matches
                    // the key we were initialized with. A mismatch indicates the device
                    // or library was swapped and we must not continue signing.
                    let current_key =
                        fetch_public_key(&state.session, &self.key_label, key_id)
                            .map_err(signature::Error::from_source)?;
                    if current_key != self.public_key {
                        return Err(signature::Error::from_source(format_err!(
                            VerificationError,
                            "PKCS#11 public key mismatch after reconnect for key '{}': \
                             HSM key has changed — refusing to sign",
                            self.key_label
                        )));
                    }

                    sign_with_session(
                        &state.session,
                        &mechanism,
                        &self.key_label,
                        key_id,
                        msg,
                    )
                    .map_err(signature::Error::from_source)?
                }
            };

        Ed25519Signature::try_from(signature_bytes.as_slice())
    }
}

impl Signer<Ed25519Signature> for Pkcs11Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<Ed25519Signature, signature::Error> {
        match self.signing_timeout {
            // No timeout configured: sign synchronously on the caller's thread.
            None => self.do_sign(msg),

            // Timeout configured: run the sign operation on a background thread
            // and wait at most `timeout`. If the HSM call completes in time the
            // result is returned normally. On timeout the `session_hung` flag is
            // set so that subsequent calls return immediately rather than blocking
            // on the mutex the background thread may still be holding.
            Some(timeout) => {
                // A previous call already timed out; the background thread may
                // still hold the session mutex. Bail out immediately.
                if self.session_hung.load(Ordering::Acquire) {
                    return Err(signature::Error::from_source(format_err!(
                        IoError,
                        "PKCS#11 session is hung from a previous timeout; \
                         restart tmkms to recover"
                    )));
                }

                let signer = self.clone(); // cheap: Arc bumps + small fields
                let msg = msg.to_vec();
                let (tx, rx) = std::sync::mpsc::channel();

                std::thread::spawn(move || {
                    let _ = tx.send(signer.do_sign(&msg));
                });

                match rx.recv_timeout(timeout) {
                    Ok(result) => result,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // The background thread still holds the mutex. Mark the
                        // session as hung so future calls don't block waiting for
                        // it. The only recovery path is a tmkms restart.
                        self.session_hung.store(true, Ordering::Release);
                        Err(signature::Error::from_source(format_err!(
                            IoError,
                            "PKCS#11 signing timed out after {}s; \
                             the HSM may be hung or disconnected — restart tmkms to recover",
                            timeout.as_secs()
                        )))
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        Err(signature::Error::from_source(format_err!(
                            PanicError,
                            "PKCS#11 signing thread terminated unexpectedly"
                        )))
                    }
                }
            }
        }
    }
}

/// Returns `true` if `err` contains a PKCS#11 return value that indicates the
/// session is no longer valid and a reconnect should be attempted.
///
/// Traverses the full error source chain so that additional context layers
/// added in future (e.g. extra `.context(...)` wrapping) do not silently
/// disable reconnect logic.
///
/// Only session-expiry codes trigger a reconnect. Other PKCS#11 errors (e.g.
/// `CKR_KEY_FUNCTION_NOT_PERMITTED`, `CKR_FUNCTION_FAILED`) indicate a
/// configuration or HSM problem that a reconnect will not fix; propagating them
/// directly avoids masking the real cause with a spurious reconnect warning.
fn is_session_error(err: &Error) -> bool {
    use std::error::Error as StdError;
    let mut source: Option<&(dyn StdError + 'static)> = err.source();
    while let Some(e) = source {
        if let Some(pkcs11_err) = e.downcast_ref::<cryptoki::error::Error>() {
            return matches!(
                pkcs11_err,
                cryptoki::error::Error::Pkcs11(
                    RvError::SessionHandleInvalid
                    | RvError::SessionClosed
                    | RvError::UserNotLoggedIn
                    | RvError::DeviceRemoved
                    | RvError::TokenNotPresent,
                    _,
                )
            );
        }
        source = e.source();
    }
    false
}

/// Resolve the private key handle and sign `msg` in one step.
///
/// Extracted as a helper so the identical find+sign sequence can be called
/// both on the initial attempt and after a session reconnect, ensuring that
/// an expired session caught at the `find_objects` stage is indistinguishable
/// from one caught at `sign` — both trigger the reconnect path.
fn sign_with_session(
    session: &Session,
    mechanism: &Mechanism<'_>,
    key_label: &str,
    key_id: Option<&[u8]>,
    msg: &[u8],
) -> Result<Vec<u8>, Error> {
    let private_key =
        find_single_key_object(session, ObjectClass::PRIVATE_KEY, key_label, key_id)?;
    Ok(session.sign(mechanism, private_key, msg)?)
}

/// Fetch the Ed25519 public key for a key object on the HSM.
///
/// Prefers `CKA_EC_POINT` (PKCS#11 v3.0 standard for EdDSA) and falls back to
/// `CKA_VALUE` (used by some non-standard HSMs). Each attribute is queried in a
/// separate `C_GetAttributeValue` call so that a `CKR_ATTRIBUTE_TYPE_INVALID`
/// response from an HSM that does not support `CKA_EC_POINT` does not abort the
/// entire operation — we gracefully fall through to the `CKA_VALUE` query.
///
/// See [`extract_ed25519_key_bytes`] for the supported encodings.
fn fetch_public_key(
    session: &Session,
    key_label: &str,
    key_id: Option<&[u8]>,
) -> Result<PublicKey, Error> {
    let public_key_object =
        find_single_key_object(session, ObjectClass::PUBLIC_KEY, key_label, key_id)?;

    // Query CKA_EC_POINT separately. If the HSM rejects the attribute type
    // (returns an error or an empty value) we fall through to CKA_VALUE below.
    let ec_point_bytes = session
        .get_attributes(public_key_object, &[AttributeType::EcPoint])
        .ok()
        .and_then(|attrs| {
            attrs.into_iter().find_map(|attr| match attr {
                Attribute::EcPoint(bytes) if !bytes.is_empty() => Some(bytes),
                _ => None,
            })
        });

    let pubkey_bytes = if let Some(bytes) = ec_point_bytes {
        bytes
    } else {
        // Fall back to CKA_VALUE (used by some non-standard HSMs and SoftHSM).
        session
            .get_attributes(public_key_object, &[AttributeType::Value])?
            .into_iter()
            .find_map(|attr| match attr {
                Attribute::Value(bytes) if !bytes.is_empty() => Some(bytes),
                _ => None,
            })
            .ok_or_else(|| {
                format_err!(
                    InvalidKey,
                    "could not get public key bytes from HSM (checked CKA_EC_POINT and CKA_VALUE)"
                )
            })?
    };

    let raw_key_bytes = extract_ed25519_key_bytes(&pubkey_bytes)?;
    PublicKey::from_raw_ed25519(raw_key_bytes)
        .ok_or_else(|| format_err!(InvalidKey, "invalid Ed25519 public key from HSM").into())
}

/// Find exactly one PKCS#11 key object matching the given class, label, and optional ID.
/// Returns an error if zero or more than one matching object is found.
fn find_single_key_object(
    session: &Session,
    class: ObjectClass,
    label: &str,
    id: Option<&[u8]>,
) -> Result<ObjectHandle, Error> {
    let mut template = vec![
        Attribute::Class(class),
        Attribute::Label(label.as_bytes().to_vec()),
    ];

    if let Some(key_id) = id {
        template.push(Attribute::Id(key_id.to_vec()));
    }

    let objects = session.find_objects(&template)?;

    match objects.len() {
        0 => fail!(
            InvalidKey,
            "PKCS#11 {} key with label '{}' not found",
            class_name(class),
            label,
        ),
        1 => Ok(objects[0]),
        n => fail!(
            InvalidKey,
            "PKCS#11 {} key with label '{}' is ambiguous: {} objects found (use key_id to disambiguate)",
            class_name(class),
            label,
            n,
        ),
    }
}

fn class_name(class: ObjectClass) -> &'static str {
    if class == ObjectClass::PRIVATE_KEY {
        "private"
    } else if class == ObjectClass::PUBLIC_KEY {
        "public"
    } else {
        "unknown"
    }
}

/// Extract the raw 32-byte Ed25519 public key from the various PKCS#11 encodings
/// produced by real HSMs:
///
/// - **32 bytes** — raw key material (some HSMs and SoftHSM via `CKA_VALUE`).
/// - **34 bytes** starting with `04 20` — DER OCTET STRING wrapping as defined
///   in PKCS#11 v3.0 for `CKA_EC_POINT`.
/// - **36 bytes** starting with `04 22 04 20` — double-wrapped OCTET STRING
///   (some HSMs wrap the 34-byte encoding in an additional OCTET STRING).
/// - **44 bytes** — DER SubjectPublicKeyInfo for Ed25519 (`30 2A 30 05 06 03
///   2B 65 70 03 21 00 <32 bytes>`); the raw key is the final 32 bytes.
fn extract_ed25519_key_bytes(bytes: &[u8]) -> Result<&[u8], Error> {
    match bytes.len() {
        // Raw 32-byte key material
        32 => Ok(bytes),
        // DER OCTET STRING: tag(0x04) + len(0x20=32) + 32 bytes
        34 if bytes[0] == 0x04 && bytes[1] == 0x20 => Ok(&bytes[2..]),
        // Double-wrapped OCTET STRING: 04 22 04 20 + 32 bytes
        // Some HSMs wrap the standard 34-byte CKA_EC_POINT in an extra OCTET STRING.
        36 if bytes[0] == 0x04
            && bytes[1] == 0x22
            && bytes[2] == 0x04
            && bytes[3] == 0x20 =>
        {
            Ok(&bytes[4..])
        }
        // SubjectPublicKeyInfo for Ed25519: 30 2A 30 05 06 03 2B 65 70 03 21 00 + 32 bytes.
        // Validate the fixed DER header before slicing to catch unexpected 44-byte formats.
        44 if bytes.starts_with(&[
            0x30, 0x2A, // SEQUENCE, 42 bytes
            0x30, 0x05, // SEQUENCE, 5 bytes (AlgorithmIdentifier)
            0x06, 0x03, 0x2B, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
            0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
        ]) => Ok(&bytes[12..]),
        _ => fail!(
            InvalidKey,
            "unexpected Ed25519 public key encoding from HSM: {} bytes \
             (expected 32 raw, 34 DER-OCTET-STRING, 36 double-wrapped OCTET-STRING, \
             or 44 SubjectPublicKeyInfo with Ed25519 OID)",
            bytes.len(),
        ),
    }
}

/// Find and return the PKCS#11 library context and the slot matching the configured token label.
fn open_pkcs11_slot(config: &Pkcs11Config) -> Result<(Pkcs11, Slot), Error> {
    if !config.library_path.exists() {
        fail!(
            ConfigError,
            "PKCS#11 library_path '{}' does not exist",
            config.library_path.display()
        );
    }
    let pkcs11 = Pkcs11::new(&config.library_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    let slot = pkcs11
        .get_slots_with_token()?
        .into_iter()
        .find(|s| {
            pkcs11
                .get_token_info(*s)
                .map(|info| info.label().trim() == config.token_label)
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            format_err!(
                ConfigError,
                "PKCS#11 token with label '{}' not found",
                &config.token_label
            )
        })?;

    Ok((pkcs11, slot))
}

/// Open a read-only session on `slot` and log in with `pin`.
///
/// Signing does not require write access; a read-only session follows the
/// principle of least privilege and avoids consuming limited RW sessions on
/// some HSMs.
fn open_session(pkcs11: &Pkcs11, slot: Slot, pin: &Zeroizing<String>) -> Result<Session, Error> {
    use secrecy::Secret;
    let session = pkcs11.open_ro_session(slot)?;
    // Create a short-lived Secret<String> for the login call only; it is
    // zeroized when it drops at the end of this function.
    // Note: the cryptoki 0.10 login API requires an owned Secret<String>, so
    // cloning the inner String is unavoidable here.
    let pin_secret = Secret::new((**pin).clone());
    session.login(UserType::User, Some(&pin_secret))?;
    Ok(session)
}

impl From<cryptoki::error::Error> for Error {
    fn from(e: cryptoki::error::Error) -> Self {
        CryptoError.context(e).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── extract_ed25519_key_bytes ────────────────────────────────────────────

    #[test]
    fn extract_raw_32_bytes() {
        let key = [0x42u8; 32];
        assert_eq!(extract_ed25519_key_bytes(&key).unwrap(), &key);
    }

    #[test]
    fn extract_der_octet_string_34_bytes() {
        let mut bytes = vec![0x04, 0x20];
        bytes.extend_from_slice(&[0xABu8; 32]);
        assert_eq!(extract_ed25519_key_bytes(&bytes).unwrap(), &bytes[2..]);
    }

    #[test]
    fn extract_spki_44_bytes() {
        let mut bytes = vec![
            0x30, 0x2A, // SEQUENCE
            0x30, 0x05, // SEQUENCE (AlgorithmIdentifier)
            0x06, 0x03, 0x2B, 0x65, 0x70, // OID Ed25519
            0x03, 0x21, 0x00, // BIT STRING
        ];
        bytes.extend_from_slice(&[0xCDu8; 32]);
        assert_eq!(extract_ed25519_key_bytes(&bytes).unwrap(), &bytes[12..]);
    }

    #[test]
    fn extract_double_wrapped_octet_string_36_bytes() {
        let mut bytes = vec![0x04, 0x22, 0x04, 0x20];
        bytes.extend_from_slice(&[0xEFu8; 32]);
        assert_eq!(extract_ed25519_key_bytes(&bytes).unwrap(), &bytes[4..]);
    }

    #[test]
    fn extract_rejects_wrong_36_byte_header() {
        // 36 bytes but inner header is wrong (0x05 instead of 0x04)
        let mut bytes = vec![0x04, 0x22, 0x05, 0x20];
        bytes.extend_from_slice(&[0x00u8; 32]);
        assert!(extract_ed25519_key_bytes(&bytes).is_err());
    }

    #[test]
    fn extract_rejects_wrong_34_byte_tag() {
        // First byte is 0x03 (BIT STRING tag), not 0x04 (OCTET STRING)
        let bytes = vec![0x03u8; 34];
        assert!(extract_ed25519_key_bytes(&bytes).is_err());
    }

    #[test]
    fn extract_rejects_wrong_44_byte_header() {
        // 44 bytes but with a garbage header
        let bytes = vec![0x00u8; 44];
        assert!(extract_ed25519_key_bytes(&bytes).is_err());
    }

    #[test]
    fn extract_rejects_unexpected_length() {
        for &len in &[0usize, 1, 16, 33, 35, 37, 43, 45, 64] {
            let bytes = vec![0u8; len];
            assert!(
                extract_ed25519_key_bytes(&bytes).is_err(),
                "expected error for {} bytes",
                len
            );
        }
    }

    // ── resolve_pin ─────────────────────────────────────────────────────────

    fn make_config(pin: Option<&str>, pin_file: Option<PathBuf>) -> Pkcs11Config {
        Pkcs11Config {
            library_path: PathBuf::from("/dummy/lib.so"),
            token_label: "TestToken".to_string(),
            pin: pin.map(|p| secrecy::Secret::new(p.to_string())),
            pin_file,
            keys: vec![],
            signing_timeout_secs: None,
        }
    }

    #[test]
    fn resolve_pin_inline_value() {
        let config = make_config(Some("correct-horse"), None);
        let pin = resolve_pin(&config).unwrap();
        assert_eq!(&**pin, "correct-horse");
    }

    #[test]
    fn resolve_pin_both_set_is_error() {
        let config = make_config(Some("1234"), Some(PathBuf::from("/tmp/pin")));
        assert!(resolve_pin(&config).is_err());
    }

    #[test]
    fn resolve_pin_neither_set_is_error() {
        let config = make_config(None, None);
        assert!(resolve_pin(&config).is_err());
    }

    #[test]
    fn resolve_pin_unset_env_var_is_error() {
        // Use a name that is extremely unlikely to be set in CI
        let config = make_config(Some("$__TMKMS_TEST_PIN_UNSET_XYZ__"), None);
        assert!(resolve_pin(&config).is_err());
    }

    #[test]
    #[allow(unsafe_code)]
    fn resolve_pin_env_var_expansion() {
        // NOTE: env::set_var/remove_var are unsafe since Rust 1.80 because they
        // are not thread-safe. CI runs tests with --test-threads=1; the unique
        // variable name also prevents interference with other tests.
        let var = "__TMKMS_PKCS11_TEST_PIN_EXPAND__";
        // SAFETY: tests run single-threaded (--test-threads=1 in CI).
        unsafe { std::env::set_var(var, "expanded-value") };
        let config = make_config(Some(&format!("${}", var)), None);
        let pin = resolve_pin(&config).unwrap();
        assert_eq!(&**pin, "expanded-value");
        // SAFETY: same as above.
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn resolve_pin_file_trims_whitespace() {
        let path = std::env::temp_dir().join("__tmkms_pkcs11_pin_test__");
        std::fs::write(&path, "  file-pin-value\n").unwrap();
        let config = make_config(None, Some(path.clone()));
        let pin = resolve_pin(&config).unwrap();
        assert_eq!(&**pin, "file-pin-value");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_pin_missing_file_is_error() {
        let config = make_config(None, Some(PathBuf::from("/nonexistent/__tmkms_no_such_pin__")));
        assert!(resolve_pin(&config).is_err());
    }
}
