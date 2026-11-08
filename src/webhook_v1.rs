//! Read access to persisted v1 webhook secrets protected by AES-256-GCM.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use core::fmt;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Failure to parse or authenticate a v1 webhook record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenError {
    /// The record is missing its nonce or authentication tag.
    Malformed,
    /// The record failed authentication.
    Authentication,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed v1 webhook secret record"),
            Self::Authentication => f.write_str("v1 webhook secret record failed authentication"),
        }
    }
}

impl core::error::Error for OpenError {}

/// Authenticate and open an existing v1 webhook secret record in place.
///
/// The caller checks the `v1.` prefix and decodes the hex before calling.
/// The decoded record holds the 12-byte nonce, ciphertext, and 16-byte tag
/// in that order. Pass the original endpoint and secret identity bytes as
/// `aad`. The returned slice contains the authenticated plaintext.
///
/// # Errors
///
/// Returns an error for a malformed record or a failed authentication.
/// Discard the record buffer on error.
pub fn open_in_place<'a>(
    key: &[u8; 32],
    aad: &[u8],
    record: &'a mut [u8],
) -> Result<&'a [u8], OpenError> {
    let (nonce, payload) = record
        .split_first_chunk_mut::<NONCE_LEN>()
        .ok_or(OpenError::Malformed)?;
    let (ciphertext, tag) = payload
        .split_last_chunk_mut::<TAG_LEN>()
        .ok_or(OpenError::Malformed)?;

    Aes256Gcm::new(key.into())
        .decrypt_inout_detached(
            &Nonce::from(*nonce),
            aad,
            (&mut *ciphertext).into(),
            &Tag::from(*tag),
        )
        .map_err(|_| OpenError::Authentication)?;
    Ok(ciphertext)
}
