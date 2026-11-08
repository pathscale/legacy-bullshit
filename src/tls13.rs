//! TLS 1.3 record protection for `TLS_AES_128_GCM_SHA256` (RFC 8446 §5.2–5.3).

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use core::fmt;

#[cfg(feature = "rustls-tls13-aes128-gcm")]
mod rustls_adapter;
#[cfg(feature = "rustls-tls13-aes128-gcm")]
pub use rustls_adapter::rustls_suite_from_chacha20;

/// Length of the authentication tag appended to a TLS ciphertext.
pub const TAG_LEN: usize = 16;
const MAX_CIPHERTEXT_LEN: usize = (1 << 14) + 256;

/// The record length was invalid or record protection failed.
///
/// Discard the buffer on error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordError;

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TLS 1.3 record protection failed")
    }
}

impl core::error::Error for RecordError {}

/// The AES-128-GCM traffic key and static IV for one TLS direction and epoch.
pub struct RecordKey {
    cipher: Aes128Gcm,
    iv: [u8; 12],
}

impl RecordKey {
    /// Build from the TLS 1.3 traffic key and static IV.
    pub fn new(key: &[u8; 16], iv: [u8; 12]) -> Self {
        Self {
            cipher: Aes128Gcm::new(key.into()),
            iv,
        }
    }

    /// Encrypt a TLSInnerPlaintext in place and return the tag to append.
    ///
    /// The buffer includes the inner content type and any padding. The caller
    /// must use each TLS record sequence number at most once for this key.
    pub fn seal_in_place(
        &self,
        sequence: u64,
        plaintext: &mut [u8],
    ) -> Result<[u8; TAG_LEN], RecordError> {
        let ciphertext_len = plaintext.len().checked_add(TAG_LEN).ok_or(RecordError)?;
        let aad = record_aad(ciphertext_len)?;
        self.cipher
            .encrypt_inout_detached(&self.nonce(sequence), &aad, plaintext.into())
            .map(Into::into)
            .map_err(|_| RecordError)
    }

    /// Authenticate and decrypt an encrypted record payload, including its tag.
    ///
    /// On success, the returned length identifies the TLSInnerPlaintext in the
    /// buffer. The caller handles its content type and padding.
    pub fn open_in_place(&self, sequence: u64, record: &mut [u8]) -> Result<usize, RecordError> {
        let aad = record_aad(record.len())?;
        let (ciphertext, tag) = record
            .split_last_chunk_mut::<TAG_LEN>()
            .ok_or(RecordError)?;
        let plaintext_len = ciphertext.len();
        self.cipher
            .decrypt_inout_detached(
                &self.nonce(sequence),
                &aad,
                ciphertext.into(),
                &Tag::from(*tag),
            )
            .map_err(|_| RecordError)?;
        Ok(plaintext_len)
    }

    fn nonce(&self, sequence: u64) -> Nonce<aes_gcm::aead::consts::U12> {
        let mut nonce = self.iv;
        for (byte, seq) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
            *byte ^= seq;
        }
        nonce.into()
    }
}

fn record_aad(ciphertext_len: usize) -> Result<[u8; 5], RecordError> {
    // The encrypted payload includes at least the inner content type and tag.
    if !(TAG_LEN + 1..=MAX_CIPHERTEXT_LEN).contains(&ciphertext_len) {
        return Err(RecordError);
    }
    let [hi, lo] = (ciphertext_len as u16).to_be_bytes();
    // TLSCiphertext.opaque_type = application_data, legacy_record_version = 0x0303.
    Ok([23, 3, 3, hi, lo])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8448_client_alert_and_tamper_rejection() {
        // RFC 8448 §3: the client alert follows one application-data record.
        let key = hex::decode("17422dda596ed5d9acd890e3c63f5051").unwrap();
        let iv = hex::decode("5b78923dee08579033e523d9").unwrap();
        let key = RecordKey::new(key.as_slice().try_into().unwrap(), iv.try_into().unwrap());
        let expected = hex::decode("c9872760655666b74d7ff1153efd6db6d0b0e3").unwrap();
        let plaintext = [0x01, 0x00, 0x15];
        let mut sealed = plaintext;
        let tag = key.seal_in_place(1, &mut sealed).unwrap();
        assert_eq!(sealed.as_slice(), &expected[..plaintext.len()]);
        assert_eq!(tag.as_slice(), &expected[plaintext.len()..]);

        let mut record = expected.clone();
        let len = key.open_in_place(1, &mut record).unwrap();
        assert_eq!(&record[..len], &plaintext);

        for offset in [0, expected.len() - 1] {
            let mut record = expected.clone();
            record[offset] ^= 1;
            assert_eq!(key.open_in_place(1, &mut record), Err(RecordError));
        }
        assert_eq!(
            key.open_in_place(0, &mut expected.clone()),
            Err(RecordError)
        );
        assert_eq!(key.open_in_place(1, &mut [0; TAG_LEN]), Err(RecordError));
    }
}
