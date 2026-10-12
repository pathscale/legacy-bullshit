//! AES for QUIC Initial packets, and for nothing else.
//!
//! Why it exists: RFC 9001 section 5.2 protects Initial packets with
//! AEAD_AES_128_GCM and AES-128-ECB header protection, whatever suite the
//! endpoints later negotiate, and QUIC version 2 (RFC 9369) keeps that. The
//! Initial keys are derived from the Destination Connection ID, which travels
//! in clear, so anyone on the path can derive them too. This protection hides
//! nothing secret; it only keeps middleboxes from parsing the packets by
//! accident. From the Handshake packets on, the negotiated suite applies, so
//! a client that only offers ChaCha20-Poly1305 never uses AES past this point.
//!
//! Scope: [`PacketKey`] seals and opens one Initial packet payload with the
//! RFC 9001 section 5.3 nonce (IV XOR packet number), and [`HeaderKey`]
//! computes the section 5.4.3 mask from a 16-byte sample. Key derivation
//! (HKDF-Expand-Label with the version salt) stays with the caller, which
//! already has HKDF-SHA256 for TLS 1.3. There is no general cipher API.
//!
//! The block cipher and GCM are RustCrypto `aes` and `aes-gcm`: audited,
//! constant-time (bitsliced in software, AES-NI or ARMv8 AES when present),
//! no_std and no alloc. Hand-rolled AES would buy nothing but risk.

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use core::fmt;

/// AEAD and header-protection key length in bytes.
pub const KEY_LEN: usize = 16;
/// AEAD IV length in bytes.
pub const IV_LEN: usize = 12;
/// AEAD tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Header-protection sample length in bytes.
pub const SAMPLE_LEN: usize = 16;
/// Header-protection mask length in bytes: one for the first byte, four for
/// the longest packet number.
pub const MASK_LEN: usize = 5;

/// The packet failed authentication. The payload buffer is left in an
/// unspecified state and must be discarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenError;

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QUIC Initial packet failed authentication")
    }
}

impl core::error::Error for OpenError {}

/// AEAD_AES_128_GCM packet protection for one direction of Initial packets.
pub struct PacketKey {
    cipher: Aes128Gcm,
    iv: [u8; IV_LEN],
}

impl PacketKey {
    /// Build from the Initial `quic key` and `quic iv` of one direction.
    pub fn new(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Self {
        Self {
            cipher: Aes128Gcm::new(key.into()),
            iv: *iv,
        }
    }

    /// Encrypt `payload` in place with the unprotected `header` as associated
    /// data, and return the tag that follows it on the wire.
    pub fn seal_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> [u8; TAG_LEN] {
        let nonce = self.nonce(packet_number);
        // Only fails for payloads beyond the GCM limit of 2^36 bytes, far
        // past any UDP datagram; return a tag that can never verify then.
        match self
            .cipher
            .encrypt_inout_detached(&nonce, header, payload.into())
        {
            Ok(tag) => tag.into(),
            Err(_) => [0; TAG_LEN],
        }
    }

    /// Verify `tag` and decrypt `payload` in place, with the unprotected
    /// `header` as associated data.
    pub fn open_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), OpenError> {
        let nonce = self.nonce(packet_number);
        self.cipher
            .decrypt_inout_detached(&nonce, header, payload.into(), &Tag::from(*tag))
            .map_err(|_| OpenError)
    }

    /// RFC 9001 section 5.3: the IV XOR the packet number, left-padded.
    fn nonce(&self, packet_number: u64) -> Nonce<aes_gcm::aead::consts::U12> {
        let mut nonce = self.iv;
        for (byte, pn) in nonce[IV_LEN - 8..]
            .iter_mut()
            .zip(packet_number.to_be_bytes())
        {
            *byte ^= pn;
        }
        nonce.into()
    }
}

/// AES-128-ECB header protection for one direction of Initial packets.
pub struct HeaderKey {
    cipher: Aes128,
}

impl HeaderKey {
    /// Build from the Initial `quic hp` key of one direction.
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self {
            cipher: Aes128::new(key.into()),
        }
    }

    /// RFC 9001 section 5.4.3: the first five bytes of AES-ECB(hp, sample).
    /// The caller applies `mask[0]` to the first byte (low four bits for long
    /// headers) and the rest to the packet number bytes.
    pub fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> [u8; MASK_LEN] {
        let mut block = (*sample).into();
        self.cipher.encrypt_block(&mut block);
        let mut mask = [0; MASK_LEN];
        mask.copy_from_slice(&block[..MASK_LEN]);
        mask
    }
}
