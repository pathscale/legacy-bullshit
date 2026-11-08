//! The legacy cryptography the standards still force on an ECC and
//! ChaCha20-Poly1305 client, kept in one place so it is easy to audit and
//! easy to find: grep for `legacy_bullshit` and you see every spot where the
//! web forces our hand.
//!
//! - [`rsa`]: verify-only RSA for TLS 1.3, because most certificate chains on
//!   the public web are still RSA. PSS for CertificateVerify, PKCS#1 v1.5 for
//!   certificate signatures. No private keys, no signing, no decryption.
//! - `quic_initial` (feature `quic-initial`): AES-128-GCM and the AES-128-ECB
//!   header-protection mask for QUIC Initial packets. RFC 9001 section 5.2
//!   fixes that suite for Initial packets. Later traffic uses the negotiated
//!   suite.
//! - `tls13` (feature `tls13-aes128-gcm`): authenticated TLS 1.3 records
//!   using the mandatory-to-implement AES-128-GCM suite.
//!
//! There is no general cipher API here, on purpose.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "quic-initial")]
pub mod quic_initial;
pub mod rsa;
#[cfg(feature = "tls13-aes128-gcm")]
pub mod tls13;
