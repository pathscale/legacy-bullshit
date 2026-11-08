use alloc::boxed::Box;

use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::crypto::CipherSuiteCommon;
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion,
    SupportedCipherSuite, Tls13CipherSuite,
};

use super::{RecordKey, TAG_LEN};

/// Construct the rustls TLS 1.3 AES-128-GCM suite using the hash and HKDF
/// from the caller's TLS 1.3 ChaCha20-Poly1305/SHA-256 suite.
///
/// Store the result in a static and explicitly add it to the provider's suite
/// list. QUIC support is outside this adapter's scope.
///
/// # Panics
///
/// Panics if the input suite's identifier differs from
/// `TLS_CHACHA20_POLY1305_SHA256`.
pub const fn rustls_suite_from_chacha20(chacha20: SupportedCipherSuite) -> Tls13CipherSuite {
    let chacha20 = match chacha20 {
        SupportedCipherSuite::Tls13(suite)
            if matches!(suite.common.suite, CipherSuite::TLS13_CHACHA20_POLY1305_SHA256) =>
        {
            suite
        }
        _ => panic!("expected the TLS 1.3 ChaCha20-Poly1305/SHA-256 suite"),
    };
    Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: chacha20.common.hash_provider,
            // Stay below the AES-GCM confidentiality limit in RFC 8446 §5.5.
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: chacha20.hkdf_provider,
        aead_alg: &Aes128Gcm,
        quic: None,
    }
}

struct Aes128Gcm;

impl Tls13AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher::new(key, iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher::new(key, iv))
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        _: AeadKey,
        _: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

struct Tls13Cipher(RecordKey);

impl Tls13Cipher {
    fn new(key: AeadKey, iv: Iv) -> Self {
        let key = key
            .as_ref()
            .try_into()
            .expect("rustls supplies a 16-byte key");
        let iv = iv
            .as_ref()
            .try_into()
            .expect("rustls supplies a 12-byte IV");
        Self(RecordKey::new(key, iv))
    }
}

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        message: OutboundPlainMessage<'_>,
        sequence: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let mut payload =
            PrefixedPayload::with_capacity(self.encrypted_payload_len(message.payload.len()));
        payload.extend_from_chunks(&message.payload);
        payload.extend_from_slice(&message.typ.to_array());
        let tag = self
            .0
            .seal_in_place(sequence, payload.as_mut())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut message: InboundOpaqueMessage<'a>,
        sequence: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let len = self
            .0
            .open_in_place(sequence, &mut message.payload)
            .map_err(|_| Error::DecryptError)?;
        message.payload.truncate(len);
        message.into_tls13_unpadded_message()
    }
}
