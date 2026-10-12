# legacy-bullshit

The legacy cryptography the standards still force on a client that runs
ECC and ChaCha20-Poly1305, and not one primitive more. Every line here
exists because an RFC or the deployed web leaves no choice, and keeping it
in one crate means one grep finds every place the web forces our hand.

Two modules, no general cipher API:

- `rsa`: verify-only RSA for TLS 1.3. RSASSA-PSS for CertificateVerify,
  RSASSA-PKCS1-v1_5 for certificate signatures. Formerly `rsa-handshake`.
- `quic_initial`: AES-128-GCM seal and open plus the AES-128-ECB
  header-protection mask, for QUIC Initial packets only.

## rsa

### Scope

- RSASSA-PSS verification (RFC 8017, section 8.1.2) with SHA-256, SHA-384 or
  SHA-512, MGF1 with the same hash, salt length equal to the hash length, as
  RFC 8446 requires for `rsa_pss_rsae_sha256`, `_sha384` and `_sha512`.
- Public keys from DER `RSAPublicKey` (PKCS#1) or `SubjectPublicKeyInfo`
  with `rsaEncryption` and NULL parameters.

Not here, by design: signing, private keys, key generation, encryption,
decryption, PKCS#1 v1.5 outside certificate signatures, and the `rsa_pss_pss_*` schemes. With no private key
anywhere, timing attacks on RSA decryption (Marvin and its relatives) have
nothing to reach.

### Policy

- Modulus 2048 to 8192 bits, odd. Anything outside is rejected.
- Public exponent exactly 65537. Every certificate on the public web uses it,
  and fixing it keeps the exponentiation to 16 squarings and one multiply.
- Strict DER: minimal lengths, minimal positive integers, no trailing bytes at
  any level.
- The signature must be exactly the modulus length and less than the modulus.
- The salt length is checked exactly, not inferred.

### Usage

```rust,ignore
use legacy_bullshit::rsa::{RsaPublicKey, tls13_scheme};

let key = RsaPublicKey::from_spki_der(spki)?;
let hash = tls13_scheme(scheme).ok_or(MyError::Scheme)?;
// `message` is the RFC 8446 section 4.4.3 CertificateVerify input:
// 64 spaces, the context string, a zero byte, the transcript hash.
key.verify_pss(hash, message, signature)?;
```

The caller still validates the certificate chain and the negotiated scheme.

### Chain certificates

Certificate authorities sign RSA certificates with RSASSA-PKCS1-v1_5
(`sha256WithRSAEncryption` and the SHA-384 and SHA-512 variants).
`verify_pkcs1v15` checks those, for certificate signatures only. It builds the
single valid encoding (`00 01 FF..FF 00 DigestInfo hash`, at least 8 bytes of
`FF`, DigestInfo with explicit NULL parameters) and compares it whole; nothing
in the decoded block is parsed, so lenient-parser forgeries have nothing to
work with. TLS 1.3 forbids PKCS#1 v1.5 for CertificateVerify; use
`verify_pss` there.

## quic_initial

RFC 9001 section 5.2 protects QUIC Initial packets with AEAD_AES_128_GCM and
AES-128-ECB header protection no matter what suite the endpoints negotiate,
and QUIC version 2 (RFC 9369) keeps that. The Initial keys are derived from
the Destination Connection ID, which is sent in clear, so anyone on the path
can derive them. This protection hides nothing secret. From the Handshake
packets on, the negotiated suite applies, so a ChaCha20-Poly1305-only client
never touches AES again.

- `PacketKey::new(key, iv)`, `seal_in_place(pn, header, payload) -> tag`,
  `open_in_place(pn, header, payload, tag)`. The nonce is the IV XOR the
  packet number (section 5.3).
- `HeaderKey::new(hp).mask(sample)`: the first five bytes of
  AES-ECB(hp, sample) (section 5.4.3).

Key derivation (HKDF-Expand-Label with the version salt) stays with the
caller, which already has HKDF-SHA256 for TLS 1.3.

AES and GCM come from RustCrypto `aes` and `aes-gcm` rather than being
written here: they are audited, constant-time (bitsliced in software,
AES-NI or ARMv8 AES when the CPU has it), and no_std without alloc.
Hand-rolled AES would add risk and buy nothing.

## Properties

`#![no_std]`, no `alloc`, `#![forbid(unsafe_code)]` in this crate. Runtime
dependencies: `sha2`, `aes`, `aes-gcm`, all with default features off. The
RSA arithmetic is a small fixed-limb Montgomery multiplication over public
inputs only, so it is not constant-time and does not need to be.

## Tests

`cargo test` runs:

- every Wycheproof RSASSA-PKCS1-v1_5 vector for 2048 to 8192-bit keys and
  every vendored Wycheproof RSA-PSS vector, plus negative tests for key
  policy, DER strictness and signature handling;
- RFC 9001 Appendix A: Initial key derivation, the full client and server
  Initial packets, and the Retry integrity tag, plus tamper and
  wrong-direction rejection;
- every Wycheproof AES-GCM vector with a 128-bit key, 96-bit IV and 128-bit
  tag (the Initial shape), both seal and open, and the FIPS-197 block.

## License

MIT OR Apache-2.0. The PSS verification structure follows RustCrypto
[`rsa`](https://github.com/RustCrypto/RSA), MIT OR Apache-2.0, noted in
`src/rsa/pss.rs`. Test vectors are from
[Wycheproof](https://github.com/C2SP/wycheproof), Apache-2.0, and
[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) Appendix A.
