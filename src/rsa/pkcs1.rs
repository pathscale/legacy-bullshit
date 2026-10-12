use super::{Error, Hash};

// DigestInfo DER prefixes from RFC 8017, section 9.2, note 1.
const SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA384: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const SHA512: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Compare `encoded` with the one valid EMSA-PKCS1-v1_5 encoding of `digest`.
///
/// Nothing is parsed: the expected bytes are built and compared whole, so
/// there is no room for lenient padding or DigestInfo parsing.
pub(crate) fn verify(hash: Hash, digest: &[u8], encoded: &[u8]) -> Result<(), Error> {
    let prefix: &[u8] = match hash {
        Hash::Sha256 => &SHA256,
        Hash::Sha384 => &SHA384,
        Hash::Sha512 => &SHA512,
    };
    let tail = prefix.len() + digest.len();
    let k = encoded.len();
    // 0x00 0x01, at least 8 bytes of 0xff, 0x00, then DigestInfo.
    let ps = k.checked_sub(tail + 3).ok_or(Error::Verification)?;
    if ps < 8 {
        return Err(Error::Verification);
    }
    let expected = [0u8, 1]
        .iter()
        .chain(core::iter::repeat_n(&0xffu8, ps))
        .chain(core::iter::once(&0u8))
        .chain(prefix.iter())
        .chain(digest.iter());
    let mut difference = 0u8;
    let mut count = 0usize;
    for (a, b) in encoded.iter().zip(expected) {
        difference |= a ^ b;
        count += 1;
    }
    if difference == 0 && count == k {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}
