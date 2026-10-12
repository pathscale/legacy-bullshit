use legacy_bullshit::rsa::{Error, Hash, RsaPublicKey, tls13_scheme};
use serde_json::Value;

fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let data: Value =
        serde_json::from_str(include_str!("data/rsa_pss_2048_sha256_mgf1_32.json")).unwrap();
    let group = &data["testGroups"][0];
    let test = group["tests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|test| test["result"] == "valid")
        .unwrap();
    (
        hex::decode(group["publicKeyAsn"].as_str().unwrap()).unwrap(),
        hex::decode(test["msg"].as_str().unwrap()).unwrap(),
        hex::decode(test["sig"].as_str().unwrap()).unwrap(),
    )
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if content.len() < 128 {
        result.push(content.len() as u8);
    } else {
        let bytes = content.len().to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        result.push(0x80 | (bytes.len() - first) as u8);
        result.extend_from_slice(&bytes[first..]);
    }
    result.extend_from_slice(content);
    result
}

fn take<'a>(input: &mut &'a [u8], tag: u8) -> &'a [u8] {
    assert_eq!(input[0], tag);
    let first = input[1];
    let (length, offset) = if first < 128 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 127);
        let length = input[2..2 + count]
            .iter()
            .fold(0usize, |n, byte| n * 256 + usize::from(*byte));
        (length, 2 + count)
    };
    let result = &input[offset..offset + length];
    *input = &input[offset + length..];
    result
}

fn modulus(der: &[u8]) -> Vec<u8> {
    let mut input = der;
    let mut sequence = take(&mut input, 0x30);
    take(&mut sequence, 2).to_vec()
}

fn key_der(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut content = tlv(2, modulus);
    content.extend(tlv(2, exponent));
    tlv(0x30, &content)
}

#[test]
fn strict_key_policy_and_der() {
    let (der, _, _) = fixture();
    let n = modulus(&der);
    assert!(RsaPublicKey::from_der(&der).is_ok());
    let mut small = vec![0u8; 129];
    small[1] = 0x80;
    small[128] = 1;
    assert!(matches!(
        RsaPublicKey::from_der(&key_der(&small, &[1, 0, 1])),
        Err(Error::Key)
    ));
    assert!(matches!(
        RsaPublicKey::from_der(&key_der(&n, &[3])),
        Err(Error::Key)
    ));
    let mut trailing = der.clone();
    trailing.push(0);
    assert!(matches!(RsaPublicKey::from_der(&trailing), Err(Error::Der)));
    let mut redundant = vec![0];
    redundant.extend_from_slice(&n);
    assert!(matches!(
        RsaPublicKey::from_der(&key_der(&redundant, &[1, 0, 1])),
        Err(Error::Der)
    ));
    let mut content = tlv(2, &n);
    // Three-byte exponent encoded with forbidden long-form length.
    content.extend_from_slice(&[2, 0x81, 3, 1, 0, 1]);
    assert!(matches!(
        RsaPublicKey::from_der(&tlv(0x30, &content)),
        Err(Error::Der)
    ));
}

#[test]
fn signature_failures() {
    let (der, msg, sig) = fixture();
    let key = RsaPublicKey::from_der(&der).unwrap();
    assert_eq!(key.verify_pss(Hash::Sha256, &msg, &sig), Ok(()));
    assert!(key.verify_pss(Hash::Sha256, &msg, &sig[1..]).is_err());
    let mut extended = sig.clone();
    extended.push(0);
    assert!(key.verify_pss(Hash::Sha256, &msg, &extended).is_err());
    let n = modulus(&der);
    let n = if n[0] == 0 { &n[1..] } else { &n[..] };
    assert!(key.verify_pss(Hash::Sha256, &msg, n).is_err());
    let mut flipped = sig.clone();
    flipped[0] ^= 1;
    assert!(key.verify_pss(Hash::Sha256, &msg, &flipped).is_err());
    assert!(key.verify_pss(Hash::Sha384, &msg, &sig).is_err());
    assert_eq!(
        key.verify_pss_prehashed(Hash::Sha256, &[0; 31], &sig),
        Err(Error::DigestLength)
    );
    assert_eq!(tls13_scheme(0x0804), Some(Hash::Sha256));
    assert_eq!(tls13_scheme(0x0805), Some(Hash::Sha384));
    assert_eq!(tls13_scheme(0x0806), Some(Hash::Sha512));
    for scheme in [0x0809, 0x080a, 0x080b, 0x0401, 0] {
        assert_eq!(tls13_scheme(scheme), None);
    }
}
