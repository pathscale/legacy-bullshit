use legacy_bullshit::rsa::{Error, Hash, RsaPublicKey};
use serde_json::Value;

fn fixture() -> (RsaPublicKey, Vec<u8>, Vec<u8>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/rsa_signature_2048_sha256.json");
    let data: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let group = &data["testGroups"][0];
    let key = hex::decode(group["publicKeyAsn"].as_str().unwrap()).unwrap();
    let key = RsaPublicKey::from_der(&key).unwrap();
    let test = group["tests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|test| test["result"] == "valid")
        .unwrap();
    let msg = hex::decode(test["msg"].as_str().unwrap()).unwrap();
    let sig = hex::decode(test["sig"].as_str().unwrap()).unwrap();
    (key, msg, sig)
}

#[test]
fn pkcs1v15_failures() {
    let (key, msg, sig) = fixture();
    assert_eq!(key.verify_pkcs1v15(Hash::Sha256, &msg, &sig), Ok(()));
    // Wrong hash, wrong message, flipped bit, wrong length, all-zero.
    assert!(key.verify_pkcs1v15(Hash::Sha384, &msg, &sig).is_err());
    assert!(key.verify_pkcs1v15(Hash::Sha512, &msg, &sig).is_err());
    let mut other = msg.clone();
    other.push(0);
    assert!(key.verify_pkcs1v15(Hash::Sha256, &other, &sig).is_err());
    for bit in [0, 7, 1000, 2047] {
        let mut flipped = sig.clone();
        flipped[bit / 8] ^= 1 << (bit % 8);
        assert!(key.verify_pkcs1v15(Hash::Sha256, &msg, &flipped).is_err());
    }
    assert!(key.verify_pkcs1v15(Hash::Sha256, &msg, &sig[1..]).is_err());
    let mut longer = vec![0];
    longer.extend_from_slice(&sig);
    assert!(key.verify_pkcs1v15(Hash::Sha256, &msg, &longer).is_err());
    assert!(
        key.verify_pkcs1v15(Hash::Sha256, &msg, &vec![0; sig.len()])
            .is_err()
    );
    assert!(
        key.verify_pkcs1v15(Hash::Sha256, &msg, &vec![0xff; sig.len()])
            .is_err()
    );
    // Prehashed digest of the wrong length.
    assert_eq!(
        key.verify_pkcs1v15_prehashed(Hash::Sha256, &[0; 31], &sig),
        Err(Error::DigestLength)
    );
    // The same signature is not accepted as PSS.
    assert!(key.verify_pss(Hash::Sha256, &msg, &sig).is_err());
}
