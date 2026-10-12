use legacy_bullshit::rsa::{Error, Hash, RsaPublicKey};
use serde_json::Value;

#[test]
fn every_vendored_pkcs1v15_vector() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let (mut files, mut valid, mut invalid, mut acceptable, mut skipped_keys) = (0, 0, 0, 0, 0);
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if !name.starts_with("rsa_signature_") {
            continue;
        }
        files += 1;
        let data: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for group in data["testGroups"].as_array().unwrap() {
            let hash = match group["sha"].as_str().unwrap() {
                "SHA-256" => Hash::Sha256,
                "SHA-384" => Hash::Sha384,
                "SHA-512" => Hash::Sha512,
                other => panic!("unsupported vendored hash: {other}"),
            };
            let asn = hex::decode(group["publicKeyAsn"].as_str().unwrap()).unwrap();
            let key = match RsaPublicKey::from_der(&asn) {
                Ok(key) => key,
                // Exponents other than 65537 are outside the policy.
                Err(Error::Key) => {
                    skipped_keys += 1;
                    continue;
                }
                Err(error) => panic!("{name}: key: {error}"),
            };
            for test in group["tests"].as_array().unwrap() {
                let msg = hex::decode(test["msg"].as_str().unwrap()).unwrap();
                let sig = hex::decode(test["sig"].as_str().unwrap()).unwrap();
                let id = &test["tcId"];
                let result = key.verify_pkcs1v15(hash, &msg, &sig);
                match test["result"].as_str().unwrap() {
                    "valid" => {
                        valid += 1;
                        assert_eq!(result, Ok(()), "{name} tcId {id}");
                    }
                    "invalid" => {
                        invalid += 1;
                        assert!(result.is_err(), "{name} tcId {id}");
                    }
                    // Legacy encodings (for example DigestInfo without NULL):
                    // the strict policy rejects them.
                    _ => {
                        acceptable += 1;
                        assert!(result.is_err(), "{name} tcId {id}");
                    }
                }
                // A valid PKCS#1 v1.5 signature must never pass as PSS. Some
                // invalid vectors are deliberately PSS signatures, so only the
                // valid ones are cross-checked.
                if test["result"] == "valid" {
                    assert!(
                        key.verify_pss(hash, &msg, &sig).is_err(),
                        "{name} tcId {id}"
                    );
                }
            }
        }
    }
    assert_eq!(files, 12);
    assert!(valid > 0 && invalid > 0);
    println!(
        "files={files} valid={valid} invalid={invalid} acceptable_rejected={acceptable} skipped_keys={skipped_keys}"
    );
}
