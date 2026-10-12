use legacy_bullshit::rsa::{Hash, RsaPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};

#[test]
fn every_vendored_vector() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let mut files = 0;
    let mut skipped_spki = 0;
    let mut acceptable = 0;
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "json")
            || !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("rsa_pss_"))
        {
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
            assert_eq!(group["sha"], group["mgfSha"]);
            let salt = match hash {
                Hash::Sha256 => 32,
                Hash::Sha384 => 48,
                Hash::Sha512 => 64,
            };
            assert_eq!(group["sLen"].as_u64().unwrap(), salt);
            let asn = hex::decode(group["publicKeyAsn"].as_str().unwrap()).unwrap();
            let key = RsaPublicKey::from_der(&asn).unwrap();
            let der = hex::decode(group["publicKeyDer"].as_str().unwrap()).unwrap();
            // The vendored canonical SPKI algorithm is identified independently
            // of the parser under test. PSS OID keys are outside this API.
            let rsa_oid = [6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1];
            let spki = if der.windows(rsa_oid.len()).any(|window| window == rsa_oid) {
                Some(RsaPublicKey::from_spki_der(&der).unwrap())
            } else {
                skipped_spki += 1;
                None
            };
            for test in group["tests"].as_array().unwrap() {
                let msg = hex::decode(test["msg"].as_str().unwrap()).unwrap();
                let sig = hex::decode(test["sig"].as_str().unwrap()).unwrap();
                let digest = match hash {
                    Hash::Sha256 => Sha256::digest(&msg).to_vec(),
                    Hash::Sha384 => Sha384::digest(&msg).to_vec(),
                    Hash::Sha512 => Sha512::digest(&msg).to_vec(),
                };
                let result = key.verify_pss(hash, &msg, &sig);
                assert_eq!(result, key.verify_pss_prehashed(hash, &digest, &sig));
                if let Some(spki) = &spki {
                    assert_eq!(result, spki.verify_pss(hash, &msg, &sig));
                }
                let expected = match test["result"].as_str().unwrap() {
                    "valid" => true,
                    "invalid" => false,
                    "acceptable" => {
                        acceptable += 1;
                        // Strict policy rejects optional legacy encodings.
                        // Current vendored files contain no acceptable cases.
                        false
                    }
                    other => panic!("unknown vector result: {other}"),
                };
                assert_eq!(
                    result.is_ok(),
                    expected,
                    "{} tcId={} flags={}",
                    path.display(),
                    test["tcId"],
                    test["flags"]
                );
            }
        }
    }
    assert!(files > 0);
    eprintln!(
        "files={files}, skipped non-rsaEncryption SPKI={skipped_spki}, acceptable={acceptable}"
    );
}
