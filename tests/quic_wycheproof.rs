//! Every Wycheproof AES-GCM vector with a 128-bit key, 96-bit IV and 128-bit
//! tag, the only shape QUIC Initial packets use. Other shapes are skipped.
use legacy_bullshit::quic_initial::{HeaderKey, PacketKey};
use serde_json::Value;

fn bytes(test: &Value, field: &str) -> Vec<u8> {
    hex::decode(test[field].as_str().unwrap()).unwrap()
}

#[test]
fn wycheproof_aes_128_gcm() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/aes_gcm_test.json");
    let json: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let (mut valid, mut invalid) = (0, 0);
    for group in json["testGroups"].as_array().unwrap() {
        if group["keySize"] != 128 || group["ivSize"] != 96 || group["tagSize"] != 128 {
            continue;
        }
        for test in group["tests"].as_array().unwrap() {
            let id = &test["tcId"];
            let key: [u8; 16] = bytes(test, "key").try_into().unwrap();
            let iv: [u8; 12] = bytes(test, "iv").try_into().unwrap();
            let aad = bytes(test, "aad");
            let msg = bytes(test, "msg");
            let ct = bytes(test, "ct");
            let tag: [u8; 16] = bytes(test, "tag").try_into().unwrap();
            // Packet number 0 makes the nonce exactly the IV.
            let packet = PacketKey::new(&key, &iv);
            let mut buffer = ct.clone();
            let opened = packet.open_in_place(0, &aad, &mut buffer, &tag);
            match test["result"].as_str().unwrap() {
                "valid" => {
                    assert!(opened.is_ok(), "tcId {id} must open");
                    assert_eq!(buffer, msg, "tcId {id} plaintext");
                    let mut sealed = msg.clone();
                    assert_eq!(
                        packet.seal_in_place(0, &aad, &mut sealed),
                        tag,
                        "tcId {id} tag"
                    );
                    assert_eq!(sealed, ct, "tcId {id} ciphertext");
                    valid += 1;
                }
                "invalid" => {
                    assert!(opened.is_err(), "tcId {id} must not open");
                    invalid += 1;
                }
                other => panic!("tcId {id}: unexpected result {other}"),
            }
        }
    }
    assert!(
        valid >= 40 && invalid >= 20,
        "valid {valid}, invalid {invalid}"
    );
    println!("Wycheproof AES-128-GCM: {valid} valid, {invalid} invalid");
}

/// FIPS-197 Appendix C.1 AES-128 block, the primitive under the mask.
#[test]
fn fips197_block_under_mask() {
    let key: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
        .unwrap()
        .try_into()
        .unwrap();
    let sample: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        HeaderKey::new(&key).mask(&sample).to_vec(),
        hex::decode("69c4e0d86a").unwrap()
    );
}
