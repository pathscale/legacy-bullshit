//! RFC 9001 Appendix A: Initial keys, the client and server Initial packets,
//! and the Retry integrity tag (also AES-128-GCM, fixed key).
use hkdf::Hkdf;
use legacy_bullshit::quic_initial::{HeaderKey, PacketKey};
use sha2::Sha256;

const SALT_V1: &str = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
const DCID: &str = "8394c8f03e515708";

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text.trim()).unwrap()
}

fn data(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    unhex(&std::fs::read_to_string(path).unwrap())
}

fn expand_label<const N: usize>(secret: &[u8], label: &str) -> [u8; N] {
    let full = [b"tls13 ".as_slice(), label.as_bytes()].concat();
    let mut info = (N as u16).to_be_bytes().to_vec();
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(0);
    let mut out = [0; N];
    Hkdf::<Sha256>::from_prk(secret)
        .unwrap()
        .expand(&info, &mut out)
        .unwrap();
    out
}

struct Keys {
    packet: PacketKey,
    header: HeaderKey,
}

fn initial(side: &str, expected: [&str; 3]) -> Keys {
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(&unhex(SALT_V1)), &unhex(DCID));
    let secret: [u8; 32] = expand_label(&initial_secret, side);
    let key: [u8; 16] = expand_label(&secret, "quic key");
    let iv: [u8; 12] = expand_label(&secret, "quic iv");
    let hp: [u8; 16] = expand_label(&secret, "quic hp");
    assert_eq!(key.to_vec(), unhex(expected[0]));
    assert_eq!(iv.to_vec(), unhex(expected[1]));
    assert_eq!(hp.to_vec(), unhex(expected[2]));
    Keys {
        packet: PacketKey::new(&key, &iv),
        header: HeaderKey::new(&hp),
    }
}

fn client() -> Keys {
    initial(
        "client in",
        [
            "1f369613dd76d5467730efcbe3b1a22d",
            "fa044b2f42a3fd3b46fb255c",
            "9f50449e04a0e810283a1e9933adedd2",
        ],
    )
}

fn server() -> Keys {
    initial(
        "server in",
        [
            "cf3a5331653c364c88f0f379b6067e37",
            "0ac1493ca1905853b0bba03e",
            "c206b8d9b9f0f37644430b490eeaa314",
        ],
    )
}

/// Protect one long-header packet as RFC 9001 sections 5.3 and 5.4 describe.
fn protect(keys: &Keys, header: &[u8], pn: u64, pn_len: usize, payload: &[u8]) -> Vec<u8> {
    let mut body = payload.to_vec();
    let tag = keys.packet.seal_in_place(pn, header, &mut body);
    let mut packet = [header, &body, &tag].concat();
    let pn_offset = header.len() - pn_len;
    let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
    let mask = keys.header.mask(&sample);
    packet[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    packet
}

/// Remove header protection and open, returning the payload.
fn unprotect(keys: &Keys, packet: &[u8], pn_offset: usize, pn: u64) -> Option<Vec<u8>> {
    let mut packet = packet.to_vec();
    let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
    let mask = keys.header.mask(&sample);
    packet[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(packet[0] & 0x03) + 1;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    let (header, rest) = packet.split_at(pn_offset + pn_len);
    let (body, tag) = rest.split_at(rest.len() - 16);
    let mut body = body.to_vec();
    keys.packet
        .open_in_place(pn, header, &mut body, tag.try_into().unwrap())
        .ok()?;
    Some(body)
}

#[test]
fn a2_client_initial() {
    let keys = client();
    let mut payload = data("rfc9001_a2_client_crypto_frame.hex");
    payload.resize(1162, 0);
    let header = unhex("c300000001088394c8f03e5157080000449e00000002");
    let expected = data("rfc9001_a2_client_initial_protected.hex");
    let packet = protect(&keys, &header, 2, 4, &payload);
    assert_eq!(packet.len(), 1200);
    assert_eq!(packet, expected);
    assert_eq!(unprotect(&keys, &expected, 18, 2).unwrap(), payload);
}

#[test]
fn a3_server_initial() {
    let keys = server();
    let payload = unhex(concat!(
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739",
        "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94",
        "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00",
        "020304"
    ));
    let header = unhex("c1000000010008f067a5502a4262b50040750001");
    let expected = unhex(concat!(
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a",
        "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3",
        "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84",
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4",
        "2158407dd074ee"
    ));
    assert_eq!(
        keys.header
            .mask(
                &unhex("2cd0991cd25b0aac406a5816b6394100")
                    .try_into()
                    .unwrap()
            )
            .to_vec(),
        unhex("2ec0d8356a")
    );
    assert_eq!(protect(&keys, &header, 1, 2, &payload), expected);
    assert_eq!(unprotect(&keys, &expected, 18, 1).unwrap(), payload);
}

#[test]
fn tampered_initial_is_rejected() {
    let keys = client();
    let mut packet = data("rfc9001_a2_client_initial_protected.hex");
    packet[100] ^= 1;
    assert!(unprotect(&keys, &packet, 18, 2).is_none());
    // The wrong direction must not open either.
    assert!(
        unprotect(
            &server(),
            &data("rfc9001_a2_client_initial_protected.hex"),
            18,
            2
        )
        .is_none()
    );
}

#[test]
fn a4_retry_integrity_tag() {
    // RFC 9001 section 5.8: AEAD_AES_128_GCM over the Retry pseudo-packet.
    let key: [u8; 16] = unhex("be0c690b9f66575a1d766b54e368c84e")
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = unhex("461599d35d632bf2239825bb").try_into().unwrap();
    let retry = unhex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
    let (body, tag) = retry.split_at(retry.len() - 16);
    let pseudo = [&[8u8][..], &unhex(DCID), body].concat();
    let retry_key = PacketKey::new(&key, &nonce);
    assert_eq!(retry_key.seal_in_place(0, &pseudo, &mut []).to_vec(), tag);
    assert!(
        retry_key
            .open_in_place(0, &pseudo, &mut [], tag.try_into().unwrap())
            .is_ok()
    );
}
