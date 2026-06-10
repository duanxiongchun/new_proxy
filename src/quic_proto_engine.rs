use hmac::{Hmac, Mac};
use quinn_proto::Connection;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedPacket {
    pub payload: Vec<u8>,
    pub mac: [u8; 32],
}

pub struct WorkerConnection {
    pub connection: Connection,
    pub authenticated: bool,
    pub tx_bytes: Arc<std::sync::atomic::AtomicU64>,
    pub rx_bytes: Arc<std::sync::atomic::AtomicU64>,
    pub peer_public_key: Option<[u8; 32]>,
}

/// Computes the HMAC-SHA256 of the given data using the provided key.
fn calculate_mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 key size should be valid");
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Verifies the HMAC-SHA256 of the given data using the provided key.
fn verify_mac(key: &[u8; 32], data: &[u8], expected_mac: &[u8; 32]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 key size should be valid");
    mac.update(data);
    mac.verify_slice(expected_mac).is_ok()
}

/// Generates the 0x01 authentication packet payload.
pub fn generate_auth_payload(
    _client_private_key: [u8; 32],
    client_public_key: [u8; 32],
    session_psk: [u8; 32],
    nonce: [u8; 16],
) -> Vec<u8> {
    // 1. Build the payload that gets signed: nonce + client_public_key
    let mut inner_payload = Vec::with_capacity(16 + 32);
    inner_payload.extend_from_slice(&nonce);
    inner_payload.extend_from_slice(&client_public_key);

    let mac = calculate_mac(&session_psk, &inner_payload);

    let signed_packet = SignedPacket {
        payload: inner_payload,
        mac,
    };

    // 2. Prepend the wire multiplexing header 0x01 to the serialized JSON
    let mut wire_payload = vec![0x01];
    wire_payload.extend_from_slice(&serde_json::to_vec(&signed_packet).unwrap_or_default());
    wire_payload
}

/// Verifies the authentication payload.
pub fn verify_auth_payload(
    payload: &[u8],
    session_psk: &[u8; 32],
    expected_nonce: &[u8; 16],
) -> bool {
    // Check wire multiplexing header
    if payload.is_empty() || payload[0] != 0x01 {
        return false;
    }

    // Deserialize SignedPacket from &payload[1..]
    let signed_packet: SignedPacket = match serde_json::from_slice(&payload[1..]) {
        Ok(sp) => sp,
        Err(_) => return false,
    };

    // Verify MAC
    if !verify_mac(session_psk, &signed_packet.payload, &signed_packet.mac) {
        return false;
    }

    // Verify inner payload length (nonce 16 + public key 32 = 48 bytes)
    if signed_packet.payload.len() != 48 {
        return false;
    }

    // Verify nonce
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&signed_packet.payload[0..16]);
    if &nonce != expected_nonce {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_auth_flow() {
        let client_private_key = [2u8; 32];
        let client_public_key = [3u8; 32];
        let session_psk = [4u8; 32];
        let nonce = [5u8; 16];

        let payload =
            generate_auth_payload(client_private_key, client_public_key, session_psk, nonce);

        assert!(verify_auth_payload(&payload, &session_psk, &nonce));
    }

    #[test]
    fn test_incorrect_nonce() {
        let client_private_key = [2u8; 32];
        let client_public_key = [3u8; 32];
        let session_psk = [4u8; 32];
        let nonce = [5u8; 16];
        let wrong_nonce = [6u8; 16];

        let payload =
            generate_auth_payload(client_private_key, client_public_key, session_psk, nonce);

        assert!(!verify_auth_payload(&payload, &session_psk, &wrong_nonce));
    }

    #[test]
    fn test_invalid_mac() {
        let client_private_key = [2u8; 32];
        let client_public_key = [3u8; 32];
        let session_psk = [4u8; 32];
        let wrong_psk = [99u8; 32];
        let nonce = [5u8; 16];

        let payload =
            generate_auth_payload(client_private_key, client_public_key, session_psk, nonce);

        // Verifying with a different PSK should fail the MAC check
        assert!(!verify_auth_payload(&payload, &wrong_psk, &nonce));

        // Tampering with the MAC in the payload should fail the MAC check
        let mut signed_packet: SignedPacket = serde_json::from_slice(&payload[1..]).unwrap();
        signed_packet.mac[0] ^= 0xFF; // Corrupt the MAC
        let mut corrupted_payload = vec![0x01];
        corrupted_payload.extend_from_slice(&serde_json::to_vec(&signed_packet).unwrap());
        assert!(!verify_auth_payload(
            &corrupted_payload,
            &session_psk,
            &nonce
        ));
    }

    #[test]
    fn test_wrong_header() {
        let client_public_key = [3u8; 32];
        let session_psk = [4u8; 32];
        let nonce = [5u8; 16];

        // Construct a SignedPacket with a correct inner payload
        let mut inner_payload = Vec::new();
        inner_payload.extend_from_slice(&nonce);
        inner_payload.extend_from_slice(&client_public_key);

        let mac = calculate_mac(&session_psk, &inner_payload);
        let signed_packet = SignedPacket {
            payload: inner_payload,
            mac,
        };
        // But prepend a wrong multiplexing header byte (0x02 instead of 0x01)
        let mut payload = vec![0x02];
        payload.extend_from_slice(&serde_json::to_vec(&signed_packet).unwrap());

        assert!(!verify_auth_payload(&payload, &session_psk, &nonce));
    }

    #[test]
    fn test_serialization_error() {
        let session_psk = [4u8; 32];
        let nonce = [5u8; 16];

        // 1. Missing multiplexing header (starts with JSON directly)
        let payload_no_header = serde_json::to_vec(&SignedPacket {
            payload: vec![],
            mac: [0; 32],
        })
        .unwrap();
        assert!(!verify_auth_payload(
            &payload_no_header,
            &session_psk,
            &nonce
        ));

        // 2. Totally invalid json (after 0x01 header)
        let mut invalid_json = vec![0x01];
        invalid_json.extend_from_slice(b"{invalid json}");
        assert!(!verify_auth_payload(&invalid_json, &session_psk, &nonce));

        // 3. Valid JSON but wrong structure (e.g. missing payload or mac fields)
        let mut wrong_struct_json = vec![0x01];
        wrong_struct_json.extend_from_slice(b"{\"payload\": [1,2,3]}");
        assert!(!verify_auth_payload(
            &wrong_struct_json,
            &session_psk,
            &nonce
        ));
    }

    #[test]
    fn test_truncated_or_malformed_payload_len() {
        let client_public_key = [3u8; 32];
        let session_psk = [4u8; 32];
        let nonce = [5u8; 16];

        // 1. Truncated payload: only 30 bytes instead of 48
        let mut inner_payload = Vec::new();
        inner_payload.extend_from_slice(&nonce);
        // Truncate public key to only 14 bytes instead of 32
        inner_payload.extend_from_slice(&client_public_key[..14]);

        let mac = calculate_mac(&session_psk, &inner_payload);
        let signed_packet = SignedPacket {
            payload: inner_payload,
            mac,
        };
        let mut payload = vec![0x01];
        payload.extend_from_slice(&serde_json::to_vec(&signed_packet).unwrap());
        assert!(!verify_auth_payload(&payload, &session_psk, &nonce));

        // 2. Too long payload: 55 bytes instead of 48
        let mut inner_payload = Vec::new();
        inner_payload.extend_from_slice(&nonce);
        inner_payload.extend_from_slice(&client_public_key);
        inner_payload.extend_from_slice(b"extra_bytes");

        let mac = calculate_mac(&session_psk, &inner_payload);
        let signed_packet = SignedPacket {
            payload: inner_payload,
            mac,
        };
        let mut payload = vec![0x01];
        payload.extend_from_slice(&serde_json::to_vec(&signed_packet).unwrap());
        assert!(!verify_auth_payload(&payload, &session_psk, &nonce));
    }
}
