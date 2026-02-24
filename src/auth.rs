// ABOUTME: Nostr event authentication for the divine-invite-faucet service
// ABOUTME: Validates kind 24242 Nostr signatures using k256 Schnorr (copied from divine-blossom)

use crate::error::{FaucetError, Result};
use crate::types::NostrEvent;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use fastly::http::header::AUTHORIZATION;
use fastly::Request;
use k256::schnorr::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Nostr auth event kind (same as divine-blossom / Blossom protocol)
const AUTH_KIND: u32 = 24242;

/// Extract and validate Nostr auth from request header.
/// Returns the validated event including the caller's pubkey.
pub fn require_auth(req: &Request) -> Result<NostrEvent> {
    let auth_header = req
        .get_header(AUTHORIZATION)
        .ok_or_else(|| FaucetError::AuthRequired("Authorization header required".into()))?
        .to_str()
        .map_err(|_| FaucetError::AuthInvalid("Invalid authorization header".into()))?;

    // Parse "Nostr <base64>" format
    let base64_event = auth_header
        .strip_prefix("Nostr ")
        .ok_or_else(|| FaucetError::AuthInvalid("Authorization must start with 'Nostr '".into()))?;

    // Decode base64
    let event_json = BASE64
        .decode(base64_event)
        .map_err(|_| FaucetError::AuthInvalid("Invalid base64 in authorization".into()))?;

    // Parse JSON
    let event: NostrEvent = serde_json::from_slice(&event_json)
        .map_err(|e| FaucetError::AuthInvalid(format!("Invalid event JSON: {}", e)))?;

    validate_event(&event)?;

    Ok(event)
}

/// Validate a Nostr auth event: check kind, expiration, event ID, and signature
fn validate_event(event: &NostrEvent) -> Result<()> {
    // Accept kind 24242 (Blossom auth) for compatibility with divine-blossom clients
    if event.kind != AUTH_KIND {
        return Err(FaucetError::AuthInvalid(format!(
            "Invalid event kind: expected {}, got {}",
            AUTH_KIND, event.kind
        )));
    }

    // Check expiration if present
    if let Some(expiration) = event.get_expiration() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now > expiration {
            return Err(FaucetError::AuthInvalid("Authorization expired".into()));
        }
    }

    // Verify event ID (SHA-256 of NIP-01 serialized event)
    let computed_id = compute_event_id(event)?;
    if computed_id != event.id {
        return Err(FaucetError::AuthInvalid("Invalid event ID".into()));
    }

    // Verify Schnorr signature
    verify_signature(event)?;

    Ok(())
}

/// Compute NIP-01 event ID: SHA-256 of [0, pubkey, created_at, kind, tags, content]
fn compute_event_id(event: &NostrEvent) -> Result<String> {
    let serialized = serde_json::to_string(&(
        0u8,
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    ))
    .map_err(|e| FaucetError::Internal(format!("Failed to serialize event: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let hash = hasher.finalize();

    Ok(hex::encode(hash))
}

/// Verify BIP-340 Schnorr signature over the event ID using k256
fn verify_signature(event: &NostrEvent) -> Result<()> {
    // Parse 32-byte x-only public key
    let pubkey_bytes = hex::decode(&event.pubkey)
        .map_err(|_| FaucetError::AuthInvalid("Invalid public key hex".into()))?;

    if pubkey_bytes.len() != 32 {
        return Err(FaucetError::AuthInvalid(format!(
            "Invalid public key length: expected 32, got {}",
            pubkey_bytes.len()
        )));
    }

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| FaucetError::AuthInvalid("Invalid public key".into()))?;

    // Parse 64-byte signature
    let sig_bytes = hex::decode(&event.sig)
        .map_err(|_| FaucetError::AuthInvalid("Invalid signature hex".into()))?;

    if sig_bytes.len() != 64 {
        return Err(FaucetError::AuthInvalid(format!(
            "Invalid signature length: expected 64, got {}",
            sig_bytes.len()
        )));
    }

    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| FaucetError::AuthInvalid("Invalid signature format".into()))?;

    // Event ID is already a SHA-256 hash; use verify_prehash for BIP-340
    let msg_bytes = hex::decode(&event.id)
        .map_err(|_| FaucetError::AuthInvalid("Invalid event ID hex".into()))?;

    use k256::schnorr::signature::hazmat::PrehashVerifier;
    verifying_key
        .verify_prehash(&msg_bytes, &signature)
        .map_err(|_| FaucetError::AuthInvalid("Invalid signature".into()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_event_id_is_hex_sha256() {
        let event = NostrEvent {
            id: "test".into(),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: AUTH_KIND,
            tags: vec![],
            content: "test".into(),
            sig: "b".repeat(128),
        };

        let id = compute_event_id(&event).unwrap();
        assert_eq!(id.len(), 64, "event ID should be 64 hex chars (SHA-256)");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "event ID should be hex"
        );
    }

    #[test]
    fn test_compute_event_id_is_deterministic() {
        let event = NostrEvent {
            id: "test".into(),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: AUTH_KIND,
            tags: vec![],
            content: "hello".into(),
            sig: "b".repeat(128),
        };

        let id1 = compute_event_id(&event).unwrap();
        let id2 = compute_event_id(&event).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_validate_event_wrong_kind_is_rejected() {
        let event = NostrEvent {
            id: "a".repeat(64),
            pubkey: "a".repeat(64),
            created_at: 9999999999,
            kind: 1, // wrong kind
            tags: vec![],
            content: "".into(),
            sig: "b".repeat(128),
        };

        let result = validate_event(&event);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("kind"));
    }

    #[test]
    fn test_validate_event_expired_is_rejected() {
        let event = NostrEvent {
            id: "a".repeat(64),
            pubkey: "a".repeat(64),
            created_at: 1000000000,
            kind: AUTH_KIND,
            tags: vec![vec!["expiration".into(), "1000000001".into()]], // expired
            content: "".into(),
            sig: "b".repeat(128),
        };

        let result = validate_event(&event);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("expired"));
    }
}
