// ABOUTME: Data types for the divine-invite-faucet service
// ABOUTME: Defines invite codes, user state, waitlist entries, and API request/response types

use serde::{Deserialize, Serialize};

/// Nostr event used for authentication (kind 24242, same as divine-blossom)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    /// Event ID (SHA-256 of serialized event, hex encoded)
    pub id: String,
    /// Author's public key (hex encoded, 32 bytes)
    pub pubkey: String,
    /// Unix timestamp of event creation
    pub created_at: u64,
    /// Event kind (24242 for auth)
    pub kind: u32,
    /// Tags array
    pub tags: Vec<Vec<String>>,
    /// Event content
    pub content: String,
    /// Schnorr signature (hex encoded, 64 bytes)
    pub sig: String,
}

impl NostrEvent {
    /// Get expiration timestamp from tags
    pub fn get_expiration(&self) -> Option<u64> {
        for tag in &self.tags {
            if tag.len() >= 2 && tag[0] == "expiration" {
                return tag[1].parse().ok();
            }
        }
        None
    }
}

/// How an invite code was created
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InviteSource {
    Admin,
    Social,
    Waitlist,
    Cashu,
}

/// Invite code record stored at key `code:{CODE}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCode {
    /// The invite code string (e.g. "DIVINE-AB23")
    pub code: String,
    /// Pubkey of the user who created/owns this code (hex)
    pub creator_pubkey: String,
    /// Pubkey of the user who used this code (hex), None if unused
    pub invitee_pubkey: Option<String>,
    /// Unix timestamp when code was created
    pub created_at: u64,
    /// Unix timestamp when code was used, None if unused
    pub used_at: Option<u64>,
    /// How this code was created
    pub source: InviteSource,
    /// Whether this code has been revoked by an admin
    #[serde(default)]
    pub revoked: bool,
}

impl InviteCode {
    /// Returns true if this code can be used (not used, not revoked)
    pub fn is_available(&self) -> bool {
        self.invitee_pubkey.is_none() && !self.revoked
    }
}

/// User invite state stored at key `user:{pubkey}`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserState {
    /// User's pubkey (hex)
    pub pubkey: String,
    /// Number of invite codes allocated to this user
    pub codes_allocated: u32,
    /// List of codes this user has generated (subset of allocated)
    pub codes_generated: Vec<String>,
    /// Number of codes this user has had consumed by others
    pub codes_used: u32,
    /// Pubkey of who invited this user (hex), None if root user
    pub invited_by: Option<String>,
    /// Unix timestamp when user first used an invite code
    pub joined_at: Option<u64>,
}

/// Waitlist entry stored at key `waitlist:{id}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitlistEntry {
    /// Unique waitlist entry ID
    pub id: String,
    /// Contact info (email or other identifier)
    pub contact: String,
    /// Optional Nostr pubkey provided at signup (hex)
    pub pubkey: Option<String>,
    /// Unix timestamp when added to waitlist
    pub requested_at: u64,
    /// Whether this entry has been approved
    pub approved: bool,
    /// Pubkey of admin who approved (hex)
    pub approved_by: Option<String>,
    /// Invite code issued to this entry
    pub code_issued: Option<String>,
}

/// Global stats stored at key `stats`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalStats {
    /// Total number of invite codes ever created
    pub total_codes: u64,
    /// Number of codes that have been used
    pub codes_used: u64,
    /// Number of entries in the waitlist
    pub waitlist_size: u64,
    /// Total number of users who have joined
    pub total_users: u64,
}

// ============================================================================
// API Request Types
// ============================================================================

/// Request body for POST /waitlist
#[derive(Debug, Deserialize)]
pub struct JoinWaitlistRequest {
    /// Contact info (email, social handle, etc.)
    pub contact: String,
    /// Optional Nostr pubkey (hex or bech32 npub)
    pub pubkey: Option<String>,
}

/// Request body for POST /validate
#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub code: String,
}

/// Request body for POST /consume
#[derive(Debug, Deserialize)]
pub struct ConsumeRequest {
    pub code: String,
}

/// Request body for POST /admin/grant
#[derive(Debug, Deserialize)]
pub struct AdminGrantRequest {
    /// Target user pubkey to receive allocations (hex)
    pub pubkey: String,
    /// Number of invite codes to allocate
    pub count: u32,
}

/// Request body for POST /admin/approve-waitlist
#[derive(Debug, Deserialize)]
pub struct AdminApproveWaitlistRequest {
    pub waitlist_id: String,
}

/// Request body for POST /admin/revoke
#[derive(Debug, Deserialize)]
pub struct AdminRevokeRequest {
    pub code: String,
}

/// Request body for POST /buy
#[derive(Debug, Deserialize)]
pub struct BuyWithCashuRequest {
    /// Cashu token string (cashuA prefixed)
    pub token: String,
    /// Optional Nostr pubkey to associate with the code (hex)
    pub pubkey: Option<String>,
}

// ============================================================================
// API Response Types
// ============================================================================

/// Response for POST /validate
#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator_pubkey: Option<String>,
    pub used: bool,
}

/// Response for POST /generate-code
#[derive(Debug, Serialize)]
pub struct GenerateCodeResponse {
    pub code: String,
    pub codes_remaining: u32,
}

/// Response for GET /my-codes
#[derive(Debug, Serialize)]
pub struct MyCodesResponse {
    pub codes_allocated: u32,
    pub codes_generated: Vec<InviteCode>,
    pub codes_remaining: u32,
}

/// Response for POST /buy
#[derive(Debug, Serialize)]
pub struct BuyResponse {
    pub code: String,
    pub amount_sats: u64,
}

/// Invite tree node for GET /admin/tree
#[derive(Debug, Serialize)]
pub struct InviteTreeNode {
    pub pubkey: String,
    pub codes_allocated: u32,
    pub codes_used: u32,
    pub invited_by: Option<String>,
    pub joined_at: Option<u64>,
    pub codes_generated: Vec<String>,
}
