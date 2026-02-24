// ABOUTME: Main entry point for the divine-invite-faucet Fastly Compute service
// ABOUTME: Routes HTTP requests to invite code, waitlist, admin, and Cashu payment handlers

mod auth;
mod codes;
mod error;
mod kv;
mod types;

use crate::auth::require_auth;
use crate::codes::{generate_code, is_valid_format, normalize_code};
use crate::error::{FaucetError, Result};
use crate::kv::{
    add_to_user_index, add_to_waitlist_index, get_invite_code, get_or_create_user_state,
    get_stats, get_user_index, get_user_state, get_waitlist_entry, get_waitlist_index,
    increment_stats_codes_used, increment_stats_total_codes, increment_stats_users,
    increment_stats_waitlist, is_cashu_secret_spent, mark_cashu_secret_spent, put_invite_code,
    put_user_state, put_waitlist_entry,
};
use crate::types::{
    AdminApproveWaitlistRequest, AdminGrantRequest, AdminRevokeRequest, BuyResponse,
    BuyWithCashuRequest, ConsumeRequest, GenerateCodeResponse, InviteCode, InviteSource,
    InviteTreeNode, JoinWaitlistRequest, MyCodesResponse, NostrEvent, ValidateRequest,
    ValidateResponse, WaitlistEntry,
};

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Config store name (must match fastly.toml)
const CONFIG_STORE: &str = "invite_config";

/// Entry point
#[fastly::main]
fn main(req: Request) -> std::result::Result<Response, Error> {
    match handle_request(req) {
        Ok(resp) => Ok(resp),
        Err(e) => Ok(error_response(&e)),
    }
}

/// Route and handle the request
fn handle_request(req: Request) -> Result<Response> {
    let method = req.get_method().clone();
    let path = req.get_path().to_string();

    eprintln!("[FAUCET ROUTE] method={} path={}", method, path);

    match (method, path.as_str()) {
        // Public endpoints
        (Method::POST, "/waitlist") => handle_join_waitlist(req),
        (Method::POST, "/validate") => handle_validate(req),

        // Authenticated endpoints
        (Method::POST, "/consume") => handle_consume(req),
        (Method::GET, "/my-codes") => handle_my_codes(req),
        (Method::POST, "/generate-code") => handle_generate_code(req),

        // Cashu payment endpoint
        (Method::POST, "/buy") => handle_buy(req),

        // Admin endpoints
        (Method::POST, "/admin/grant") => handle_admin_grant(req),
        (Method::POST, "/admin/approve-waitlist") => handle_admin_approve_waitlist(req),
        (Method::GET, "/admin/tree") => handle_admin_tree(req),
        (Method::GET, "/admin/waitlist") => handle_admin_waitlist(req),
        (Method::GET, "/admin/stats") => handle_admin_stats(req),
        (Method::POST, "/admin/revoke") => handle_admin_revoke(req),

        // CORS preflight
        (Method::OPTIONS, _) => Ok(cors_preflight_response()),

        // Not found
        _ => Err(FaucetError::NotFound("Not found".into())),
    }
}

// ============================================================================
// Public Handlers
// ============================================================================

/// POST /waitlist — Join the invite waitlist
fn handle_join_waitlist(mut req: Request) -> Result<Response> {
    let body: JoinWaitlistRequest = parse_json_body(&mut req)?;

    if body.contact.trim().is_empty() {
        return Err(FaucetError::BadRequest("contact is required".into()));
    }

    let now = current_timestamp();
    let id = hash_id(&format!("waitlist:{}:{}", body.contact, now));

    let entry = WaitlistEntry {
        id: id.clone(),
        contact: body.contact.trim().to_string(),
        pubkey: body.pubkey,
        requested_at: now,
        approved: false,
        approved_by: None,
        code_issued: None,
    };

    put_waitlist_entry(&entry)?;
    add_to_waitlist_index(&id)?;
    increment_stats_waitlist()?;

    eprintln!("[WAITLIST] New entry id={}", id);

    let mut resp = json_response(
        StatusCode::CREATED,
        &serde_json::json!({ "id": id, "message": "You're on the waitlist!" }),
    );
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// POST /validate — Check if a code is valid (no auth required)
fn handle_validate(mut req: Request) -> Result<Response> {
    let body: ValidateRequest = parse_json_body(&mut req)?;
    let code = normalize_code(&body.code);

    let result = if !is_valid_format(&code) {
        ValidateResponse {
            valid: false,
            code: None,
            creator_pubkey: None,
            used: false,
        }
    } else {
        match get_invite_code(&code)? {
            None => ValidateResponse {
                valid: false,
                code: None,
                creator_pubkey: None,
                used: false,
            },
            Some(inv) => ValidateResponse {
                valid: inv.is_available(),
                code: Some(inv.code.clone()),
                creator_pubkey: Some(inv.creator_pubkey.clone()),
                used: inv.invitee_pubkey.is_some(),
            },
        }
    };

    let mut resp = json_response(StatusCode::OK, &result);
    add_cors_headers(&mut resp);
    Ok(resp)
}

// ============================================================================
// Authenticated Handlers
// ============================================================================

/// POST /consume — Use an invite code to register (links inviter → invitee)
fn handle_consume(mut req: Request) -> Result<Response> {
    let event = require_auth(&req)?;
    let body: ConsumeRequest = parse_json_body(&mut req)?;

    let code = normalize_code(&body.code);

    if !is_valid_format(&code) {
        return Err(FaucetError::BadRequest("Invalid code format".into()));
    }

    let mut invite = get_invite_code(&code)?
        .ok_or_else(|| FaucetError::NotFound("Invite code not found".into()))?;

    if !invite.is_available() {
        return Err(FaucetError::Conflict(
            "Invite code is already used or revoked".into(),
        ));
    }

    let now = current_timestamp();
    let invitee_pubkey = event.pubkey.to_lowercase();

    let mut invitee_state = get_or_create_user_state(&invitee_pubkey)?;

    // Reject if user already joined
    if invitee_state.joined_at.is_some() {
        return Err(FaucetError::Conflict("User has already joined".into()));
    }

    // Mark code as used
    invite.invitee_pubkey = Some(invitee_pubkey.clone());
    invite.used_at = Some(now);
    put_invite_code(&invite)?;

    // Update invitee user state
    invitee_state.invited_by = Some(invite.creator_pubkey.clone());
    invitee_state.joined_at = Some(now);
    // Grant default allocation if not pre-allocated by admin
    if invitee_state.codes_allocated == 0 {
        invitee_state.codes_allocated = 5;
    }
    put_user_state(&invitee_state)?;
    add_to_user_index(&invitee_pubkey)?;

    // Increment inviter's used count
    let mut creator_state = get_or_create_user_state(&invite.creator_pubkey)?;
    creator_state.codes_used += 1;
    put_user_state(&creator_state)?;

    increment_stats_codes_used()?;
    increment_stats_users()?;

    eprintln!("[CONSUME] code={} invitee={}", code, invitee_pubkey);

    let mut resp = json_response(
        StatusCode::OK,
        &serde_json::json!({
            "message": "Welcome to diVine!",
            "codes_allocated": invitee_state.codes_allocated,
        }),
    );
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// GET /my-codes — Get the caller's allocated invite codes
fn handle_my_codes(req: Request) -> Result<Response> {
    let event = require_auth(&req)?;
    let pubkey = event.pubkey.to_lowercase();

    let state = get_or_create_user_state(&pubkey)?;

    // Fetch each generated code's full record from KV
    let mut codes = Vec::new();
    for code_str in &state.codes_generated {
        if let Ok(Some(code)) = get_invite_code(code_str) {
            codes.push(code);
        }
    }

    let remaining = state
        .codes_allocated
        .saturating_sub(state.codes_generated.len() as u32);

    let result = MyCodesResponse {
        codes_allocated: state.codes_allocated,
        codes_generated: codes,
        codes_remaining: remaining,
    };

    let mut resp = json_response(StatusCode::OK, &result);
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// POST /generate-code — Generate one of the caller's allocated codes
fn handle_generate_code(req: Request) -> Result<Response> {
    let event = require_auth(&req)?;
    let pubkey = event.pubkey.to_lowercase();

    let mut state = get_or_create_user_state(&pubkey)?;

    if state.codes_generated.len() as u32 >= state.codes_allocated {
        return Err(FaucetError::Forbidden("No invite codes remaining".into()));
    }

    // Generate a collision-free code
    let now = current_timestamp();
    let mut nonce: u32 = 0;
    let code_str = loop {
        let candidate = generate_code(&pubkey, now, nonce);
        match get_invite_code(&candidate)? {
            None => break candidate,
            Some(_) => {
                nonce += 1;
                if nonce > 100 {
                    return Err(FaucetError::Internal(
                        "Code generation failed: too many collisions".into(),
                    ));
                }
            }
        }
    };

    let invite = InviteCode {
        code: code_str.clone(),
        creator_pubkey: pubkey.clone(),
        invitee_pubkey: None,
        created_at: now,
        used_at: None,
        source: InviteSource::Social,
        revoked: false,
    };

    put_invite_code(&invite)?;
    increment_stats_total_codes(1)?;

    state.codes_generated.push(code_str.clone());
    put_user_state(&state)?;

    let remaining = state
        .codes_allocated
        .saturating_sub(state.codes_generated.len() as u32);

    eprintln!("[GENERATE] pubkey={} code={}", pubkey, code_str);

    let mut resp = json_response(
        StatusCode::CREATED,
        &GenerateCodeResponse {
            code: code_str,
            codes_remaining: remaining,
        },
    );
    add_cors_headers(&mut resp);
    Ok(resp)
}

// ============================================================================
// Cashu Payment Handler
// ============================================================================

/// POST /buy — Submit a Cashu token to receive an invite code
fn handle_buy(mut req: Request) -> Result<Response> {
    let body: BuyWithCashuRequest = parse_json_body(&mut req)?;

    let price_sats = get_config("cashu_price_sats")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1000);

    let mint_url = get_config("cashu_mint_url")
        .unwrap_or_else(|| "https://mint.minibits.cash/Bitcoin".into());

    let (amount, secrets) = verify_cashu_token(&body.token, &mint_url, price_sats)?;

    // Mark all proof secrets as spent before issuing the code (prevents replay)
    for secret in &secrets {
        let hash = hex::encode(Sha256::digest(secret.as_bytes()));
        mark_cashu_secret_spent(&hash)?;
    }

    // Generate a collision-free invite code for the buyer
    let now = current_timestamp();
    let creator_pubkey = body
        .pubkey
        .as_deref()
        .map(|p| p.to_lowercase())
        .unwrap_or_else(|| format!("cashu:{}", hash_id(&secrets.join(","))));

    let mut nonce: u32 = 0;
    let code_str = loop {
        let candidate = generate_code(&format!("cashu:{}:{}", creator_pubkey, now), now, nonce);
        match get_invite_code(&candidate)? {
            None => break candidate,
            Some(_) => {
                nonce += 1;
                if nonce > 100 {
                    return Err(FaucetError::Internal("Code generation failed".into()));
                }
            }
        }
    };

    let invite = InviteCode {
        code: code_str.clone(),
        creator_pubkey: creator_pubkey.clone(),
        invitee_pubkey: None,
        created_at: now,
        used_at: None,
        source: InviteSource::Cashu,
        revoked: false,
    };

    put_invite_code(&invite)?;
    increment_stats_total_codes(1)?;

    eprintln!("[BUY] code={} amount_sats={}", code_str, amount);

    let mut resp = json_response(
        StatusCode::CREATED,
        &BuyResponse {
            code: code_str,
            amount_sats: amount,
        },
    );
    add_cors_headers(&mut resp);
    Ok(resp)
}

// ============================================================================
// Admin Handlers
// ============================================================================

/// POST /admin/grant — Allocate N invite codes to a user's pubkey
fn handle_admin_grant(mut req: Request) -> Result<Response> {
    let event = require_admin(&req)?;
    let body: AdminGrantRequest = parse_json_body(&mut req)?;

    if body.pubkey.is_empty() {
        return Err(FaucetError::BadRequest("pubkey is required".into()));
    }
    if body.count == 0 {
        return Err(FaucetError::BadRequest("count must be > 0".into()));
    }

    let target_pubkey = body.pubkey.to_lowercase();
    let mut state = get_or_create_user_state(&target_pubkey)?;
    state.codes_allocated += body.count;
    put_user_state(&state)?;
    add_to_user_index(&target_pubkey)?;

    eprintln!(
        "[ADMIN GRANT] admin={} target={} count={} total_allocated={}",
        event.pubkey, target_pubkey, body.count, state.codes_allocated
    );

    let mut resp = json_response(
        StatusCode::OK,
        &serde_json::json!({
            "pubkey": target_pubkey,
            "codes_allocated": state.codes_allocated,
        }),
    );
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// POST /admin/approve-waitlist — Approve a waitlist entry and issue an invite code
fn handle_admin_approve_waitlist(mut req: Request) -> Result<Response> {
    let event = require_admin(&req)?;
    let body: AdminApproveWaitlistRequest = parse_json_body(&mut req)?;

    let mut entry = get_waitlist_entry(&body.waitlist_id)?
        .ok_or_else(|| FaucetError::NotFound("Waitlist entry not found".into()))?;

    if entry.approved {
        return Err(FaucetError::Conflict(
            "Waitlist entry already approved".into(),
        ));
    }

    let now = current_timestamp();
    let admin_pubkey = event.pubkey.to_lowercase();

    // Generate a collision-free invite code for this waitlist entry
    let mut nonce: u32 = 0;
    let code_str = loop {
        let candidate = generate_code(
            &format!("waitlist:{}:{}", entry.id, admin_pubkey),
            now,
            nonce,
        );
        match get_invite_code(&candidate)? {
            None => break candidate,
            Some(_) => {
                nonce += 1;
                if nonce > 100 {
                    return Err(FaucetError::Internal("Code generation failed".into()));
                }
            }
        }
    };

    let invite = InviteCode {
        code: code_str.clone(),
        creator_pubkey: admin_pubkey.clone(),
        invitee_pubkey: None,
        created_at: now,
        used_at: None,
        source: InviteSource::Waitlist,
        revoked: false,
    };

    put_invite_code(&invite)?;
    increment_stats_total_codes(1)?;

    entry.approved = true;
    entry.approved_by = Some(admin_pubkey.clone());
    entry.code_issued = Some(code_str.clone());
    put_waitlist_entry(&entry)?;

    eprintln!(
        "[ADMIN APPROVE] admin={} waitlist_id={} code={}",
        admin_pubkey, body.waitlist_id, code_str
    );

    let mut resp = json_response(
        StatusCode::OK,
        &serde_json::json!({
            "waitlist_id": body.waitlist_id,
            "code": code_str,
        }),
    );
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// GET /admin/tree — View the invite tree (all users and their relationships)
fn handle_admin_tree(req: Request) -> Result<Response> {
    require_admin(&req)?;

    let pubkeys = get_user_index()?;
    let mut nodes: Vec<InviteTreeNode> = Vec::new();

    for pubkey in &pubkeys {
        if let Ok(Some(state)) = get_user_state(pubkey) {
            nodes.push(InviteTreeNode {
                pubkey: state.pubkey.clone(),
                codes_allocated: state.codes_allocated,
                codes_used: state.codes_used,
                invited_by: state.invited_by.clone(),
                joined_at: state.joined_at,
                codes_generated: state.codes_generated.clone(),
            });
        }
    }

    let mut resp = json_response(StatusCode::OK, &nodes);
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// GET /admin/waitlist — View all waitlist entries
fn handle_admin_waitlist(req: Request) -> Result<Response> {
    require_admin(&req)?;

    let ids = get_waitlist_index()?;
    let mut entries = Vec::new();

    for id in &ids {
        if let Ok(Some(entry)) = get_waitlist_entry(id) {
            entries.push(entry);
        }
    }

    let mut resp = json_response(StatusCode::OK, &entries);
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// GET /admin/stats — Global statistics
fn handle_admin_stats(req: Request) -> Result<Response> {
    require_admin(&req)?;

    let stats = get_stats()?;

    let mut resp = json_response(StatusCode::OK, &stats);
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// POST /admin/revoke — Revoke an invite code
fn handle_admin_revoke(mut req: Request) -> Result<Response> {
    let event = require_admin(&req)?;
    let body: AdminRevokeRequest = parse_json_body(&mut req)?;

    let code = normalize_code(&body.code);

    let mut invite = get_invite_code(&code)?
        .ok_or_else(|| FaucetError::NotFound("Invite code not found".into()))?;

    if invite.revoked {
        return Err(FaucetError::Conflict("Code is already revoked".into()));
    }

    invite.revoked = true;
    put_invite_code(&invite)?;

    eprintln!("[ADMIN REVOKE] admin={} code={}", event.pubkey, code);

    let mut resp = json_response(
        StatusCode::OK,
        &serde_json::json!({ "code": code, "revoked": true }),
    );
    add_cors_headers(&mut resp);
    Ok(resp)
}

// ============================================================================
// Cashu Token Verification
// ============================================================================

/// Cashu token envelope (cashuA format)
#[derive(Deserialize)]
struct CashuTokenEnvelope {
    token: Vec<CashuTokenEntry>,
}

/// Single mint entry inside a cashuA token
#[derive(Deserialize)]
struct CashuTokenEntry {
    mint: String,
    proofs: Vec<CashuProof>,
}

/// Individual Cashu proof
#[derive(Deserialize)]
struct CashuProof {
    amount: u64,
    secret: String,
}

/// Parse and verify a cashuA token against the expected mint and minimum price.
///
/// Decodes base64url → JSON, validates mint URL, sums proof amounts, and checks
/// our KV for already-processed proof secrets (replay prevention).
///
/// Note: This performs local replay prevention but does not call the mint's
/// checkstate API. A future improvement can add NUT-07 proof state verification.
///
/// Returns (total_amount_sats, proof_secrets) on success.
fn verify_cashu_token(
    token_str: &str,
    expected_mint_url: &str,
    min_sats: u64,
) -> Result<(u64, Vec<String>)> {
    // cashuA tokens start with "cashuA"
    let encoded = token_str
        .strip_prefix("cashuA")
        .ok_or_else(|| FaucetError::BadRequest("Token must start with 'cashuA'".into()))?;

    // Decode base64url (try without padding first, then with)
    let json_bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| URL_SAFE.decode(encoded))
        .map_err(|_| FaucetError::BadRequest("Invalid base64 in Cashu token".into()))?;

    let envelope: CashuTokenEnvelope = serde_json::from_slice(&json_bytes)
        .map_err(|e| FaucetError::BadRequest(format!("Invalid Cashu token JSON: {}", e)))?;

    if envelope.token.is_empty() {
        return Err(FaucetError::BadRequest("Empty Cashu token".into()));
    }

    let mut total_sats: u64 = 0;
    let mut all_secrets: Vec<String> = Vec::new();

    for entry in &envelope.token {
        // Validate the token's mint matches our configured mint
        if entry.mint.trim_end_matches('/') != expected_mint_url.trim_end_matches('/') {
            return Err(FaucetError::BadRequest(format!(
                "Token mint '{}' does not match accepted mint '{}'",
                entry.mint, expected_mint_url
            )));
        }

        for proof in &entry.proofs {
            // Check if this proof secret has already been processed by this service
            let secret_hash = hex::encode(Sha256::digest(proof.secret.as_bytes()));
            if is_cashu_secret_spent(&secret_hash)? {
                return Err(FaucetError::Conflict(
                    "Cashu token has already been redeemed".into(),
                ));
            }

            total_sats += proof.amount;
            all_secrets.push(proof.secret.clone());
        }
    }

    if total_sats < min_sats {
        return Err(FaucetError::BadRequest(format!(
            "Token amount {} sats is less than required {} sats",
            total_sats, min_sats
        )));
    }

    Ok((total_sats, all_secrets))
}

// ============================================================================
// Auth Helpers
// ============================================================================

/// Validate Nostr auth and verify the caller is a configured admin
fn require_admin(req: &Request) -> Result<NostrEvent> {
    let event = require_auth(req)?;
    if !is_admin(&event.pubkey) {
        return Err(FaucetError::Forbidden("Admin access required".into()));
    }
    Ok(event)
}

/// Check if a pubkey (hex) appears in the comma-separated admin_pubkeys config
fn is_admin(pubkey: &str) -> bool {
    let pubkey_lower = pubkey.to_lowercase();
    get_config("admin_pubkeys")
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_lowercase())
                .any(|p| p == pubkey_lower)
        })
        .unwrap_or(false)
}

// ============================================================================
// Config
// ============================================================================

/// Read a value from the Fastly config store
fn get_config(key: &str) -> Option<String> {
    fastly::config_store::ConfigStore::open(CONFIG_STORE).get(key)
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Generate a short hex ID: first 8 bytes of SHA-256 of input (16 hex chars)
fn hash_id(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(&hash[..8])
}

/// Parse a JSON body from a mutable request reference
fn parse_json_body<T: serde::de::DeserializeOwned>(req: &mut Request) -> Result<T> {
    let body = req.take_body_str();
    serde_json::from_str(&body)
        .map_err(|e| FaucetError::BadRequest(format!("Invalid JSON: {}", e)))
}

/// Build a JSON response (without CORS headers — call add_cors_headers separately)
fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Response {
    let json = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
    let mut resp = Response::from_status(status);
    resp.set_header(header::CONTENT_TYPE, "application/json");
    resp.set_body(json);
    resp
}

/// Build an error response with CORS headers
fn error_response(error: &FaucetError) -> Response {
    let body = serde_json::json!({ "error": error.message() });
    let mut resp = Response::from_status(error.status_code());
    resp.set_header(header::CONTENT_TYPE, "application/json");
    resp.set_body(body.to_string());
    add_cors_headers(&mut resp);
    resp
}

/// Add CORS headers permitting cross-origin requests
fn add_cors_headers(resp: &mut Response) {
    resp.set_header("Access-Control-Allow-Origin", "*");
    resp.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    resp.set_header("Access-Control-Allow-Headers", "Authorization, Content-Type");
}

/// CORS preflight response
fn cors_preflight_response() -> Response {
    let mut resp = Response::from_status(StatusCode::NO_CONTENT);
    add_cors_headers(&mut resp);
    resp.set_header("Access-Control-Max-Age", "86400");
    resp
}
