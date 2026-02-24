// ABOUTME: Fastly KV store operations for invite codes, user state, waitlist, and stats
// ABOUTME: All values are JSON-serialized; keys use typed prefixes for namespacing

use crate::error::{FaucetError, Result};
use crate::types::{GlobalStats, InviteCode, UserState, WaitlistEntry};
use fastly::kv_store::{KVStore, KVStoreError};

/// KV store name (must match fastly.toml)
const KV_STORE_NAME: &str = "invite_data";

/// Key prefix for invite code records
const CODE_PREFIX: &str = "code:";

/// Key prefix for user state records
const USER_PREFIX: &str = "user:";

/// Key prefix for waitlist entry records
const WAITLIST_PREFIX: &str = "waitlist:";

/// Key for the waitlist entry ID index
const WAITLIST_INDEX_KEY: &str = "index:waitlist";

/// Key for the user pubkey index
const USER_INDEX_KEY: &str = "index:users";

/// Key for global statistics
const STATS_KEY: &str = "stats";

/// Key prefix for tracking spent Cashu proof secrets
const SPENT_CASHU_PREFIX: &str = "spent_cashu:";

/// Open the KV store, returning an error if unavailable
fn open_store() -> Result<KVStore> {
    KVStore::open(KV_STORE_NAME)
        .map_err(|e| FaucetError::StorageError(format!("Failed to open KV store: {}", e)))?
        .ok_or_else(|| FaucetError::StorageError("KV store not configured".into()))
}

// ============================================================================
// Invite Codes
// ============================================================================

/// Look up an invite code by its code string
pub fn get_invite_code(code: &str) -> Result<Option<InviteCode>> {
    let key = format!("{}{}", CODE_PREFIX, code.to_uppercase());
    let store = open_store()?;

    match store.lookup(&key) {
        Ok(mut entry) => {
            let body = entry.take_body().into_string();
            let record: InviteCode = serde_json::from_str(&body)
                .map_err(|e| FaucetError::StorageError(format!("Failed to parse invite code: {}", e)))?;
            Ok(Some(record))
        }
        Err(KVStoreError::ItemNotFound) => Ok(None),
        Err(e) => Err(FaucetError::StorageError(format!("KV lookup failed: {}", e))),
    }
}

/// Store an invite code record
pub fn put_invite_code(code: &InviteCode) -> Result<()> {
    let key = format!("{}{}", CODE_PREFIX, code.code.to_uppercase());
    let json = serde_json::to_string(code)
        .map_err(|e| FaucetError::Internal(format!("Failed to serialize invite code: {}", e)))?;

    let store = open_store()?;
    store
        .insert(&key, json)
        .map_err(|e| FaucetError::StorageError(format!("KV insert failed: {}", e)))?;

    Ok(())
}

// ============================================================================
// User State
// ============================================================================

/// Look up user state by pubkey (hex)
pub fn get_user_state(pubkey: &str) -> Result<Option<UserState>> {
    let key = format!("{}{}", USER_PREFIX, pubkey.to_lowercase());
    let store = open_store()?;

    match store.lookup(&key) {
        Ok(mut entry) => {
            let body = entry.take_body().into_string();
            let state: UserState = serde_json::from_str(&body)
                .map_err(|e| FaucetError::StorageError(format!("Failed to parse user state: {}", e)))?;
            Ok(Some(state))
        }
        Err(KVStoreError::ItemNotFound) => Ok(None),
        Err(e) => Err(FaucetError::StorageError(format!("KV lookup failed: {}", e))),
    }
}

/// Store user state
pub fn put_user_state(state: &UserState) -> Result<()> {
    let key = format!("{}{}", USER_PREFIX, state.pubkey.to_lowercase());
    let json = serde_json::to_string(state)
        .map_err(|e| FaucetError::Internal(format!("Failed to serialize user state: {}", e)))?;

    let store = open_store()?;
    store
        .insert(&key, json)
        .map_err(|e| FaucetError::StorageError(format!("KV insert failed: {}", e)))?;

    Ok(())
}

/// Get user state, returning a default empty state if not found
pub fn get_or_create_user_state(pubkey: &str) -> Result<UserState> {
    match get_user_state(pubkey)? {
        Some(state) => Ok(state),
        None => Ok(UserState {
            pubkey: pubkey.to_lowercase(),
            codes_allocated: 0,
            codes_generated: vec![],
            codes_used: 0,
            invited_by: None,
            joined_at: None,
        }),
    }
}

/// Get the list of all tracked user pubkeys
pub fn get_user_index() -> Result<Vec<String>> {
    let store = open_store()?;

    match store.lookup(USER_INDEX_KEY) {
        Ok(mut entry) => {
            let body = entry.take_body().into_string();
            let pubkeys: Vec<String> = serde_json::from_str(&body).unwrap_or_default();
            Ok(pubkeys)
        }
        Err(KVStoreError::ItemNotFound) => Ok(vec![]),
        Err(e) => Err(FaucetError::StorageError(format!("KV lookup failed: {}", e))),
    }
}

/// Add a pubkey to the user index (with retry for concurrent writes)
pub fn add_to_user_index(pubkey: &str) -> Result<()> {
    let pubkey_lower = pubkey.to_lowercase();

    for attempt in 0..5 {
        let mut pubkeys = get_user_index().unwrap_or_default();

        if pubkeys.contains(&pubkey_lower) {
            return Ok(());
        }

        pubkeys.push(pubkey_lower.clone());

        let json = serde_json::to_string(&pubkeys)
            .map_err(|e| FaucetError::Internal(format!("Failed to serialize user index: {}", e)))?;

        let store = open_store()?;
        match store.insert(USER_INDEX_KEY, json) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 4 => {
                eprintln!("[KV] Retry {} for user index update: {}", attempt + 1, e);
                continue;
            }
            Err(e) => return Err(FaucetError::StorageError(format!("KV insert failed: {}", e))),
        }
    }

    Err(FaucetError::StorageError(
        "Max retries exceeded for user index update".into(),
    ))
}

// ============================================================================
// Waitlist
// ============================================================================

/// Look up a waitlist entry by its ID
pub fn get_waitlist_entry(id: &str) -> Result<Option<WaitlistEntry>> {
    let key = format!("{}{}", WAITLIST_PREFIX, id);
    let store = open_store()?;

    match store.lookup(&key) {
        Ok(mut entry) => {
            let body = entry.take_body().into_string();
            let record: WaitlistEntry = serde_json::from_str(&body)
                .map_err(|e| FaucetError::StorageError(format!("Failed to parse waitlist entry: {}", e)))?;
            Ok(Some(record))
        }
        Err(KVStoreError::ItemNotFound) => Ok(None),
        Err(e) => Err(FaucetError::StorageError(format!("KV lookup failed: {}", e))),
    }
}

/// Store a waitlist entry
pub fn put_waitlist_entry(entry: &WaitlistEntry) -> Result<()> {
    let key = format!("{}{}", WAITLIST_PREFIX, entry.id);
    let json = serde_json::to_string(entry)
        .map_err(|e| FaucetError::Internal(format!("Failed to serialize waitlist entry: {}", e)))?;

    let store = open_store()?;
    store
        .insert(&key, json)
        .map_err(|e| FaucetError::StorageError(format!("KV insert failed: {}", e)))?;

    Ok(())
}

/// Get the list of all waitlist entry IDs
pub fn get_waitlist_index() -> Result<Vec<String>> {
    let store = open_store()?;

    match store.lookup(WAITLIST_INDEX_KEY) {
        Ok(mut entry) => {
            let body = entry.take_body().into_string();
            let ids: Vec<String> = serde_json::from_str(&body).unwrap_or_default();
            Ok(ids)
        }
        Err(KVStoreError::ItemNotFound) => Ok(vec![]),
        Err(e) => Err(FaucetError::StorageError(format!("KV lookup failed: {}", e))),
    }
}

/// Add a waitlist entry ID to the index (with retry for concurrent writes)
pub fn add_to_waitlist_index(id: &str) -> Result<()> {
    for attempt in 0..5 {
        let mut ids = get_waitlist_index().unwrap_or_default();

        if ids.contains(&id.to_string()) {
            return Ok(());
        }

        ids.push(id.to_string());

        let json = serde_json::to_string(&ids)
            .map_err(|e| FaucetError::Internal(format!("Failed to serialize waitlist index: {}", e)))?;

        let store = open_store()?;
        match store.insert(WAITLIST_INDEX_KEY, json) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 4 => {
                eprintln!("[KV] Retry {} for waitlist index update: {}", attempt + 1, e);
                continue;
            }
            Err(e) => return Err(FaucetError::StorageError(format!("KV insert failed: {}", e))),
        }
    }

    Err(FaucetError::StorageError(
        "Max retries exceeded for waitlist index update".into(),
    ))
}

// ============================================================================
// Global Stats
// ============================================================================

/// Get global stats, returning defaults if not yet stored
pub fn get_stats() -> Result<GlobalStats> {
    let store = open_store()?;

    match store.lookup(STATS_KEY) {
        Ok(mut entry) => {
            let body = entry.take_body().into_string();
            let stats: GlobalStats = serde_json::from_str(&body).unwrap_or_default();
            Ok(stats)
        }
        Err(KVStoreError::ItemNotFound) => Ok(GlobalStats::default()),
        Err(e) => Err(FaucetError::StorageError(format!("KV lookup failed: {}", e))),
    }
}

/// Store global stats
pub fn put_stats(stats: &GlobalStats) -> Result<()> {
    let json = serde_json::to_string(stats)
        .map_err(|e| FaucetError::Internal(format!("Failed to serialize stats: {}", e)))?;

    let store = open_store()?;
    store
        .insert(STATS_KEY, json)
        .map_err(|e| FaucetError::StorageError(format!("KV insert failed: {}", e)))?;

    Ok(())
}

/// Increment total_codes counter (with retry)
pub fn increment_stats_total_codes(by: u64) -> Result<()> {
    for attempt in 0..5 {
        let mut stats = get_stats()?;
        stats.total_codes += by;
        match put_stats(&stats) {
            Ok(()) => return Ok(()),
            Err(_) if attempt < 4 => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Increment codes_used counter (with retry)
pub fn increment_stats_codes_used() -> Result<()> {
    for attempt in 0..5 {
        let mut stats = get_stats()?;
        stats.codes_used += 1;
        match put_stats(&stats) {
            Ok(()) => return Ok(()),
            Err(_) if attempt < 4 => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Increment waitlist_size counter (with retry)
pub fn increment_stats_waitlist() -> Result<()> {
    for attempt in 0..5 {
        let mut stats = get_stats()?;
        stats.waitlist_size += 1;
        match put_stats(&stats) {
            Ok(()) => return Ok(()),
            Err(_) if attempt < 4 => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Increment total_users counter (with retry)
pub fn increment_stats_users() -> Result<()> {
    for attempt in 0..5 {
        let mut stats = get_stats()?;
        stats.total_users += 1;
        match put_stats(&stats) {
            Ok(()) => return Ok(()),
            Err(_) if attempt < 4 => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ============================================================================
// Cashu Spent Token Tracking
// ============================================================================

/// Check if a Cashu proof secret hash has already been spent through this service
pub fn is_cashu_secret_spent(secret_hash: &str) -> Result<bool> {
    let key = format!("{}{}", SPENT_CASHU_PREFIX, secret_hash);
    let store = open_store()?;

    match store.lookup(&key) {
        Ok(_) => Ok(true),
        Err(KVStoreError::ItemNotFound) => Ok(false),
        Err(e) => Err(FaucetError::StorageError(format!("KV lookup failed: {}", e))),
    }
}

/// Record a Cashu proof secret hash as spent
pub fn mark_cashu_secret_spent(secret_hash: &str) -> Result<()> {
    let key = format!("{}{}", SPENT_CASHU_PREFIX, secret_hash);
    let store = open_store()?;

    store
        .insert(&key, "1")
        .map_err(|e| FaucetError::StorageError(format!("KV insert failed: {}", e)))?;

    Ok(())
}
