// ABOUTME: Invite code generation and validation for DIVINE-XXXX format
// ABOUTME: Generates human-readable, collision-resistant alphanumeric codes

use sha2::{Digest, Sha256};

/// Prefix for all invite codes
const CODE_PREFIX: &str = "DIVINE-";

/// Alphanumeric character set: uppercase letters and digits, excluding ambiguous
/// characters (0/O, 1/I, L) to avoid confusion when reading codes aloud
const CHARSET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

const CHARSET_LEN: usize = 32; // must match CHARSET length

/// Length of the random suffix portion
const SUFFIX_LEN: usize = 4;

/// Generate a DIVINE-XXXX code from a seed string.
/// The code is deterministic for a given seed; vary the seed (e.g., include nonce)
/// to get different codes when retrying after a collision.
pub fn generate_code_from_seed(seed: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();

    let mut suffix = String::with_capacity(SUFFIX_LEN);
    for i in 0..SUFFIX_LEN {
        let byte = hash[i] as usize;
        suffix.push(CHARSET[byte % CHARSET_LEN] as char);
    }

    format!("{}{}", CODE_PREFIX, suffix)
}

/// Generate a DIVINE-XXXX code from creator pubkey, timestamp, and nonce.
/// Increment nonce to get a different code when retrying after a collision.
pub fn generate_code(creator_pubkey: &str, timestamp: u64, nonce: u32) -> String {
    let seed = format!("invite:{}:{}:{}", creator_pubkey, timestamp, nonce);
    generate_code_from_seed(&seed)
}

/// Check if a code string has the valid DIVINE-XXXX format.
/// Code must be uppercase; normalize first if needed.
pub fn is_valid_format(code: &str) -> bool {
    if !code.starts_with(CODE_PREFIX) {
        return false;
    }

    let suffix = &code[CODE_PREFIX.len()..];

    if suffix.len() != SUFFIX_LEN {
        return false;
    }

    suffix.chars().all(|c| (CHARSET as &[u8]).contains(&(c as u8)))
}

/// Normalize an invite code to uppercase for consistent storage and lookup
pub fn normalize_code(code: &str) -> String {
    code.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_has_correct_format() {
        let code = generate_code("abc123pubkey", 1700000000, 0);
        assert!(
            code.starts_with("DIVINE-"),
            "Code must start with DIVINE-"
        );
        assert_eq!(
            code.len(),
            11,
            "Code must be 11 chars total (DIVINE- = 7, suffix = 4)"
        );
    }

    #[test]
    fn test_generate_code_suffix_uses_only_charset_chars() {
        let code = generate_code("abc123pubkey", 1700000000, 0);
        let suffix = &code[CODE_PREFIX.len()..];
        for ch in suffix.chars() {
            assert!(
                (CHARSET as &[u8]).contains(&(ch as u8)),
                "Char '{}' not in charset",
                ch
            );
        }
    }

    #[test]
    fn test_generate_code_is_deterministic() {
        let code1 = generate_code("abc123pubkey", 1700000000, 0);
        let code2 = generate_code("abc123pubkey", 1700000000, 0);
        assert_eq!(code1, code2, "Same seed must produce same code");
    }

    #[test]
    fn test_generate_code_different_nonces_produce_valid_codes() {
        for nonce in 0..10 {
            let code = generate_code("abc123pubkey", 1700000000, nonce);
            assert!(
                is_valid_format(&code),
                "Code with nonce {} has invalid format: {}",
                nonce,
                code
            );
        }
    }

    #[test]
    fn test_is_valid_format_accepts_valid_codes() {
        assert!(is_valid_format("DIVINE-AB23"));
        assert!(is_valid_format("DIVINE-ABCD"));
        assert!(is_valid_format("DIVINE-2345"));
        assert!(is_valid_format("DIVINE-WXYZ"));
    }

    #[test]
    fn test_is_valid_format_rejects_invalid_codes() {
        assert!(!is_valid_format("DIVINE-ABC"), "Too short");
        assert!(!is_valid_format("DIVINE-ABCDE"), "Too long");
        assert!(!is_valid_format("INVITE-ABCD"), "Wrong prefix");
        assert!(!is_valid_format("divine-abcd"), "Lowercase not accepted");
        assert!(!is_valid_format("DIVINE-0OIL"), "Ambiguous chars not in charset");
        assert!(!is_valid_format(""), "Empty string");
    }

    #[test]
    fn test_charset_excludes_ambiguous_characters() {
        // 0 and O look alike; 1, I, and L look alike
        for &ch in CHARSET {
            assert_ne!(ch, b'0', "Charset must not contain '0'");
            assert_ne!(ch, b'O', "Charset must not contain 'O'");
            assert_ne!(ch, b'1', "Charset must not contain '1'");
            assert_ne!(ch, b'I', "Charset must not contain 'I'");
            assert_ne!(ch, b'L', "Charset must not contain 'L'");
        }
    }

    #[test]
    fn test_charset_has_correct_length() {
        assert_eq!(CHARSET.len(), CHARSET_LEN);
    }

    #[test]
    fn test_normalize_code_uppercases() {
        assert_eq!(normalize_code("divine-ab23"), "DIVINE-AB23");
        assert_eq!(normalize_code("DIVINE-AB23"), "DIVINE-AB23");
        assert_eq!(normalize_code("Divine-Ab2Z"), "DIVINE-AB2Z");
    }
}
