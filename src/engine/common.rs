//! Common utilities for security engines
//!
//! Shared functionality used across bash and file engines.

use once_cell::sync::Lazy;
use regex::Regex;

/// Common secret patterns to detect in any context
pub static SECRET_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // API keys and tokens (flexible matching for various formats)
        Regex::new(r"(?i)api[_-]?key\s*[=:]\s*['\x22]?[a-zA-Z0-9_]{16,}").unwrap(),
        Regex::new(r"(?i)secret[_-]?key\s*[=:]\s*['\x22]?[a-zA-Z0-9_]{16,}").unwrap(),
        Regex::new(r"(?i)access[_-]?token\s*[=:]\s*['\x22]?[a-zA-Z0-9_]{16,}").unwrap(),
        // AWS patterns
        Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), // AWS Access Key
        Regex::new(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\x22]?[0-9a-zA-Z/+]{20,}").unwrap(),
        // GitHub tokens
        Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
        Regex::new(r"github_pat_[A-Za-z0-9_]{22,}").unwrap(),
        // Generic passwords in commands
        Regex::new(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\x22][^'\x22]+['\x22]").unwrap(),
    ]
});

/// Check if text contains potential secrets
pub fn contains_secret(text: &str) -> bool {
    for pattern in SECRET_PATTERNS.iter() {
        if pattern.is_match(text) {
            return true;
        }
    }
    false
}

/// Redact secrets in text for logging
pub fn redact_secrets(text: &str) -> String {
    let mut redacted = text.to_string();

    for pattern in SECRET_PATTERNS.iter() {
        redacted = pattern.replace_all(&redacted, "[REDACTED]").to_string();
    }

    redacted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_secret_api_key() {
        assert!(contains_secret("API_KEY=sk_live_abc123def456789012345"));
        assert!(contains_secret("api-key: abcdef1234567890abcdef"));
    }

    #[test]
    fn test_contains_secret_aws() {
        assert!(contains_secret("AKIAIOSFODNN7EXAMPLE"));
        assert!(contains_secret(
            "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
        ));
    }

    #[test]
    fn test_contains_secret_github() {
        assert!(contains_secret(
            "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        ));
        assert!(contains_secret(
            "github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        ));
    }

    #[test]
    fn test_contains_secret_password() {
        assert!(contains_secret("password='mysecretpassword'"));
        assert!(contains_secret("PASSWORD=\"hunter2\""));
    }

    #[test]
    fn test_no_secret_in_normal_text() {
        assert!(!contains_secret("git status"));
        assert!(!contains_secret("npm install"));
        assert!(!contains_secret("Hello, World!"));
    }

    #[test]
    fn test_redact_secrets() {
        let text = "API_KEY=sk_live_abc123def456789012345 some text";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("sk_live"));
        assert!(redacted.contains("[REDACTED]"));
    }
}
