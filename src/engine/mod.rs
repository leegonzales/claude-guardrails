//! Security engine for claude-guardrails
//!
//! Coordinates security checks across all tool types.

pub mod bash;
pub mod common;
pub mod file;

use crate::config::{Config, SafetyLevel};
use crate::input::{HookInput, ToolInput};
use crate::output::Decision;
use crate::rules::allowlist::CompiledAllowlist;

use regex::RegexSet;
use std::env;

/// The main security engine
pub struct SecurityEngine {
    config: Config,
    safety_level: SafetyLevel,
    bash_rules: RegexSet,
    file_rules: RegexSet,
    exfil_rules: RegexSet,
    allowlist: CompiledAllowlist,
}

impl SecurityEngine {
    /// Create a new security engine with the given configuration
    pub fn new(config: Config) -> Self {
        let safety_level = config.general.safety_level;

        // Compile bash rules
        let bash_patterns: Vec<&str> = crate::rules::dangerous::get_rules_for_level(safety_level)
            .iter()
            .map(|r| r.pattern)
            .collect();
        let bash_rules = RegexSet::new(&bash_patterns).unwrap_or_else(|_| RegexSet::empty());

        // Compile file rules
        let file_patterns: Vec<&str> =
            crate::rules::secrets::get_secret_patterns_for_level(safety_level)
                .iter()
                .map(|r| r.pattern)
                .collect();
        let file_rules = RegexSet::new(&file_patterns).unwrap_or_else(|_| RegexSet::empty());

        // Compile exfiltration rules
        let exfil_patterns: Vec<&str> = crate::rules::exfiltration::get_exfiltration_rules()
            .iter()
            .filter(|r| safety_level.includes(r.level))
            .map(|r| r.pattern)
            .collect();
        let exfil_rules = RegexSet::new(&exfil_patterns).unwrap_or_else(|_| RegexSet::empty());

        // Load allowlist if configured
        let allowlist = config
            .allowlist_path()
            .and_then(|path| {
                if path.exists() {
                    CompiledAllowlist::from_file(&path).ok()
                } else {
                    None
                }
            })
            .unwrap_or_else(CompiledAllowlist::empty);

        Self {
            config,
            safety_level,
            bash_rules,
            file_rules,
            exfil_rules,
            allowlist,
        }
    }

    /// Check if guardrails are disabled via environment
    pub fn is_disabled(&self) -> bool {
        env::var("GUARDRAILS_DISABLED").is_ok()
    }

    /// Check if warn-only mode is enabled
    pub fn is_warn_only(&self) -> bool {
        env::var("GUARDRAILS_WARN_ONLY").is_ok()
    }

    /// Main entry point: check an input and return a decision
    pub fn check(&self, input: &HookInput) -> Decision {
        // Check if disabled via environment
        if self.is_disabled() {
            return Decision::allow("disabled via GUARDRAILS_DISABLED");
        }

        // Route to appropriate checker based on tool type
        let decision = match &input.tool_input {
            ToolInput::Bash { command, .. } => self.check_bash(command),
            ToolInput::Read { file_path } => self.check_file(&input.tool_name, file_path),
            ToolInput::Edit { file_path, .. } => self.check_file(&input.tool_name, file_path),
            ToolInput::Write { file_path, .. } => self.check_file(&input.tool_name, file_path),
            ToolInput::Unknown { .. } => Decision::allow("unknown tool type - passing through"),
        };

        // If warn-only mode, convert denies to warnings
        if self.is_warn_only() {
            if let Decision::Deny { rule_id, reason } = decision {
                return Decision::warn(rule_id, reason);
            }
        }

        decision
    }

    /// Check a bash command
    pub fn check_bash(&self, command: &str) -> Decision {
        // Check allowlist first
        if let Some(reason) = self.allowlist.matches("Bash", command) {
            return Decision::allow(format!("allowlisted: {}", reason));
        }

        // Use the bash-specific checker
        bash::check_command(
            command,
            &self.config,
            self.safety_level,
            &self.bash_rules,
            &self.exfil_rules,
        )
    }

    /// Check a file operation
    pub fn check_file(&self, tool: &str, file_path: &str) -> Decision {
        // Check allowlist first
        if let Some(reason) = self.allowlist.matches(tool, file_path) {
            return Decision::allow(format!("allowlisted: {}", reason));
        }

        // Use the file-specific checker
        file::check_path(file_path, self.safety_level, &self.file_rules)
    }

    /// Get the current safety level
    pub fn safety_level(&self) -> SafetyLevel {
        self.safety_level
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> SecurityEngine {
        SecurityEngine::new(Config::default())
    }

    #[test]
    fn test_basic_allow() {
        let engine = test_engine();
        let decision = engine.check_bash("ls -la");
        assert!(decision.is_allow());
    }

    #[test]
    fn test_rm_rf_root_blocked() {
        let engine = test_engine();
        let decision = engine.check_bash("rm -rf /");
        assert!(decision.is_deny());
    }

    #[test]
    fn test_file_env_blocked() {
        let engine = test_engine();
        let decision = engine.check_file("Read", "/path/to/.env");
        assert!(decision.is_deny());
    }

    #[test]
    fn test_file_normal_allowed() {
        let engine = test_engine();
        let decision = engine.check_file("Read", "/path/to/README.md");
        assert!(decision.is_allow());
    }
}
