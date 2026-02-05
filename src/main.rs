//! claude-guardrails - Security guardrails for Claude Code YOLO mode
//!
//! A fast, robust security hook that analyzes commands before execution.
//!
//! # Usage
//!
//! ```bash
//! # As a Claude Code hook (reads JSON from stdin, writes JSON to stdout)
//! echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | claude-guardrails
//!
//! # With safety level override
//! claude-guardrails --safety-level=strict
//!
//! # Dry-run mode (show what would be blocked)
//! claude-guardrails --dry-run
//! ```

use std::env;
use std::io::{self, BufRead, Write};

use claude_guardrails::{
    audit::AuditLogger,
    config::{Config, SafetyLevel},
    engine::SecurityEngine,
    input::HookInput,
    output::HookOutput,
};

/// Print version information
fn print_version() {
    println!("claude-guardrails {}", env!("CARGO_PKG_VERSION"));
}

/// Print help message
fn print_help() {
    println!(
        r#"claude-guardrails - Security guardrails for Claude Code YOLO mode

USAGE:
    claude-guardrails [OPTIONS]

OPTIONS:
    -h, --help              Print this help message
    -v, --version           Print version information
    -l, --safety-level      Safety level: critical, high, strict (default: high)
    -d, --dry-run           Dry-run mode (show what would be blocked but allow)
    -c, --config PATH       Path to config file

ENVIRONMENT:
    GUARDRAILS_DISABLED=1   Disable all checks (still logs)
    GUARDRAILS_WARN_ONLY=1  Warn but don't block

USAGE AS HOOK:
    Configure in ~/.claude/settings.json:
    {{
      "hooks": {{
        "PreToolUse": [{{
          "type": "command",
          "command": "~/.claude/guardrails/claude-guardrails",
          "timeout": 5000,
          "tools": ["Bash", "Read", "Edit", "Write"]
        }}]
      }}
    }}
"#
    );
}

/// Parse command line arguments
struct Args {
    help: bool,
    version: bool,
    safety_level: Option<SafetyLevel>,
    dry_run: bool,
    config_path: Option<String>,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut result = Args {
            help: false,
            version: false,
            safety_level: None,
            dry_run: false,
            config_path: None,
        };

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => result.help = true,
                "-v" | "--version" => result.version = true,
                "-d" | "--dry-run" => result.dry_run = true,
                "-l" | "--safety-level" => {
                    if i + 1 < args.len() {
                        i += 1;
                        result.safety_level = SafetyLevel::from_str(&args[i]);
                    }
                }
                "-c" | "--config" => {
                    if i + 1 < args.len() {
                        i += 1;
                        result.config_path = Some(args[i].clone());
                    }
                }
                arg if arg.starts_with("--safety-level=") => {
                    let level = arg.trim_start_matches("--safety-level=");
                    result.safety_level = SafetyLevel::from_str(level);
                }
                arg if arg.starts_with("--config=") => {
                    let path = arg.trim_start_matches("--config=");
                    result.config_path = Some(path.to_string());
                }
                _ => {}
            }
            i += 1;
        }

        result
    }
}

fn main() {
    let args = Args::parse();

    // Handle help and version
    if args.help {
        print_help();
        return;
    }

    if args.version {
        print_version();
        return;
    }

    // Load configuration
    let mut config = if let Some(ref path) = args.config_path {
        Config::load_from(std::path::Path::new(path)).unwrap_or_else(|e| {
            eprintln!("Warning: Failed to load config from {}: {}", path, e);
            Config::default()
        })
    } else {
        Config::load()
    };

    // Override safety level if specified
    if let Some(level) = args.safety_level {
        config.general.safety_level = level;
    }

    // Set up dry-run mode via environment
    if args.dry_run {
        env::set_var("GUARDRAILS_WARN_ONLY", "1");
    }

    // Create security engine
    let engine = SecurityEngine::new(config.clone());

    // Create audit logger
    let audit_path = if config.general.audit_log {
        config.audit_path()
    } else {
        None
    };
    let mut logger = AuditLogger::new(audit_path.as_deref());

    // Read JSON from stdin
    let stdin = io::stdin();
    let mut input_json = String::new();

    for line in stdin.lock().lines() {
        match line {
            Ok(line) => input_json.push_str(&line),
            Err(_) => break,
        }
    }

    // Handle empty input
    if input_json.trim().is_empty() {
        // No input = nothing to check, allow
        let output = HookOutput::allow();
        println!("{}", output.to_json());
        return;
    }

    // Parse input
    let input = match HookInput::from_json(&input_json) {
        Ok(input) => input,
        Err(e) => {
            // SECURITY: Fail closed on parse errors
            // Malformed input could be an evasion attempt
            eprintln!("Error: Failed to parse input (denying): {}", e);
            let output = HookOutput::deny_with_rule(
                "parse-error",
                &format!("Failed to parse hook input: {}", e),
            );
            println!("{}", output.to_json());
            return;
        }
    };

    // Check if disabled
    let disabled = engine.is_disabled();

    // Run security check
    let decision = engine.check(&input);

    // Log the decision
    if let Err(e) = logger.log_decision(&input, &decision, disabled) {
        eprintln!("Warning: Failed to write audit log: {}", e);
    }

    // Generate output
    let output = HookOutput::from_decision(&decision);

    // Write to stdout
    let json = output.to_json();
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{}", json);
    let _ = handle.flush();
}
