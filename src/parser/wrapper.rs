//! Wrapper command detection and unwrapping
//!
//! Handles commands like sudo, timeout, env, etc. that wrap other commands.

use std::collections::HashSet;

/// Default wrapper commands to detect
pub const DEFAULT_WRAPPERS: &[&str] = &[
    "sudo",
    "timeout",
    "xargs",
    "env",
    "nice",
    "nohup",
    "ionice",
    "strace",
    "time",
    "unbuffer",
    "watch",
    "caffeinate", // macOS
    "doas",       // BSD sudo alternative
];

/// Extract the actual command from wrapper commands
///
/// Example: "sudo timeout 30 rm -rf /" -> ["rm -rf /"]
/// Example: "env VAR=val command arg" -> ["command arg"]
pub fn unwrap_command(command: &str, wrappers: &[String]) -> Vec<String> {
    let wrapper_set: HashSet<&str> = wrappers.iter().map(|s| s.as_str()).collect();
    let mut results = Vec::new();

    // Tokenize the command
    let tokens = match shlex::split(command) {
        Some(t) => t,
        None => return vec![command.to_string()],
    };

    if tokens.is_empty() {
        return vec![command.to_string()];
    }

    // Recursively unwrap
    let unwrapped = unwrap_tokens(&tokens, &wrapper_set);

    if unwrapped.is_empty() {
        results.push(command.to_string());
    } else {
        for cmd_tokens in unwrapped {
            results.push(cmd_tokens.join(" "));
        }
    }

    results
}

/// Recursively unwrap tokens
fn unwrap_tokens(tokens: &[String], wrappers: &HashSet<&str>) -> Vec<Vec<String>> {
    if tokens.is_empty() {
        return Vec::new();
    }

    let first = &tokens[0];

    // If not a wrapper, return as-is
    if !wrappers.contains(first.as_str()) {
        return vec![tokens.to_vec()];
    }

    // Handle specific wrappers
    match first.as_str() {
        "sudo" => unwrap_sudo(tokens, wrappers),
        "timeout" => unwrap_timeout(tokens, wrappers),
        "env" => unwrap_env(tokens, wrappers),
        "nice" | "ionice" | "nohup" | "strace" | "time" | "unbuffer" => {
            unwrap_simple_prefix(tokens, wrappers)
        }
        "xargs" => unwrap_xargs(tokens, wrappers),
        "watch" => unwrap_watch(tokens, wrappers),
        "caffeinate" | "doas" => unwrap_simple_prefix(tokens, wrappers),
        _ => vec![tokens.to_vec()],
    }
}

/// Unwrap sudo command
/// sudo [-u user] [-g group] [-E] [-H] [-P] [-S] command args...
fn unwrap_sudo(tokens: &[String], wrappers: &HashSet<&str>) -> Vec<Vec<String>> {
    let mut idx = 1;

    while idx < tokens.len() {
        let token = &tokens[idx];

        // Skip sudo options
        if token.starts_with('-') {
            // Options that take an argument
            if matches!(
                token.as_str(),
                "-u" | "--user" | "-g" | "--group" | "-C" | "--close-from" | "-h" | "--host"
            ) {
                idx += 2; // Skip option and its argument
            } else {
                idx += 1; // Skip single option
            }
        } else {
            // Found the actual command
            let remaining: Vec<String> = tokens[idx..].to_vec();
            return unwrap_tokens(&remaining, wrappers);
        }
    }

    Vec::new()
}

/// Unwrap timeout command
/// timeout [options] duration command args...
fn unwrap_timeout(tokens: &[String], wrappers: &HashSet<&str>) -> Vec<Vec<String>> {
    let mut idx = 1;

    while idx < tokens.len() {
        let token = &tokens[idx];

        if token.starts_with('-') {
            // Options that take an argument
            if matches!(token.as_str(), "-s" | "--signal" | "-k" | "--kill-after") {
                idx += 2;
            } else {
                idx += 1;
            }
        } else {
            // First non-option is the duration, skip it
            idx += 1;
            if idx < tokens.len() {
                let remaining: Vec<String> = tokens[idx..].to_vec();
                return unwrap_tokens(&remaining, wrappers);
            }
            break;
        }
    }

    Vec::new()
}

/// Unwrap env command
/// env [VAR=val...] command args...
fn unwrap_env(tokens: &[String], wrappers: &HashSet<&str>) -> Vec<Vec<String>> {
    let mut idx = 1;

    while idx < tokens.len() {
        let token = &tokens[idx];

        if token.starts_with('-') {
            // Skip options
            if matches!(token.as_str(), "-u" | "--unset") {
                idx += 2;
            } else {
                idx += 1;
            }
        } else if token.contains('=') {
            // Skip VAR=val assignments
            idx += 1;
        } else {
            // Found the actual command
            let remaining: Vec<String> = tokens[idx..].to_vec();
            return unwrap_tokens(&remaining, wrappers);
        }
    }

    Vec::new()
}

/// Unwrap simple prefix commands (nice, nohup, etc.)
/// These just take optional flags then the command
fn unwrap_simple_prefix(tokens: &[String], wrappers: &HashSet<&str>) -> Vec<Vec<String>> {
    let mut idx = 1;

    while idx < tokens.len() {
        let token = &tokens[idx];

        if token.starts_with('-') {
            // nice -n N, ionice -c N, etc.
            if matches!(token.as_str(), "-n" | "-c" | "-p") {
                idx += 2;
            } else {
                idx += 1;
            }
        } else {
            let remaining: Vec<String> = tokens[idx..].to_vec();
            return unwrap_tokens(&remaining, wrappers);
        }
    }

    Vec::new()
}

/// Unwrap xargs command
/// xargs [options] [command [initial-args]]
fn unwrap_xargs(tokens: &[String], wrappers: &HashSet<&str>) -> Vec<Vec<String>> {
    let mut idx = 1;

    while idx < tokens.len() {
        let token = &tokens[idx];

        if token.starts_with('-') {
            // Options that take an argument
            if matches!(
                token.as_str(),
                "-n" | "-L" | "-I" | "-E" | "-s" | "-P" | "-d" | "-a"
            ) {
                idx += 2;
            } else {
                idx += 1;
            }
        } else {
            // Found the command xargs will execute
            let remaining: Vec<String> = tokens[idx..].to_vec();
            return unwrap_tokens(&remaining, wrappers);
        }
    }

    Vec::new()
}

/// Unwrap watch command
/// watch [options] command
fn unwrap_watch(tokens: &[String], wrappers: &HashSet<&str>) -> Vec<Vec<String>> {
    let mut idx = 1;

    while idx < tokens.len() {
        let token = &tokens[idx];

        if token.starts_with('-') {
            // Options that take an argument
            if matches!(token.as_str(), "-n" | "-d" | "--interval" | "--differences") {
                idx += 2;
            } else {
                idx += 1;
            }
        } else {
            // Found the command
            let remaining: Vec<String> = tokens[idx..].to_vec();
            return unwrap_tokens(&remaining, wrappers);
        }
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_wrappers() -> Vec<String> {
        DEFAULT_WRAPPERS.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_unwrap_sudo() {
        let wrappers = default_wrappers();

        let result = unwrap_command("sudo rm -rf /", &wrappers);
        assert_eq!(result, vec!["rm -rf /"]);

        let result = unwrap_command("sudo -u root rm -rf /", &wrappers);
        assert_eq!(result, vec!["rm -rf /"]);

        let result = unwrap_command("sudo -E -H ls -la", &wrappers);
        assert_eq!(result, vec!["ls -la"]);
    }

    #[test]
    fn test_unwrap_timeout() {
        let wrappers = default_wrappers();

        let result = unwrap_command("timeout 30 rm -rf /", &wrappers);
        assert_eq!(result, vec!["rm -rf /"]);

        let result = unwrap_command("timeout -s KILL 60 command arg", &wrappers);
        assert_eq!(result, vec!["command arg"]);
    }

    #[test]
    fn test_unwrap_env() {
        let wrappers = default_wrappers();

        let result = unwrap_command("env VAR=val command arg", &wrappers);
        assert_eq!(result, vec!["command arg"]);

        let result = unwrap_command("env -i PATH=/bin command", &wrappers);
        assert_eq!(result, vec!["command"]);
    }

    #[test]
    fn test_unwrap_nested() {
        let wrappers = default_wrappers();

        let result = unwrap_command("sudo timeout 30 rm -rf /", &wrappers);
        assert_eq!(result, vec!["rm -rf /"]);

        let result = unwrap_command("sudo nice -n 10 nohup command arg", &wrappers);
        assert_eq!(result, vec!["command arg"]);
    }

    #[test]
    fn test_unwrap_no_wrapper() {
        let wrappers = default_wrappers();

        let result = unwrap_command("rm -rf /", &wrappers);
        assert_eq!(result, vec!["rm -rf /"]);

        let result = unwrap_command("git status", &wrappers);
        assert_eq!(result, vec!["git status"]);
    }

    #[test]
    fn test_unwrap_nohup() {
        let wrappers = default_wrappers();

        let result = unwrap_command("nohup command arg &", &wrappers);
        assert_eq!(result, vec!["command arg &"]);
    }

    #[test]
    fn test_unwrap_xargs() {
        let wrappers = default_wrappers();

        let result = unwrap_command("xargs rm -f", &wrappers);
        assert_eq!(result, vec!["rm -f"]);

        let result = unwrap_command("xargs -n 1 echo", &wrappers);
        assert_eq!(result, vec!["echo"]);
    }
}
