//! steward-x5x9: the verdict for a variable in command position must not depend on how
//! it is quoted.
//!
//! On main a bare `$X hi` is blocked as `dynamic-command`, while `"$X" hi`,
//! `"${X}" hi` and `'$X' hi` pass. The same gap exists in the fallback used when the
//! parser cannot read the text: it looks only at the start of the input, so a variable
//! in a later command position (after `;`, `&&`, `||` or `|`) is not looked at.
//!
//! Each test names the forms it covers. Every deny case has a matching static case that
//! must stay allowed. All of them go through `SecurityEngine::check_bash`, the entry the
//! hook binary uses, with the real tree-sitter-bash parser and the real rule set.

use claude_guardrails::{Config, Decision, SafetyLevel, SecurityEngine};

fn verdict(command: &str) -> Decision {
    let mut config = Config::default();
    config.general.safety_level = SafetyLevel::High;
    SecurityEngine::new(config).check_bash(command)
}

/// The five spellings of a variable as the command word. `{}` is the variable name.
const FORMS: &[&str] = &["$X", "\"$X\"", "'$X'", "${X}", "\"${X}\""];

/// The static command word that matches each form in the same quoting.
const STATIC_FORMS: &[&str] = &["ls", "\"ls\"", "'ls'", "ls", "\"ls\""];

#[track_caller]
fn assert_blocked_by(command: &str, rule_id: &str) {
    let d = verdict(command);
    assert!(d.is_deny(), "expected a block for {command:?}, got {d:?}");
    assert_eq!(
        d.rule_id(),
        Some(rule_id),
        "expected {rule_id} for {command:?}, got {d:?}"
    );
}

#[track_caller]
fn assert_allowed(command: &str) {
    let d = verdict(command);
    assert!(d.is_allow(), "expected ALLOW for {command:?}, got {d:?}");
}

// ---------------------------------------------------------------------------
// The parsed path: one verdict for every quoting of the same variable.
// ---------------------------------------------------------------------------

#[test]
fn a_variable_command_word_is_blocked_in_every_quoting() {
    for form in FORMS {
        assert_blocked_by(&format!("{form} -la"), "dynamic-command");
        assert_blocked_by(&format!("X=ls; {form} -la"), "dynamic-command");
    }
}

#[test]
fn a_variable_command_word_is_blocked_after_a_separator_in_every_quoting() {
    for form in FORMS {
        for sep in [";", "&&", "||", "|", "\n"] {
            assert_blocked_by(&format!("echo start {sep} {form} -la"), "dynamic-command");
        }
    }
}

#[test]
fn a_variable_command_word_with_a_suffix_is_blocked_in_every_quoting() {
    for cmd in [
        "\"$X/tool\" args",
        "\"${X}/tool\" args",
        "\"$X\"/tool args",
        "'$X/tool' args",
        "\"a$X\" args",
    ] {
        assert_blocked_by(cmd, "dynamic-command");
    }
}

#[test]
fn a_substitution_command_word_gets_the_same_verdict_quoted_or_not() {
    // Bare `$(cmd) args` and a backtick word are blocked on main; the quoted forms are
    // the same command word.
    for cmd in [
        "$(echo ls) -la",
        "\"$(echo ls)\" -la",
        "`echo ls` -la",
        "\"`echo ls`\" -la",
    ] {
        assert_blocked_by(cmd, "dynamic-command");
    }
}

#[test]
fn static_command_words_stay_allowed_in_each_quoting() {
    for form in STATIC_FORMS {
        assert_allowed(&format!("{form} -la"));
        assert_allowed(&format!("echo start && {form} -la"));
    }
    assert_allowed("'ls' -la");
    assert_allowed("\"ls\" -la");
    assert_allowed("l\"s\" -la");
}

#[test]
fn a_variable_in_argument_position_stays_allowed_in_every_quoting() {
    // Only the command word is looked at. Arguments are untouched, as on main.
    for form in FORMS {
        assert_allowed(&format!("echo {form}"));
        assert_allowed(&format!("ls -la {form}"));
        assert_allowed(&format!("echo start; echo {form}"));
    }
}

// ---------------------------------------------------------------------------
// The fallback path: the text does not parse, every command position is looked at.
// ---------------------------------------------------------------------------

/// Text before the command that the parser cannot read. The fallback runs on it.
const UNPARSEABLE_PREFIXES: &[&str] = &[")", "x=( a", "echo <<", ";;"];

#[test]
fn the_fallback_blocks_a_variable_command_word_at_the_start_in_every_quoting() {
    for form in FORMS {
        assert_blocked_by(&format!("{form} -la )"), "variable-command");
    }
}

#[test]
fn the_fallback_blocks_a_variable_command_word_after_every_separator() {
    for form in FORMS {
        for sep in [";", "&&", "||", "|"] {
            for prefix in UNPARSEABLE_PREFIXES {
                assert_blocked_by(&format!("{prefix} {sep} {form} -la"), "variable-command");
            }
        }
    }
}

#[test]
fn the_fallback_blocks_a_variable_command_word_after_a_newline_group_or_keyword() {
    for form in FORMS {
        assert_blocked_by(&format!(")\n{form} -la"), "variable-command");
        assert_blocked_by(&format!("); {{ {form} -la; }}"), "variable-command");
        assert_blocked_by(&format!("); ( {form} -la )"), "variable-command");
        assert_blocked_by(&format!("); then {form} -la"), "variable-command");
    }
}

#[test]
fn the_fallback_blocks_a_substitution_command_word_after_a_separator() {
    for cmd in [
        "); $(echo ls) -la",
        ") && \"$(echo ls)\" -la",
        ") || `echo ls` -la",
        ") | \"`echo ls`\" -la",
    ] {
        assert_blocked_by(cmd, "variable-command");
    }
}

#[test]
fn the_fallback_keeps_static_command_words_and_arguments_allowed() {
    for form in STATIC_FORMS {
        for sep in [";", "&&", "||", "|"] {
            assert_allowed(&format!(") {sep} {form} -la"));
        }
    }
    for form in FORMS {
        assert_allowed(&format!("); echo {form}"));
        assert_allowed(&format!(") && ls -la {form}"));
    }
    assert_allowed("); echo $(date)");
    assert_allowed("); x=$(date); echo done");
    assert_allowed("); echo $(( 1 + 2 ))");
}
