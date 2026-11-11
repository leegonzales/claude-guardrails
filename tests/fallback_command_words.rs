//! steward-bq2l: when the parser cannot read the text, a command word that holds `$` or a
//! backtick is judged at every command position. Where the scan does not model the
//! syntax, it does not guess: every later `$` or backtick is judged as a possible
//! command word. Here-document bodies are modelled, as data.
//!
//! Each "unreadable" case is run twice, once with unreadable text before it and once
//! with unreadable text after it, so that the fallback is the path under test. Cases
//! that are judged have a static twin that must stay allowed wherever the scan models
//! the syntax. All of them go through `SecurityEngine::check_bash`, the entry the hook
//! binary uses, with the real tree-sitter-bash parser and the real rule set.

use claude_guardrails::{Config, Decision, SafetyLevel, SecurityEngine};

fn verdict(command: &str) -> Decision {
    let mut config = Config::default();
    config.general.safety_level = SafetyLevel::High;
    SecurityEngine::new(config).check_bash(command)
}

/// The same command text made unreadable in two ways, so the fallback runs on it.
fn unreadable(row: &str) -> [String; 2] {
    [format!("); {row}"), format!("{row}\n() {{ true; }}")]
}

#[track_caller]
fn assert_judged_dynamic(command: &str) {
    let d = verdict(command);
    assert!(d.is_deny(), "expected a block for {command:?}, got {d:?}");
    assert!(
        matches!(d.rule_id(), Some("variable-command" | "dynamic-command")),
        "expected a dynamic-command rule for {command:?}, got {d:?}"
    );
}

#[track_caller]
fn assert_allowed(command: &str) {
    let d = verdict(command);
    assert!(d.is_allow(), "expected ALLOW for {command:?}, got {d:?}");
}

#[track_caller]
fn judged_dynamic_unreadable(row: &str) {
    for text in unreadable(row) {
        assert_judged_dynamic(&text);
    }
}

#[track_caller]
fn allowed_unreadable(row: &str) {
    for text in unreadable(row) {
        assert_allowed(&text);
    }
}

/// The two spellings of the variable used as the command word.
const WORDS: &[&str] = &["$X hi", "\"$X\" hi"];

// ---------------------------------------------------------------------------
// Redirections before the command word.
// ---------------------------------------------------------------------------

#[test]
fn a_command_word_after_an_input_redirection_is_judged() {
    for word in WORDS {
        for lead in ["<f", "< f", "0<f", "0< f", "<<<x", "<&0", "2<f"] {
            judged_dynamic_unreadable(&format!("{lead} {word}"));
        }
    }
}

#[test]
fn a_command_word_after_a_named_descriptor_redirection_is_judged() {
    for word in WORDS {
        judged_dynamic_unreadable(&format!("{{fd}}>/dev/null {word}"));
        judged_dynamic_unreadable(&format!("{{fd}}<f {word}"));
    }
}

#[test]
fn a_redirection_target_is_not_a_command_word() {
    for text in [
        "\"ls\">$X",
        "\"ls\">\"$X\"",
        "ls >$X",
        "ls <$X",
        "ls 2>$X",
        "ls >f $X",
        "ls <f $X",
        ">$X ls",
        "<$X ls",
        "A=1 >$X ls",
    ] {
        allowed_unreadable(text);
    }
}

// ---------------------------------------------------------------------------
// Syntax the scan does not model: the rest of the input is judged.
// ---------------------------------------------------------------------------

#[test]
fn a_command_in_a_function_keyword_body_is_judged() {
    for word in WORDS {
        judged_dynamic_unreadable(&format!("function f {{ {word}; }}; f"));
        judged_dynamic_unreadable(&format!("function f() {{ {word}; }}; f"));
        judged_dynamic_unreadable(&format!("function f {{\n{word}\n}}"));
    }
}

#[test]
fn a_command_in_a_short_body_is_judged() {
    for word in WORDS {
        judged_dynamic_unreadable(&format!("if [[ -n x ]] {{ {word} }}"));
        judged_dynamic_unreadable(&format!("for i in a b {{ {word} }}"));
    }
}

#[test]
fn a_command_after_a_double_parenthesis_is_judged() {
    for word in WORDS {
        judged_dynamic_unreadable(&format!("((echo a); {word})"));
        judged_dynamic_unreadable(&format!("echo $((echo a); {word})"));
    }
    // Two separate groups are scanned as commands.
    for word in WORDS {
        judged_dynamic_unreadable(&format!("( (echo a); {word} )"));
    }
}

#[test]
fn a_command_after_a_test_expression_is_judged() {
    judged_dynamic_unreadable("[[ -n x ]] && \"$X\" hi");
    judged_dynamic_unreadable("[[ a == a && \"$X\" ]]");
    allowed_unreadable("[[ -n x && -n y ]]");
}

#[test]
fn a_command_in_a_case_body_is_judged() {
    for word in WORDS {
        judged_dynamic_unreadable(&format!("case x in x) {word} ;; esac"));
        judged_dynamic_unreadable(&format!("case x in (a|b) {word} ;; esac"));
        judged_dynamic_unreadable(&format!("case x in x) ls ;; y) {word} ;; esac"));
    }
    allowed_unreadable("case x in x) ls ;; esac");
}

#[test]
fn a_dollar_after_an_unmodelled_construct_is_judged_and_one_before_it_is_not() {
    for construct in [
        "[[ a ]]",
        "case x in x) ls ;; esac",
        "echo <(date)",
        "echo $((1 + 2))",
    ] {
        judged_dynamic_unreadable(&format!("{construct}; echo \"$X\""));
        allowed_unreadable(&format!("echo \"$X\"; {construct}"));
    }
}

// ---------------------------------------------------------------------------
// Here-documents are modelled: the body is data, then the next line is a command.
// ---------------------------------------------------------------------------

#[test]
fn a_command_after_a_here_document_with_a_stray_quote_is_judged() {
    for word in WORDS {
        for body in ["say \"hi", "x=(a", "it's", "a ) b", "`"] {
            judged_dynamic_unreadable(&format!("cat <<EOF\n{body}\nEOF\n{word}"));
            judged_dynamic_unreadable(&format!("cat <<'EOF'\n{body}\nEOF\n{word}"));
            judged_dynamic_unreadable(&format!("cat <<-EOF\n\t{body}\n\tEOF\n{word}"));
        }
    }
}

#[test]
fn here_document_text_is_data_not_commands() {
    for text in [
        "cat <<'EOF'\n$X\nEOF",
        "cat <<'EOF'\n$X hi\nEOF",
        "cat <<'EOF'\n$(echo $X)\n`$X`\nEOF",
        "cat <<EOF\n$X hi\nEOF",
        "cat <<EOF\n\"$X\" hi\nEOF",
        "cat <<\"EOF\"\n$X hi\nEOF",
        "cat <<\\EOF\n$X hi\nEOF",
        "cat <<-EOF\n\t$X hi\n\tEOF",
        "cat <<EOF | tr a b\n$X\nEOF",
        "cat <<A <<B\n$X\nA\n$X\nB",
        "cat << EOF\n$X\nEOF",
    ] {
        allowed_unreadable(text);
    }
}

#[test]
fn a_command_after_the_last_of_two_here_documents_is_judged() {
    judged_dynamic_unreadable("cat <<A <<'B'\nx '\nA\ny \"\nB\n\"$X\" hi");
}

#[test]
fn a_substitution_in_an_unquoted_here_document_is_commands() {
    judged_dynamic_unreadable("cat <<EOF\n$($X hi)\nEOF");
    judged_dynamic_unreadable("cat <<EOF\n`\"$X\" hi`\nEOF");
    judged_dynamic_unreadable("cat <<EOF\nline $(echo a; $X hi)\nEOF");
    allowed_unreadable("cat <<EOF\n$(date) $(echo $X)\nEOF");
}

// ---------------------------------------------------------------------------
// Substitutions: backticks, process substitution, arithmetic, case in a substitution.
// ---------------------------------------------------------------------------

#[test]
fn the_last_word_inside_backticks_is_judged() {
    judged_dynamic_unreadable("echo `\"$X\"`");
    judged_dynamic_unreadable("echo `$X`");
    judged_dynamic_unreadable("echo \"`$X`\"");
    judged_dynamic_unreadable("echo `echo a; \"$X\"`");
    allowed_unreadable("echo `date`");
    allowed_unreadable("echo `ls \"$X\"`");
}

#[test]
fn a_command_inside_a_process_substitution_is_judged() {
    for word in WORDS {
        judged_dynamic_unreadable(&format!("echo p<({word})"));
        judged_dynamic_unreadable(&format!("echo <({word}) >({word})"));
        judged_dynamic_unreadable(&format!("diff <(ls) <({word})"));
    }
    allowed_unreadable("echo p<(date)");
}

#[test]
fn a_command_inside_an_arithmetic_substitution_is_judged() {
    judged_dynamic_unreadable("echo $(( $(\"$X\") ))");
    judged_dynamic_unreadable("(( $(\"$X\") ))");
    judged_dynamic_unreadable("echo $(( 1 + `\"$X\"` ))");
    // A quoted parenthesis does not end the arithmetic expression.
    judged_dynamic_unreadable("echo $(( $(echo \"(\") )); \"$X\"");
    judged_dynamic_unreadable("echo $(( $(echo ')') )); \"$X\"");
    allowed_unreadable("echo $((1 + 2))");
    allowed_unreadable("(( 1 + 2 )); ls");
}

#[test]
fn a_command_in_a_case_body_inside_a_substitution_is_judged() {
    judged_dynamic_unreadable("echo \"$(case x in x) \"$X\";; esac)\"");
    judged_dynamic_unreadable("echo $(case x in x) \"$X\";; esac)");
    judged_dynamic_unreadable("echo `case x in x) \"$X\";; esac`");
    allowed_unreadable("echo \"$(case x in x) ls;; esac)\"");
}

// ---------------------------------------------------------------------------
// The parsed path: two more expansion kinds as the command name.
// ---------------------------------------------------------------------------

#[test]
fn an_arithmetic_or_process_substitution_command_name_is_judged() {
    for text in [
        "$(( $X )) hi",
        "\"$(( $X ))\" hi",
        "$((1 + 2)) hi",
        "<(date) hi",
        "echo a; $(( $X )) hi",
        "echo a && <(date) hi",
    ] {
        let d = verdict(text);
        assert!(d.is_deny(), "expected a block for {text:?}, got {d:?}");
        assert_eq!(d.rule_id(), Some("dynamic-command"), "{text:?}");
    }
}

#[test]
fn an_arithmetic_or_process_substitution_argument_stays_allowed() {
    for text in [
        "echo $(( $X + 1 ))",
        "echo $((1 + 2))",
        "cat <(date)",
        "diff <(ls) <(ls)",
        "echo \"$(( 1 + 2 ))\"",
        "ls >(cat)",
    ] {
        assert_allowed(text);
    }
}
