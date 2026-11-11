//! Resolve literal assignments made earlier in the same command (steward-fd2k).
//!
//! The guard blocks a variable in command position ("dynamic-command") because the
//! variable hides which command runs. When the same command text assigns that
//! variable a plain literal first (`S=/tmp/a; $S/x.sh`), nothing is hidden: the
//! literal is right there. [`resolve`] substitutes the literals and returns the
//! expanded text, so the caller can check it against every rule as if it had been
//! typed.
//!
//! This is a security boundary, so the model is small and refuses on anything it
//! does not fully understand. `None` always means "keep the block".
//!
//! # What is modelled
//!
//! The command is a flat list of top-level statements joined by `;` or newlines.
//! Each statement is one of:
//!
//! * a bare assignment `NAME=literal`, or `export NAME=literal ...`: sets `NAME`;
//! * a "use" statement: a command, pipeline, list (`&&`, `||`) or redirected
//!   statement built only from words, quotes, plain `$NAME` / `${NAME}` references
//!   and redirects. Every reference to a known name is replaced by its literal.
//!
//! # What makes it refuse (`None`)
//!
//! * a value that is not a plain literal: any `$`, backtick, `$(...)`, `<(...)`,
//!   backslash, quote inside the value, glob or brace character, `=`, `;`, `|`, `&`,
//!   `<`, `>`, `#`, `!`, newline or tab. The allowed characters are letters, digits
//!   and `_ . / : @ % + , ~ -` and the space;
//! * an assignment that may not run or may not persist: inside `||`/`&&` lists, a
//!   subshell, a group, `if`/`for`/`while`/`case`, a function, a command
//!   substitution, or followed by `&`;
//! * a prefix assignment (`X=a cmd`), `unset`, `declare`/`local`/`readonly` and
//!   any builtin that can change or evaluate variables (see [`MUTATORS`]);
//! * a name that changes how words split or how commands are found (see
//!   [`is_reserved`]);
//! * a braced expansion with an operator (`${X:-d}`, `${#X}`, `${!X}`);
//! * an unbraced `$NAME` of a known name directly followed by `:` or `[` (zsh
//!   modifiers and subscripts: `$X:l`, `$X[1]`);
//! * an expansion that creates a declaration (`export`, `unset`) the literal text did
//!   not contain, such as `$K X=rm` with `K=export`;
//! * a `$NAME` for a known name that the parser did not see as an expansion
//!   (single quotes, backslash escapes, comments): the textual and parsed counts
//!   must agree;
//! * a command name that is not one plain word after substitution (`rm""`,
//!   `'rm'`, `r\m`), so a spelling the rules do not match cannot be produced;
//! * a space-containing literal in a redirect target;
//! * the expanded text failing the same checks again (it must be a fixed point).
//!
//! Unknown names (`$HOME`, a variable assigned by something this model does not
//! understand) are left alone, exactly as typed text is today. Only a variable in
//! command position that is still unresolved keeps the block, and the caller
//! re-runs the dynamic-command detector on the expanded text to enforce that.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use tree_sitter::{Node, Parser};

/// Builtins and keywords that can assign a variable, evaluate text, change how a
/// name resolves, or run later statements somewhere this model cannot see. A command
/// named by any of these makes the whole command unresolvable.
const MUTATORS: &[&str] = &[
    ".",
    "alias",
    "builtin",
    "command",
    "coproc",
    "declare",
    "enable",
    "eval",
    "exec",
    "export",
    "getopts",
    "hash",
    "let",
    "local",
    "mapfile",
    "printf",
    "read",
    "readarray",
    "readonly",
    "set",
    "shift",
    "shopt",
    "source",
    "time",
    "trap",
    "typeset",
    "unalias",
    "unset",
    "wait",
];

/// A reference to `$NAME` or `${NAME` anywhere in the text, quotes and escapes
/// included. Used to cross-check the parsed references.
static REFERENCE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)").expect("valid regex"));

/// One replacement in the source text.
struct Edit {
    start: usize,
    end: usize,
    text: String,
}

/// Characters a literal may contain. Everything the shell treats specially is out,
/// so the text is the same words before and after expansion.
fn is_value_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '_' | '.' | '/' | ':' | '@' | '%' | '+' | ',' | '~' | '-' | ' '
        )
}

/// Names whose value is not a plain stored string, or that change how the shell
/// splits words, finds commands or resolves paths.
fn is_reserved(name: &str) -> bool {
    matches!(
        name,
        "_" | "IFS"
            | "PATH"
            | "CDPATH"
            | "PWD"
            | "OLDPWD"
            | "SHLVL"
            | "RANDOM"
            | "SRANDOM"
            | "SECONDS"
            | "LINENO"
            | "PPID"
            | "UID"
            | "EUID"
            | "GROUPS"
            | "OPTIND"
            | "OPTARG"
            | "OPTERR"
            | "REPLY"
            | "FUNCNAME"
            | "GLOBIGNORE"
            | "FIGNORE"
            | "PIPESTATUS"
            | "DIRSTACK"
            | "MAPFILE"
            // zsh: lower-case arrays tied to PATH, CDPATH and friends, and the
            // commands zsh runs for a bare redirect.
            | "path"
            | "cdpath"
            | "fpath"
            | "NULLCMD"
            | "READNULLCMD"
    ) || name.starts_with("BASH")
        || name.starts_with("ZSH")
        || name.starts_with("COMP")
        || name.starts_with("EPOCH")
        || name.starts_with("HIST")
        || name.starts_with("READLINE")
}

/// Substitute the literals assigned earlier in `source` and return the expanded
/// text, or `None` when the command is not fully understood (keep the block).
///
/// `None` is also returned when nothing was substituted: a variable in command
/// position that no literal explains is exactly what the block is for.
pub fn resolve(source: &str) -> Option<String> {
    let edits = plan(source)?;
    if edits.is_empty() {
        return None;
    }
    let expanded = apply(source, edits);

    // Substitution only adds text. A command name that expanded to `export` or
    // `unset` (`$K X=rm`) is a declaration the walk above never saw, so a later
    // `$X` kept a stale value. The literal text and the expanded text must hold the
    // same declarations.
    if count_declarations(source)? != count_declarations(&expanded)? {
        return None;
    }

    // The expanded text must be understood by the same rules, with nothing left to
    // substitute and every command named by one plain word.
    let again = plan(&expanded)?;
    if !again.is_empty() {
        return None;
    }
    if !commands_are_plain(&expanded)? {
        return None;
    }
    Some(expanded)
}

/// Number of `declaration_command` and `unset_command` nodes anywhere in `source`.
fn count_declarations(source: &str) -> Option<usize> {
    fn walk(node: &Node) -> usize {
        let own = usize::from(matches!(
            node.kind(),
            "declaration_command" | "unset_command"
        ));
        let mut cursor = node.walk();
        own + node.children(&mut cursor).map(|c| walk(&c)).sum::<usize>()
    }
    Some(walk(&parse(source)?.root_node()))
}

fn parse(source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    if tree.root_node().has_error() {
        return None;
    }
    Some(tree)
}

fn apply(source: &str, mut edits: Vec<Edit>) -> String {
    // Edits come from non-overlapping nodes in source order; apply from the back so
    // earlier byte offsets stay valid.
    edits.sort_by_key(|e| e.start);
    let mut out = source.to_string();
    for e in edits.iter().rev() {
        out.replace_range(e.start..e.end, &e.text);
    }
    out
}

/// Walk the top-level statements, tracking known literals and collecting the
/// replacements for every reference to one. `None` means refuse.
fn plan(source: &str) -> Option<Vec<Edit>> {
    let tree = parse(source)?;
    let root = tree.root_node();
    let mut env: HashMap<String, String> = HashMap::new();
    let mut edits = Vec::new();

    let mut cursor = root.walk();
    for stmt in root.children(&mut cursor) {
        if !stmt.is_named() {
            // Only `;` separates. `&` backgrounds the previous statement (a subshell),
            // `;;` and anything else is not a plain sequence.
            if stmt.kind() == ";" {
                continue;
            }
            return None;
        }
        match stmt.kind() {
            "comment" => {}
            "variable_assignment" => {
                let (name, value) = literal_assignment(&stmt, source)?;
                env.insert(name, value);
            }
            "declaration_command" => {
                let mut c = stmt.walk();
                let kids: Vec<Node> = stmt.children(&mut c).collect();
                if kids.len() < 2 || kids[0].kind() != "export" {
                    return None;
                }
                for kid in &kids[1..] {
                    if kid.kind() != "variable_assignment" {
                        return None;
                    }
                    let (name, value) = literal_assignment(kid, source)?;
                    env.insert(name, value);
                }
            }
            _ => {
                let mut ctx = Use {
                    source,
                    env: &env,
                    edits: &mut edits,
                    substituted: 0,
                };
                walk_use(&stmt, &mut ctx, false)?;
                // Every `$NAME` for a known name must have been parsed as an
                // expansion and replaced; otherwise the author meant something this
                // model does not see (quotes, escapes).
                let text = stmt.utf8_text(source.as_bytes()).ok()?;
                let textual = REFERENCE
                    .captures_iter(text)
                    .filter(|c| env.contains_key(&c[1]))
                    .count();
                if textual != ctx.substituted {
                    return None;
                }
            }
        }
    }
    Some(edits)
}

/// `NAME=literal` (or `NAME=`): the name and value, or `None` if either is not plain.
fn literal_assignment(node: &Node, source: &str) -> Option<(String, String)> {
    let mut cursor = node.walk();
    let kids: Vec<Node> = node.children(&mut cursor).collect();
    // Exactly `name`, `=` and at most one value; `+=` and `name[i]=` do not fit.
    if kids.len() < 2 || kids.len() > 3 {
        return None;
    }
    if kids[0].kind() != "variable_name" || kids[1].kind() != "=" {
        return None;
    }
    let name = kids[0].utf8_text(source.as_bytes()).ok()?.to_string();
    if is_reserved(&name) {
        return None;
    }
    let value = match kids.get(2) {
        None => String::new(),
        Some(v) => literal_value(v, source)?,
    };
    Some((name, value))
}

fn literal_value(node: &Node, source: &str) -> Option<String> {
    let text = node.utf8_text(source.as_bytes()).ok()?;
    let value = match node.kind() {
        "word" | "number" => text,
        "raw_string" => text.strip_prefix('\'')?.strip_suffix('\'')?,
        "string" => {
            // Only literal content between the quotes: no expansion, no substitution.
            let mut c = node.walk();
            if node
                .named_children(&mut c)
                .any(|k| k.kind() != "string_content")
            {
                return None;
            }
            text.strip_prefix('"')?.strip_suffix('"')?
        }
        _ => return None,
    };
    if value.chars().all(is_value_char) {
        Some(value.to_string())
    } else {
        None
    }
}

/// State for walking one "use" statement.
struct Use<'a> {
    source: &'a str,
    env: &'a HashMap<String, String>,
    edits: &'a mut Vec<Edit>,
    substituted: usize,
}

/// Walk a use statement. Only a small set of node kinds is understood; any other
/// kind (subshell, substitution, assignment, compound, function, ...) refuses.
fn walk_use(node: &Node, ctx: &mut Use, in_redirect: bool) -> Option<()> {
    if !node.is_named() {
        // Operators and quotes inside kinds already allowed: `|`, `&&`, `||`, `"`, `>`.
        return Some(());
    }
    match node.kind() {
        "command" => {
            check_command_name(node, ctx.source)?;
            walk_children(node, ctx, in_redirect)
        }
        "pipeline"
        | "list"
        | "redirected_statement"
        | "command_name"
        | "concatenation"
        | "string"
        | "raw_string"
        | "string_content"
        | "word"
        | "number"
        | "variable_name"
        | "special_variable_name"
        | "file_descriptor" => walk_children(node, ctx, in_redirect),
        "file_redirect" => walk_children(node, ctx, true),
        "simple_expansion" => reference(node, ctx, in_redirect, false),
        "expansion" => reference(node, ctx, in_redirect, true),
        _ => None,
    }
}

fn walk_children(node: &Node, ctx: &mut Use, in_redirect: bool) -> Option<()> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_use(&child, ctx, in_redirect)?;
    }
    Some(())
}

/// A literal command name may not be a builtin that changes variables. A name that
/// is still built from expansions or quotes is checked after substitution, when the
/// whole text is walked again.
fn check_command_name(node: &Node, source: &str) -> Option<()> {
    let mut cursor = node.walk();
    let name_node = node
        .children(&mut cursor)
        .find(|c| c.kind() == "command_name");
    if let Some(name_node) = name_node {
        let mut c = name_node.walk();
        let first = name_node.children(&mut c).next()?;
        if first.kind() == "word" || first.kind() == "number" {
            let text = first.utf8_text(source.as_bytes()).ok()?;
            if MUTATORS.contains(&text) {
                return None;
            }
        }
    }
    Some(())
}

/// Handle `$NAME` and `${NAME}`. Known names are replaced by their literal; unknown
/// names are left as typed. Anything else inside `${...}` refuses.
fn reference(node: &Node, ctx: &mut Use, in_redirect: bool, braced: bool) -> Option<()> {
    let mut cursor = node.walk();
    let kids: Vec<Node> = node.children(&mut cursor).collect();
    let name_node = if braced {
        // Exactly `${` name `}`: no operator, no indirection, no length.
        if kids.len() != 3 || kids[0].kind() != "${" || kids[2].kind() != "}" {
            return None;
        }
        &kids[1]
    } else {
        if kids.len() != 2 || kids[0].kind() != "$" {
            return None;
        }
        &kids[1]
    };
    match name_node.kind() {
        // `$1`, `$@`, `$?`: not a name this model tracks.
        "special_variable_name" => Some(()),
        "variable_name" => {
            let name = name_node.utf8_text(ctx.source.as_bytes()).ok()?;
            if let Some(value) = ctx.env.get(name) {
                // A space in a redirect target splits into extra words in the text but
                // is an "ambiguous redirect" error in the shell: do not guess.
                if in_redirect && value.contains(' ') {
                    return None;
                }
                // zsh applies history modifiers (`$X:l`, `$X:s/a/b/`, `$X:h`) and
                // subscripts (`$X[1]`) straight after an unbraced name, in or out of
                // double quotes, so the text after the reference would not be what
                // runs. `${X}:l` is a plain literal in zsh and stays allowed.
                if !braced
                    && matches!(
                        ctx.source.as_bytes().get(node.end_byte()),
                        Some(b':' | b'[')
                    )
                {
                    return None;
                }
                ctx.edits.push(Edit {
                    start: node.start_byte(),
                    end: node.end_byte(),
                    text: value.clone(),
                });
                ctx.substituted += 1;
            }
            Some(())
        }
        _ => None,
    }
}

/// After substitution, every command in the text must be named by one plain word
/// and must not be a variable-changing builtin. Returns `Some(false)` when not.
fn commands_are_plain(source: &str) -> Option<bool> {
    let tree = parse(source)?;
    let mut ok = true;
    visit_commands(&tree.root_node(), source, &mut ok);
    Some(ok)
}

fn visit_commands(node: &Node, source: &str, ok: &mut bool) {
    if node.kind() == "command" {
        let mut cursor = node.walk();
        let name_node = node
            .children(&mut cursor)
            .find(|c| c.kind() == "command_name");
        match name_node {
            // A command with no name is redirects and assignments only.
            None => {}
            Some(name_node) => {
                let mut c = name_node.walk();
                let mut parts = name_node.children(&mut c);
                let (first, rest) = (parts.next(), parts.next());
                let plain = match (first, rest) {
                    (Some(first), None) if first.kind() == "word" || first.kind() == "number" => {
                        let text = first.utf8_text(source.as_bytes()).unwrap_or("");
                        !text.is_empty()
                            && text.chars().all(|ch| is_value_char(ch) && ch != ' ')
                            && !MUTATORS.contains(&text)
                    }
                    _ => false,
                };
                if !plain {
                    *ok = false;
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_commands(&child, source, ok);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_command_and_arguments() {
        assert_eq!(
            resolve("S=/tmp/a; $S/x.sh --out $S/o").as_deref(),
            Some("S=/tmp/a; /tmp/a/x.sh --out /tmp/a/o")
        );
    }

    #[test]
    fn substitutes_braced_and_double_quoted() {
        assert_eq!(
            resolve("P=\"python3 -I /p/c.py\"; ${P} \"$P\" x").as_deref(),
            Some("P=\"python3 -I /p/c.py\"; python3 -I /p/c.py \"python3 -I /p/c.py\" x")
        );
    }

    #[test]
    fn concatenated_names_join_before_the_rules_see_them() {
        assert_eq!(
            resolve("X=r; Y=m; $X$Y -rf /").as_deref(),
            Some("X=r; Y=m; rm -rf /")
        );
    }

    #[test]
    fn reassignment_uses_the_value_in_force() {
        assert_eq!(
            resolve("X=echo; $X a; X=rm; $X b").as_deref(),
            Some("X=echo; echo a; X=rm; rm b")
        );
    }

    #[test]
    fn export_counts_as_assignment() {
        assert_eq!(
            resolve("export X=echo; $X a").as_deref(),
            Some("export X=echo; echo a")
        );
    }

    #[test]
    fn nothing_to_substitute_is_none() {
        assert_eq!(resolve("echo hi"), None);
        assert_eq!(resolve("$X hi"), None);
        assert_eq!(resolve("X=echo; ls"), None);
    }

    #[test]
    fn refuses_what_it_does_not_model() {
        for cmd in [
            "S=$(cmd); $S",
            "X=a; unset X; $X",
            "X=a || X=echo; $X",
            "(X=echo; $X)",
            "X=echo $X hi",
            "X=echo; ${X:-d} hi",
            "X=echo; $X '$X'",
            "X=rm; $X\"\" -rf /",
            "IFS=/; X=a/b; $X",
            "X='a b\nc'; $X",
            "X=echo; read X; $X",
            "X=echo; f() { :; }; $X",
            "K=export; X=echo; $K X=rm; $X -rf /",
            "X=RM; $X:l -rf /",
            "X=/; Y=rm; $Y -rf $X[1]",
            "path=/tmp/e; X=ls; $X",
            "ZSH_NAME=a; X=ls; $X",
        ] {
            assert_eq!(resolve(cmd), None, "should refuse {cmd:?}");
        }
    }

    #[test]
    fn value_characters() {
        for ok in ["a", "/a/b-c_d.e", "a b", "~/x", "a:b@c%d+e,f", ""] {
            assert!(ok.chars().all(is_value_char), "{ok:?}");
        }
        for bad in [
            "$", "`", "\\", "'", "\"", "*", "?", "[", "]", "{", "}", "(", ")", "<", ">", "|", "&",
            ";", "=", "#", "!", "\n", "\t", "^",
        ] {
            assert!(!bad.chars().all(is_value_char), "{bad:?}");
        }
    }
}
