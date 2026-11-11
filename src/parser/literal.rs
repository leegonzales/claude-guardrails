//! Resolve literal assignments made earlier in the same command (steward-fd2k).
//!
//! The guard blocks a variable in command position ("dynamic-command") because the
//! variable hides which command runs. When the same command text assigns that
//! variable a plain literal first (`S=/tmp/a; $S/x.sh`), nothing is hidden: the
//! literal is right there. [`resolve`] substitutes the literals and returns the
//! expanded text, so the caller can check it against every rule as if it had been
//! typed.
//!
//! # Why an allowlist
//!
//! Rounds 1 and 2 of review found a new bypass each time: `$K` that resolves to
//! `export`, zsh modifiers and subscripts, `noglob export`, `print -v`, `zstyle -s`,
//! backslash-newline. A denylist of shell builtins always lags the shell's grammar
//! (zsh has about 100 builtins and its own precommand modifiers). This module goes the
//! other way: it resolves only an input whose every part it fully understands, and
//! `None` means "keep the block, exactly as before".
//!
//! # The rule
//!
//! [`resolve`] returns the expanded text only when all of this holds.
//!
//! 1. The whole input is printable ASCII and holds none of: a backslash, a backtick, a
//!    `#`, a newline or any other control character, `=(` `<(` `>(`, a `$` that is not
//!    directly followed by a name (so no `${...}`, `$(...)`, `$1`, `$=X`), and a
//!    `$NAME` followed directly by `:`, `[`, `(` or `{`.
//! 2. The input is a flat list of statements joined by `;`. Each statement is either
//!    a plain `NAME=literal` assignment with nothing else on it, or a "use" statement:
//!    a command, pipeline, `&&`/`||` list or redirect built from words, plain quotes
//!    and plain `$NAME` references.
//! 3. Every simple command in a use statement is named by a literal on the
//!    [`SAFE_COMMANDS`] list, or by a bare `$NAME` (optionally followed by one literal
//!    word) that resolves to a SAFE command or to an absolute path.
//! 4. A literal value matches `[A-Za-z0-9_./:@%+=,-]+`, bare or inside plain single
//!    or double quotes, and does not start with `=`. The assigned name is not one of
//!    the special parameters of bash or zsh (see [`is_reserved`]).
//! 5. The expanded text parses to the same shape, has nothing left to substitute and
//!    passes rule 3 again.
//!
//! The caller then checks the expanded text against every rule, as if typed.
//!
//! # The literal class, one character at a time
//!
//! * `A-Za-z0-9`, `_`, `.`, `-`: ordinary word characters. A leading `-` is an option
//!   when typed too, so substitution does not change it.
//! * `/`: path separator. It is how an absolute path is recognised (rule 3).
//! * `:`: ordinary in a value. Directly after a `$NAME` it starts a zsh modifier, which
//!   rule 1 refuses.
//! * `@`, `%`, `+`, `,`: ordinary in a value. `,` needs a `{` to be a brace expansion
//!   and `{` is not in the class. `%` and `@` are not special inside a word.
//! * `=`: ordinary inside a word. At the start of a word zsh expands `=cmd`, but a value
//!   that came from a variable is not expanded, so a value may not start with `=`.
//!
//! Not in the class, and why: space (word splitting differs by shell and by `IFS`),
//! `$` and backtick (expansion), `\` (escape), quotes inside a value (the parser and
//! the shell could disagree on where the value ends), `* ? [ ] { }` and `~` (glob,
//! brace and tilde expansion happen on the typed word but not on a variable's value),
//! `; & | < > ( )` (they end or redirect the command), `#` (a comment), `!` (history
//! and negation), `^` (zsh glob), tab, newline and every non-ASCII character.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use tree_sitter::{Node, Parser};

/// The commands a statement may name, directly or through a variable. Each one is
/// either an external program or `echo`, so it cannot assign a shell variable or run a
/// later statement of the input in this shell. Reasons, one line each:
///
/// * `cat`: reads files to stdout; an external program.
/// * `echo`: prints its arguments; a builtin with no side effect on variables.
/// * `git`: an external program; the expanded text is checked by the git rules.
/// * `ls`: lists files; an external program.
/// * `python3`: an external program that runs the script the text names; the
///   expanded text is checked by the `python -c` rules like typed text.
///
/// `sh`, `bash`, `zsh`, `eval`, `xargs`, `find`, `env`, `sudo` and every precommand
/// modifier are out: they run another command by argument, which the rules match only
/// by its spelling.
pub const SAFE_COMMANDS: &[&str] = &["cat", "echo", "git", "ls", "python3"];

/// A reference to `$NAME` anywhere in the text, quotes included. Used to cross-check
/// the parsed references.
static REFERENCE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)").expect("valid regex"));

/// One replacement in the source text.
struct Edit {
    start: usize,
    end: usize,
    text: String,
}

/// What a walk found: the replacements, and the number of named children of every
/// command (equal before and after expansion).
struct Plan {
    edits: Vec<Edit>,
    shape: Vec<usize>,
}

/// Characters a literal may contain. See the module comment for each one.
fn is_value_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '_' | '.' | '/' | ':' | '@' | '%' | '+' | '=' | ',' | '-')
}

fn is_plain_value(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('=') && value.chars().all(is_value_char)
}

/// The special parameters of bash and zsh, the names they tie to `PATH`, `CDPATH` and
/// the like, and the names that change how `git` and `python3` start. A value assigned
/// to one of these does more than store a string.
fn is_reserved(name: &str) -> bool {
    const EXACT: &[&str] = &[
        // bash
        "_",
        "CDPATH",
        "DIRSTACK",
        "EUID",
        "FIGNORE",
        "FUNCNAME",
        "GLOBIGNORE",
        "GROUPS",
        "HOME",
        "IFS",
        "LINENO",
        "MAPFILE",
        "OLDPWD",
        "OPTARG",
        "OPTERR",
        "OPTIND",
        "PATH",
        "PIPESTATUS",
        "PPID",
        "PWD",
        "RANDOM",
        "REPLY",
        "SECONDS",
        "SHELL",
        "SHLVL",
        "SRANDOM",
        "UID",
        // zsh (print -l ${(ko)parameters[(R)*special*]}), lower-case tied names included
        "ARGC",
        "COLUMNS",
        "EGID",
        "FPATH",
        "FUNCNEST",
        "GID",
        "KEYBOARD_HACK",
        "LANG",
        "LINES",
        "MAILPATH",
        "MANPATH",
        "MODULE_PATH",
        "NULLCMD",
        "PROMPT",
        "PROMPT2",
        "PROMPT3",
        "PROMPT4",
        "PS1",
        "PS2",
        "PS3",
        "PS4",
        "PSVAR",
        "READNULLCMD",
        "SAVEHIST",
        "SPROMPT",
        "TERM",
        "TRY_BLOCK_ERROR",
        "TRY_BLOCK_INTERRUPT",
        "TTYIDLE",
        "USERNAME",
        "WORDCHARS",
        "aliases",
        "argv",
        "builtins",
        "cdpath",
        "commands",
        "dirstack",
        "errnos",
        "fignore",
        "fpath",
        "funcfiletrace",
        "funcsourcetrace",
        "funcstack",
        "functions",
        "functions_source",
        "functrace",
        "galiases",
        "histchars",
        "history",
        "historywords",
        "jobdirs",
        "jobstates",
        "jobtexts",
        "mailpath",
        "manpath",
        "module_path",
        "modules",
        "nameddirs",
        "options",
        "parameters",
        "patchars",
        "path",
        "pipestatus",
        "prompt",
        "psvar",
        "reswords",
        "saliases",
        "signals",
        "status",
        "sysparams",
        "termcap",
        "terminfo",
        "userdirs",
        "usergroups",
        "zsh_eval_context",
        // Read by the programs on the SAFE list or by the shell at startup.
        "EDITOR",
        "ENV",
        "MANPAGER",
        "PAGER",
        "VISUAL",
    ];
    EXACT.contains(&name)
        || [
            "BASH", "COMP", "DYLD_", "EPOCH", "GIT_", "HIST", "LC_", "LD_", "PYTHON", "READLINE",
            "ZSH", "dis_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Substitute the literals assigned earlier in `source` and return the expanded
/// text, or `None` when the command is not fully understood (keep the block).
///
/// `None` is also returned when nothing was substituted: a variable in command
/// position that no literal explains is exactly what the block is for.
pub fn resolve(source: &str) -> Option<String> {
    prefilter(source)?;
    let first = plan(source, false)?;
    if first.edits.is_empty() {
        return None;
    }
    let shape = first.shape.clone();
    let expanded = apply(source, first.edits);

    // The expanded text must be as clean as the input, have the same shape, hold
    // nothing left to substitute and still name every command by a plain word. A typed
    // absolute path is a plain word here: it is what `$S/x.sh` expanded to.
    prefilter(&expanded)?;
    let again = plan(&expanded, true)?;
    if !again.edits.is_empty() || again.shape != shape {
        return None;
    }
    Some(expanded)
}

/// Rule 1: the text-level refusals, before any parsing.
fn prefilter(source: &str) -> Option<()> {
    let bytes = source.as_bytes();
    // Printable ASCII only: no newline, tab, carriage return or other control
    // character, no non-ASCII character.
    if bytes.is_empty() || !bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return None;
    }
    if bytes.iter().any(|b| matches!(b, b'\\' | b'`' | b'#')) {
        return None;
    }
    if ["=(", "<(", ">("].iter().any(|p| source.contains(p)) {
        return None;
    }
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        // `$` must start a plain name: no `${`, `$(`, `$1`, `$@`, `$=X`, `$~X`, `$^X`,
        // and no `$` at the end.
        let start = i + 1;
        let first = *bytes.get(start)?;
        if !(first.is_ascii_alphabetic() || first == b'_') {
            return None;
        }
        let mut end = start + 1;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        // zsh modifiers and subscripts, glob qualifiers and brace lists.
        if let Some(next) = bytes.get(end) {
            if matches!(next, b':' | b'[' | b'(' | b'{') {
                return None;
            }
        }
        i = end;
    }
    Some(())
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

/// Rules 2 to 4: walk the top-level statements, tracking known literals and collecting
/// the replacements for every reference to one. `None` means refuse.
///
/// `typed_absolute` lets a command be named by a literal absolute path. It is `false`
/// for the input (a typed absolute path is not a SAFE literal) and `true` for the
/// expanded text, where `$S/x.sh` has become `/tmp/a/x.sh`.
fn plan(source: &str, typed_absolute: bool) -> Option<Plan> {
    let tree = parse(source)?;
    let root = tree.root_node();
    let mut env: HashMap<String, String> = HashMap::new();
    let mut edits = Vec::new();
    let mut shape = Vec::new();

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
            "variable_assignment" => {
                let (name, value) = literal_assignment(&stmt, source)?;
                env.insert(name, value);
            }
            _ => {
                let mut ctx = Use {
                    source,
                    env: &env,
                    edits: &mut edits,
                    shape: &mut shape,
                    substituted: 0,
                    typed_absolute,
                };
                walk_use(&stmt, &mut ctx)?;
                let substituted = ctx.substituted;
                // Every `$NAME` for a known name must have been parsed as an
                // expansion and replaced; otherwise the author meant something this
                // model does not see (single quotes).
                let text = stmt.utf8_text(source.as_bytes()).ok()?;
                let textual = REFERENCE
                    .captures_iter(text)
                    .filter(|c| env.contains_key(&c[1]))
                    .count();
                if textual != substituted {
                    return None;
                }
                if !holds_a_command(&stmt) {
                    return None;
                }
            }
        }
    }
    Some(Plan { edits, shape })
}

/// A use statement must hold at least one command (a bare redirect does not).
fn holds_a_command(node: &Node) -> bool {
    if node.kind() == "command" {
        return true;
    }
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .any(|child| holds_a_command(&child));
    found
}

/// `NAME=literal`: the name and value, or `None` if either is not plain. An empty
/// value, `+=`, `NAME[i]=` and arrays do not fit.
fn literal_assignment(node: &Node, source: &str) -> Option<(String, String)> {
    let mut cursor = node.walk();
    let kids: Vec<Node> = node.children(&mut cursor).collect();
    if kids.len() != 3 || kids[0].kind() != "variable_name" || kids[1].kind() != "=" {
        return None;
    }
    let name = kids[0].utf8_text(source.as_bytes()).ok()?.to_string();
    if is_reserved(&name) {
        return None;
    }
    let value = literal_value(&kids[2], source)?;
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
    is_plain_value(value).then(|| value.to_string())
}

/// State for walking one "use" statement.
struct Use<'a> {
    source: &'a str,
    env: &'a HashMap<String, String>,
    edits: &'a mut Vec<Edit>,
    shape: &'a mut Vec<usize>,
    substituted: usize,
    typed_absolute: bool,
}

/// The operator tokens a use statement may hold. Everything else (`&`, `;`, `;;`,
/// `<<`, `(`, `{`, `!`, ...) refuses.
const ALLOWED_TOKENS: &[&str] = &[
    "|", "|&", "&&", "||", "\"", "$", ">", ">>", "<", ">&", "<&", "&>", "&>>", ">|",
];

/// Walk a use statement. Only a small set of node kinds is understood; any other kind
/// (subshell, substitution, assignment, compound, function, heredoc, ...) refuses.
fn walk_use(node: &Node, ctx: &mut Use) -> Option<()> {
    if !node.is_named() {
        return ALLOWED_TOKENS.contains(&node.kind()).then_some(());
    }
    match node.kind() {
        "command" => {
            command_name(node, ctx)?;
            let mut cursor = node.walk();
            let mut named = 0;
            for child in node.children(&mut cursor) {
                if child.is_named() {
                    named += 1;
                }
                if child.kind() == "command_name" {
                    // Handled above, together with its reference.
                    continue;
                }
                walk_use(&child, ctx)?;
            }
            ctx.shape.push(named);
            Some(())
        }
        "pipeline"
        | "list"
        | "redirected_statement"
        | "file_redirect"
        | "concatenation"
        | "string"
        | "raw_string"
        | "string_content"
        | "word"
        | "number"
        | "file_descriptor" => walk_children(node, ctx),
        "simple_expansion" => reference(node, ctx),
        _ => None,
    }
}

fn walk_children(node: &Node, ctx: &mut Use) -> Option<()> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_use(&child, ctx)?;
    }
    Some(())
}

/// Rule 3: the command is named by a SAFE literal, or by a bare `$NAME` (and at most one
/// literal word after it) that resolves to a SAFE command or an absolute path. Records
/// the replacement for the reference.
fn command_name(command: &Node, ctx: &mut Use) -> Option<()> {
    let mut cursor = command.walk();
    let name_node = command
        .children(&mut cursor)
        .find(|c| c.kind() == "command_name")?;
    let mut c = name_node.walk();
    let mut parts: Vec<Node> = name_node.children(&mut c).collect();
    // `$S/x.sh` parses as one concatenation of a reference and a word.
    if let [only] = parts.as_slice() {
        if only.kind() == "concatenation" {
            let mut cc = only.walk();
            let inner: Vec<Node> = only.children(&mut cc).collect();
            parts = inner;
        }
    }
    let text = |n: &Node| n.utf8_text(ctx.source.as_bytes()).ok().map(str::to_string);

    match parts.as_slice() {
        // A literal name.
        [word] if word.kind() == "word" || word.kind() == "number" => {
            let name = text(word)?;
            let typed_abs =
                ctx.typed_absolute && name.starts_with('/') && name.chars().all(is_value_char);
            (SAFE_COMMANDS.contains(&name.as_str()) || typed_abs).then_some(())
        }
        // `$NAME` alone: a SAFE command or an absolute path.
        [expansion] if expansion.kind() == "simple_expansion" => {
            let value = known_value(expansion, ctx)?;
            if !(SAFE_COMMANDS.contains(&value.as_str()) || value.starts_with('/')) {
                return None;
            }
            substitute(expansion, value, ctx);
            Some(())
        }
        // `$NAME/x.sh`: an absolute path followed by one plain word.
        [expansion, suffix]
            if expansion.kind() == "simple_expansion"
                && (suffix.kind() == "word" || suffix.kind() == "number") =>
        {
            let value = known_value(expansion, ctx)?;
            let suffix_text = text(suffix)?;
            if !value.starts_with('/') || !suffix_text.chars().all(is_value_char) {
                return None;
            }
            substitute(expansion, value, ctx);
            Some(())
        }
        _ => None,
    }
}

/// The literal a `$NAME` node stands for, or `None` when the name is unknown or is not
/// a plain name. A known name in command position must resolve; an unknown one is the
/// hidden command the block is for.
fn known_value(node: &Node, ctx: &Use) -> Option<String> {
    let mut cursor = node.walk();
    let kids: Vec<Node> = node.children(&mut cursor).collect();
    if kids.len() != 2 || kids[0].kind() != "$" || kids[1].kind() != "variable_name" {
        return None;
    }
    let name = kids[1].utf8_text(ctx.source.as_bytes()).ok()?;
    ctx.env.get(name).cloned()
}

fn substitute(node: &Node, value: String, ctx: &mut Use) {
    ctx.edits.push(Edit {
        start: node.start_byte(),
        end: node.end_byte(),
        text: value,
    });
    ctx.substituted += 1;
}

/// Handle `$NAME` in an argument or a redirect. Known names are replaced by their
/// literal; unknown names are left as typed, exactly as the old path treated them.
fn reference(node: &Node, ctx: &mut Use) -> Option<()> {
    let mut cursor = node.walk();
    let kids: Vec<Node> = node.children(&mut cursor).collect();
    if kids.len() != 2 || kids[0].kind() != "$" || kids[1].kind() != "variable_name" {
        // `$1`, `$@`, `$?`: not a name this model tracks.
        return None;
    }
    let name = kids[1].utf8_text(ctx.source.as_bytes()).ok()?;
    if let Some(value) = ctx.env.get(name) {
        substitute(node, value.clone(), ctx);
    }
    Some(())
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
    fn substitutes_in_double_quotes_and_redirects() {
        assert_eq!(
            resolve("S=/tmp/a; $S/x.sh \"$S/in\" > $S/out").as_deref(),
            Some("S=/tmp/a; /tmp/a/x.sh \"/tmp/a/in\" > /tmp/a/out")
        );
    }

    #[test]
    fn safe_command_through_a_variable() {
        assert_eq!(resolve("X=echo; $X hi").as_deref(), Some("X=echo; echo hi"));
        assert_eq!(
            resolve("X=git; Y=status; $X $Y").as_deref(),
            Some("X=git; Y=status; git status")
        );
    }

    #[test]
    fn reassignment_uses_the_value_in_force() {
        assert_eq!(
            resolve("X=echo; $X a; X=ls; $X b").as_deref(),
            Some("X=echo; echo a; X=ls; ls b")
        );
    }

    #[test]
    fn nothing_to_substitute_is_none() {
        assert_eq!(resolve("echo hi"), None);
        assert_eq!(resolve("$X hi"), None);
        assert_eq!(resolve("X=echo; ls"), None);
        assert_eq!(resolve(""), None);
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
            "X=rm; $X -rf /",
            "X=echo; $X\"\" hi",
            "IFS=/; X=a/b; $X",
            "X=echo; read X; $X",
            "X=echo; f() { :; }; $X",
            "K=export; X=echo; $K X=rm; $X -rf /",
            "X=echo; noglob export X=rm; $X -rf /",
            "X=RM; $X:l -rf /",
            "X=/; Y=rm; $Y -rf $X[1]",
            "path=/tmp/e; X=ls; $X",
            "ZSH_NAME=a; X=ls; $X",
            "X=echo\n$X hi",
            "X=echo; $X a\\ b",
            "P=\"python3 -I /p/c.py\"; $P",
            "X=r; Y=m; $X$Y -rf /",
        ] {
            assert_eq!(resolve(cmd), None, "should refuse {cmd:?}");
        }
    }

    #[test]
    fn value_characters() {
        for ok in ["a", "/a/b-c_d.e", "a:b@c%d+e,f", "a=b", "A1"] {
            assert!(is_plain_value(ok), "{ok:?}");
        }
        for bad in [
            "$", "`", "\\", "'", "\"", "*", "?", "[", "]", "{", "}", "(", ")", "<", ">", "|", "&",
            ";", "#", "!", "\n", "\t", "^", "~", " ", "", "=ls", "\u{e9}",
        ] {
            assert!(!is_plain_value(bad), "{bad:?}");
        }
    }

    #[test]
    fn prefilter_refusals() {
        for bad in [
            "echo a\\b",
            "echo `id`",
            "echo # c",
            "echo a\nb",
            "echo a\tb",
            "echo \u{e9}",
            "echo ${X}",
            "echo $(id)",
            "echo $1",
            "echo $",
            "echo $=X",
            "echo $X:l",
            "echo $X[1]",
            "echo $X(N)",
            "echo $X{a,b}",
            "echo <(id)",
            "echo =(id)",
        ] {
            assert_eq!(prefilter(bad), None, "{bad:?}");
        }
        for ok in [
            "echo $X",
            "echo \"$X\"",
            "echo $X.txt $X/y $X-z",
            "echo '$X'",
        ] {
            assert_eq!(prefilter(ok), Some(()), "{ok:?}");
        }
    }

    #[test]
    fn reserved_names() {
        for name in [
            "IFS",
            "PATH",
            "path",
            "cdpath",
            "fpath",
            "NULLCMD",
            "READNULLCMD",
            "ZSH_NAME",
            "ZSHX",
            "BASH_ENV",
            "HOME",
            "GIT_PAGER",
            "PYTHONSTARTUP",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "histchars",
            "argv",
            "options",
            "LC_ALL",
            "PAGER",
        ] {
            assert!(is_reserved(name), "{name}");
        }
        for name in ["X", "S", "P", "B", "M", "K", "My_Var2", "scratch", "tool"] {
            assert!(!is_reserved(name), "{name}");
        }
    }

    /// Every special parameter the installed zsh reports must be reserved. Skipped when
    /// there is no zsh on the machine.
    #[test]
    fn every_zsh_special_parameter_is_reserved() {
        let Ok(out) = std::process::Command::new("zsh")
            .args([
                "-fc",
                "zmodload zsh/parameter 2>/dev/null; print -l ${(ko)parameters[(R)*special*]}",
            ])
            .output()
        else {
            return;
        };
        if !out.status.success() {
            return;
        }
        let listing = String::from_utf8_lossy(&out.stdout);
        let names: Vec<&str> = listing
            .lines()
            .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
            .filter(|n| !n.chars().next().unwrap().is_ascii_digit())
            .collect();
        assert!(!names.is_empty(), "zsh listed no special parameters");
        for name in names {
            assert!(
                is_reserved(name),
                "zsh special parameter {name} not reserved"
            );
        }
    }

    #[test]
    fn safe_list_is_the_short_literal_list() {
        assert_eq!(SAFE_COMMANDS, &["cat", "echo", "git", "ls", "python3"]);
    }
}
