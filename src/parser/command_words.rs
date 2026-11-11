//! A scan for a variable or substitution used as a command word.
//!
//! This runs when the parser cannot read the input, so it cannot rely on a syntax
//! tree. It reads the text once, keeps track of quotes and nesting, and decides for
//! every word whether the word is at a command position. A word at a command position
//! that holds `$` or a backtick anywhere in it, in any quoting, is a dynamic command
//! word, the same verdict the parsed path gives.
//!
//! Command positions are: the start of the input, after `;`, `&`, `|`, a newline,
//! `(`, `)` (a case arm or a short function body), the start of `$( )` and backtick
//! substitutions, after a keyword (`then`, `do`, `else`, `elif`, `if`, `while`,
//! `until`, `{`, `!`), and after leading assignments and redirections.
//!
//! The scan models only that. Here-document bodies are modelled too: a quoted body is
//! data and is skipped, an unquoted body is data except for `$( )` and backticks.
//!
//! For any other syntax the scan does not guess. It enters the LOST state: from that
//! point to the end of the input, every `$` and every backtick is judged as a possible
//! command word. The constructs that do this are `[[`, `case`, `function`, `select`
//! and `coproc` as a command word, a lone `{` after other words, `((` and `$((`,
//! `<(`, `>(` and `=(`, and a redirection with a named descriptor (`{fd}>f`).

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::VecDeque;

#[derive(Clone, Copy, PartialEq)]
enum Quote {
    None,
    Single,
    /// `$'...'`: a backslash escapes the next character, including `'`.
    Ansi,
    Double,
    /// The body of an unquoted here-document: like double quotes, but `"` is data.
    Here,
    /// The body of a here-document with a quoted delimiter: data.
    HereLit,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// `( ... )` at a word start: a subshell.
    Group,
    /// `$( ... )`.
    Subst,
    /// A pair of backticks.
    Backtick,
    /// `x=( ... )`, `*( ... )`: the contents are not commands.
    WordParen,
    /// `${ ... }`: the contents are part of one word.
    Brace,
}

#[derive(Clone, Copy, PartialEq)]
enum Outcome {
    Ok,
    /// A command word that holds `$` or a backtick.
    Dynamic,
    /// A construct the scan does not model.
    Lost,
}

/// A here-document whose body starts after the next newline.
struct Here {
    delim: String,
    /// `<<-`: leading tabs are removed from the delimiter line.
    strip: bool,
    /// The delimiter was quoted, so the body is data.
    quoted: bool,
}

impl Here {
    fn new(raw: &str, strip: bool) -> Self {
        let quoted = raw.contains(['\'', '"', '\\']);
        let delim = raw
            .chars()
            .filter(|c| !matches!(c, '\'' | '"' | '\\'))
            .collect();
        Here {
            delim,
            strip,
            quoted,
        }
    }
}

#[derive(Clone, Default)]
struct Scan {
    /// The next word starts at a command position.
    cmd_pos: bool,
    /// The raw text of the word being read.
    word: String,
    /// The word holds `$` or a backtick.
    dynamic: bool,
    /// The word started at a command position.
    at_cmd: bool,
    /// The previous word was a bare redirection operator; this word is its target.
    redirect: bool,
    /// The previous word was a bare `<<` or `<<-`; this word is the delimiter.
    here_op: Option<bool>,
}

struct Frame {
    kind: Kind,
    /// The word that was being read when the frame opened (`Subst`, `Backtick`).
    saved: Scan,
    saved_quote: Quote,
    /// `WordParen`: `cmd_pos` once the frame closes.
    after: bool,
}

const OPERATORS: &str = r"(?:>>?|<<<?|>&|<&|>\||&>>?|<>|<)";

static ASSIGNMENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=").unwrap());
static REDIRECT: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!(r"^(?:[0-9]+|&)?{OPERATORS}")).unwrap());
static REDIRECT_ONLY: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!(r"^(?:[0-9]+|&)?{OPERATORS}$")).unwrap());
static FD_REDIRECT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\{[A-Za-z_][A-Za-z0-9_]*\}[<>]").unwrap());
static FD_NAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$").unwrap());
static HEREDOC: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9]*<<(-?)(.*)$").unwrap());

fn is_keyword(word: &str) -> bool {
    matches!(
        word,
        "!" | "{" | "then" | "do" | "else" | "elif" | "if" | "while" | "until"
    )
}

/// Command words whose syntax the scan does not model.
fn is_unmodelled(word: &str) -> bool {
    matches!(word, "[[" | "case" | "function" | "select" | "coproc")
}

/// A word made of descriptor digits and redirection operator characters only.
fn operator_only(word: &str) -> bool {
    word.chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '<' | '>' | '&'))
}

impl Scan {
    fn new() -> Self {
        Scan {
            cmd_pos: true,
            ..Scan::default()
        }
    }

    fn push(&mut self, ch: char) {
        if self.word.is_empty() {
            self.at_cmd = self.cmd_pos;
        }
        self.word.push(ch);
    }

    /// Record the here-document that this word starts, or whose delimiter it is.
    fn note_here(&mut self, word: &str, found: &mut Vec<Here>) {
        if let Some(strip) = self.here_op.take() {
            found.push(Here::new(word, strip));
            return;
        }
        if let Some(caps) = HEREDOC.captures(word) {
            let rest = &caps[2];
            if rest.starts_with('<') {
                return; // a here-string, `<<<`
            }
            let strip = &caps[1] == "-";
            if rest.is_empty() {
                self.here_op = Some(strip);
            } else {
                found.push(Here::new(rest, strip));
            }
        }
    }

    /// End the word and judge it.
    fn finish(&mut self, suppressed: bool, found: &mut Vec<Here>) -> Outcome {
        if self.word.is_empty() {
            return Outcome::Ok;
        }
        let word = std::mem::take(&mut self.word);
        let dynamic = std::mem::take(&mut self.dynamic);
        self.note_here(&word, found);
        if FD_REDIRECT.is_match(&word) {
            return Outcome::Lost;
        }
        if suppressed {
            return Outcome::Ok;
        }
        if !self.at_cmd {
            // A lone `{` after other words is a short body (`if [[ ]] { ... }`).
            return if word == "{" {
                Outcome::Lost
            } else {
                Outcome::Ok
            };
        }
        if self.redirect {
            self.redirect = false;
            return Outcome::Ok;
        }
        if is_keyword(&word) || ASSIGNMENT.is_match(&word) {
            return Outcome::Ok;
        }
        if REDIRECT.is_match(&word) {
            self.redirect = REDIRECT_ONLY.is_match(&word);
            return Outcome::Ok;
        }
        self.cmd_pos = false;
        if is_unmodelled(&word) {
            Outcome::Lost
        } else if dynamic {
            Outcome::Dynamic
        } else {
            Outcome::Ok
        }
    }

    /// End the word and start a new command.
    fn boundary(&mut self, suppressed: bool, found: &mut Vec<Here>) -> Outcome {
        let outcome = self.finish(suppressed, found);
        self.cmd_pos = true;
        self.redirect = false;
        self.here_op = None;
        outcome
    }
}

/// The index after the delimiter line that starts at `pos`, if the line is the
/// delimiter of the here-document.
fn delimiter_line_end(chars: &[char], pos: usize, here: &Here) -> Option<usize> {
    let mut end = pos;
    while end < chars.len() && chars[end] != '\n' {
        end += 1;
    }
    let line: String = chars[pos..end].iter().collect();
    let line = if here.strip {
        line.trim_start_matches('\t')
    } else {
        line.as_str()
    };
    (line == here.delim).then(|| (end + 1).min(chars.len()))
}

fn body_quote(here: &Here) -> Quote {
    if here.quoted {
        Quote::HereLit
    } else {
        Quote::Here
    }
}

/// True when a command word, at any command position, holds `$` or a backtick, or when
/// the input uses syntax the scan does not model and holds `$` or a backtick after it.
pub fn has_dynamic_command_word(command: &str) -> bool {
    let chars: Vec<char> = command.chars().collect();
    let mut s = Scan::new();
    let mut quote = Quote::None;
    let mut stack: Vec<Frame> = Vec::new();
    let mut i = 0;

    // Here-documents seen on this line, and the one whose body is being read.
    let mut found: Vec<Here> = Vec::new();
    let mut pending: VecDeque<Here> = VecDeque::new();
    let mut here: Option<Here> = None;
    let mut at_line_start = false;
    // The scan met syntax it does not model.
    let mut lost = false;

    macro_rules! outcome {
        ($o:expr) => {{
            let o = $o;
            pending.extend(found.drain(..));
            match o {
                Outcome::Dynamic => return true,
                Outcome::Lost => lost = true,
                Outcome::Ok => {}
            }
        }};
    }

    while i < chars.len() {
        let ch = chars[i];
        let next = chars.get(i + 1).copied();

        if lost {
            if ch == '$' || ch == '`' {
                return true;
            }
            i += 1;
            continue;
        }

        // A here-document body: look for the delimiter at the start of each line.
        if matches!(quote, Quote::Here | Quote::HereLit) {
            if at_line_start {
                at_line_start = false;
                if let Some(h) = &here {
                    if let Some(end) = delimiter_line_end(&chars, i, h) {
                        i = end;
                        here = pending.pop_front();
                        s.word.clear();
                        s.dynamic = false;
                        s.cmd_pos = true;
                        match &here {
                            Some(h) => {
                                quote = body_quote(h);
                                at_line_start = true;
                            }
                            None => quote = Quote::None,
                        }
                        continue;
                    }
                }
            }
            if quote == Quote::HereLit {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                i += 1;
                at_line_start = true;
                continue;
            }
        }

        let in_brace = stack.last().is_some_and(|f| f.kind == Kind::Brace);
        let suppressed = in_word_paren(&stack);

        match quote {
            Quote::Single | Quote::Ansi => {
                s.push(ch);
                if ch == '$' || ch == '`' {
                    s.dynamic = true;
                }
                if ch == '\\' && quote == Quote::Ansi {
                    if let Some(n) = next {
                        s.push(n);
                        i += 1;
                    }
                } else if ch == '\'' {
                    quote = Quote::None;
                }
                i += 1;
                continue;
            }
            Quote::Double | Quote::Here => {
                match ch {
                    '\\' => {
                        s.push(ch);
                        if let Some(n) = next {
                            s.push(n);
                            i += 1;
                        }
                    }
                    '"' if quote == Quote::Double => {
                        s.push(ch);
                        quote = Quote::None;
                    }
                    '\n' if quote == Quote::Here => {
                        s.push(ch);
                        at_line_start = true;
                    }
                    '$' if next == Some('(') && chars.get(i + 2) == Some(&'(') => {
                        // Arithmetic: not modelled.
                        s.push('$');
                        s.dynamic = true;
                        i += 2;
                        lost = true;
                    }
                    '$' if next == Some('(') => {
                        s.push('$');
                        s.push('(');
                        s.dynamic = true;
                        stack.push(open(Kind::Subst, &s, quote));
                        s = inner();
                        quote = Quote::None;
                        i += 1;
                    }
                    '`' if stack.last().is_some_and(|f| f.kind == Kind::Backtick) => {
                        outcome!(s.finish(false, &mut found));
                        let frame = stack.pop().unwrap();
                        s = frame.saved;
                        quote = frame.saved_quote;
                        s.push('`');
                    }
                    '`' => {
                        s.push(ch);
                        s.dynamic = true;
                        stack.push(open(Kind::Backtick, &s, quote));
                        s = inner();
                        quote = Quote::None;
                    }
                    '$' => {
                        s.push(ch);
                        s.dynamic = true;
                    }
                    _ => s.push(ch),
                }
                i += 1;
                continue;
            }
            Quote::None | Quote::HereLit => {}
        }

        match ch {
            '\\' => match next {
                Some('\n') => i += 1,
                Some(n) => {
                    s.push(ch);
                    s.push(n);
                    i += 1;
                }
                None => s.push(ch),
            },
            '\'' => {
                s.push(ch);
                quote = Quote::Single;
            }
            '"' => {
                s.push(ch);
                quote = Quote::Double;
            }
            '$' => match next {
                Some('(') if chars.get(i + 2) == Some(&'(') => {
                    // Arithmetic: not modelled.
                    s.push('$');
                    s.dynamic = true;
                    i += 2;
                    lost = true;
                }
                Some('(') => {
                    s.push('$');
                    s.push('(');
                    s.dynamic = true;
                    stack.push(open(Kind::Subst, &s, quote));
                    s = inner();
                    i += 1;
                }
                Some('{') => {
                    s.push('$');
                    s.push('{');
                    s.dynamic = true;
                    stack.push(open(Kind::Brace, &s, quote));
                    i += 1;
                }
                Some('\'') => {
                    s.push('$');
                    s.push('\'');
                    quote = Quote::Ansi;
                    i += 1;
                }
                Some('"') => {
                    s.push('$');
                    s.push('"');
                    quote = Quote::Double;
                    i += 1;
                }
                _ => {
                    s.push(ch);
                    s.dynamic = true;
                }
            },
            '`' if stack.last().is_some_and(|f| f.kind == Kind::Backtick) => {
                outcome!(s.finish(false, &mut found));
                let frame = stack.pop().unwrap();
                s = frame.saved;
                quote = frame.saved_quote;
                s.push('`');
            }
            '`' => {
                s.push(ch);
                s.dynamic = true;
                stack.push(open(Kind::Backtick, &s, quote));
                s = inner();
            }
            '}' if in_brace => {
                stack.pop();
                s.push(ch);
            }
            _ if in_brace => s.push(ch),
            '#' if s.word.is_empty() => {
                while i + 1 < chars.len() && chars[i + 1] != '\n' {
                    i += 1;
                }
            }
            ' ' | '\t' | '\r' => outcome!(s.finish(suppressed, &mut found)),
            '\n' | ';' | '|' => {
                if s.word.ends_with('>') && ch == '|' {
                    s.push(ch);
                } else {
                    let suppressed = leave_word_paren(&mut stack, ch != '\n');
                    outcome!(s.boundary(suppressed, &mut found));
                    if ch == '\n' && here.is_none() {
                        if let Some(h) = pending.pop_front() {
                            quote = body_quote(&h);
                            here = Some(h);
                            at_line_start = true;
                        }
                    }
                }
            }
            '&' => {
                let redirect_part = s.word.ends_with(['>', '<'])
                    || (s.word.is_empty() && matches!(next, Some('>')));
                if redirect_part {
                    s.push(ch);
                } else {
                    let suppressed = leave_word_paren(&mut stack, true);
                    outcome!(s.boundary(suppressed, &mut found));
                }
            }
            '<' | '>' => {
                if next == Some('(') {
                    // Process substitution: not modelled.
                    i += 1;
                    lost = true;
                } else {
                    let prefix = operator_only(&s.word) || FD_NAME.is_match(&s.word);
                    if !s.word.is_empty() && !prefix {
                        outcome!(s.finish(suppressed, &mut found));
                    }
                    s.push(ch);
                }
            }
            '(' => {
                if s.word.is_empty() {
                    if next == Some('(') {
                        // An arithmetic command: not modelled.
                        i += 1;
                        lost = true;
                    } else {
                        let mut frame = open(Kind::Group, &s, quote);
                        frame.after = true;
                        stack.push(frame);
                        s.cmd_pos = true;
                        s.redirect = false;
                    }
                } else if s.word == "=" {
                    // zsh `=( ... )`: not modelled.
                    lost = true;
                } else if next == Some(')') {
                    // A function definition, `name()`: the body is a command.
                    outcome!(s.finish(suppressed, &mut found));
                    s.cmd_pos = true;
                    i += 1;
                } else {
                    // `x=( a b )`, `*(.)`: the contents are not commands.
                    outcome!(s.finish(suppressed, &mut found));
                    let mut frame = open(Kind::WordParen, &s, quote);
                    frame.after = s.cmd_pos;
                    stack.push(frame);
                    s.cmd_pos = false;
                }
            }
            ')' => {
                outcome!(s.finish(suppressed, &mut found));
                match stack.last().map(|f| f.kind) {
                    Some(Kind::Subst) => {
                        let frame = stack.pop().unwrap();
                        s = frame.saved;
                        quote = frame.saved_quote;
                        s.push(')');
                    }
                    Some(Kind::WordParen) => {
                        let frame = stack.pop().unwrap();
                        s.cmd_pos = frame.after;
                    }
                    Some(Kind::Group) => {
                        stack.pop();
                        s.cmd_pos = true;
                        s.redirect = false;
                    }
                    _ => {
                        s.cmd_pos = true;
                        s.redirect = false;
                    }
                }
            }
            _ => s.push(ch),
        }
        i += 1;
    }

    // The input ended inside a quote, a substitution or a group. Check the words that
    // are still open, innermost first.
    if quote == Quote::Here {
        // The rest is the body of a here-document, which is data.
        s.word.clear();
        s.dynamic = false;
    }
    if s.finish(in_word_paren(&stack), &mut found) == Outcome::Dynamic {
        return true;
    }
    while let Some(frame) = stack.pop() {
        if matches!(frame.kind, Kind::Subst | Kind::Backtick) {
            s = frame.saved;
            if s.finish(in_word_paren(&stack), &mut found) == Outcome::Dynamic {
                return true;
            }
        }
    }
    false
}

/// The words inside `x=( ... )` and `*( ... )` are not commands.
fn in_word_paren(stack: &[Frame]) -> bool {
    stack.last().is_some_and(|f| f.kind == Kind::WordParen)
}

/// `;`, `|` and `&` cannot appear inside `x=( ... )`, so a paren that holds one was not
/// an array: leave it. Returns whether the scan is still inside an array.
fn leave_word_paren(stack: &mut Vec<Frame>, operator: bool) -> bool {
    if operator && in_word_paren(stack) {
        stack.pop();
    }
    in_word_paren(stack)
}

/// A frame that saves the word being read, for a substitution that starts inside it.
fn open(kind: Kind, s: &Scan, quote: Quote) -> Frame {
    Frame {
        kind,
        saved: s.clone(),
        saved_quote: quote,
        after: false,
    }
}

/// The state at the start of a substitution: a command position, no word.
fn inner() -> Scan {
    Scan::new()
}

#[cfg(test)]
mod tests {
    use super::has_dynamic_command_word as dynamic;

    #[test]
    fn a_word_that_holds_a_dollar_or_backtick_at_a_command_position_is_dynamic() {
        for text in [
            "$X hi",
            "\"$X\" hi",
            "'$X' hi",
            "${X} hi",
            "\"${X:-a b}\" hi",
            "\"\"$X hi",
            "x\"$X\" hi",
            "'a$X' hi",
            "$(echo ls) hi",
            "`echo ls` hi",
            "ls; $X",
            "ls && ! $X",
            "A=1 B=2 >f $X",
            "> f $X",
            "<f $X",
            "< f \"$X\"",
            "2>/dev/null \"$X\"",
            "case x in x) $X ;; esac",
            "f() $X",
            "echo $($X hi)",
            "echo \"$($X hi)\"",
            "echo `$X hi`",
            "echo `$X`",
            "echo `ls; \"$X\"`",
            "if $X; then ls; fi",
            "${X:-a hi",
        ] {
            assert!(dynamic(text), "{text}");
        }
    }

    #[test]
    fn static_words_and_arguments_are_not_dynamic() {
        for text in [
            "ls -la",
            "\"ls\" '; $X'",
            "\"ls\" 'if $X'",
            "ls # ; $X",
            "echo $X \"$X\" '$X' ${X}",
            "echo hi > f $X",
            "echo hi 2>&1 $X",
            "echo hi <f $X",
            "\"ls\">$X",
            "A=1 ls $X",
            "x=$(date); ls",
            "echo $((1 + 2))",
            "echo $(date) $X",
            "ls *(.) $X",
            "x=($X $(date)) ls",
            "echo ${X:-a;b} ls",
            "'ls'\"\" -la",
        ] {
            assert!(!dynamic(text), "{text}");
        }
    }

    #[test]
    fn an_unterminated_quote_or_group_is_scanned_to_the_end() {
        assert!(dynamic("ls; $X \"unterminated"));
        assert!(dynamic("echo $(ls; $X"));
        assert!(!dynamic("echo \"a; $X"));
    }

    #[test]
    fn syntax_the_scan_does_not_model_judges_every_later_dollar() {
        for text in [
            "[[ a == a && \"$X\" ]]",
            "case x in (\"$X\") ls ;; esac",
            "function f { $X; }",
            "echo $(( $X + 1 ))",
            "echo <(\"$X\")",
            "(( $X ))",
            "{fd}>f ls $X",
            "if true { ls $X }",
            "echo =($X)",
        ] {
            assert!(dynamic(text), "{text}");
        }
        for text in [
            "echo $X; [[ a ]]",
            "[[ a == b ]]; ls",
            "echo $((1 + 2))",
            "echo <(date)",
            "case x in x) ls ;; esac",
        ] {
            assert!(!dynamic(text), "{text}");
        }
    }

    #[test]
    fn here_document_bodies_are_data() {
        for text in [
            "cat <<'EOF'\n$X hi\nEOF",
            "cat <<EOF\n$X hi\nEOF",
            "cat <<-EOF\n\t$X\n\tEOF",
            "cat <<A <<B\n$X\nA\n$X\nB",
            "cat <<EOF\n$(date)\nEOF",
            "cat <<EOF\nx '\nEOF\nls",
            "cat <<'EOF'\nx \"\nEOF\nls",
            "cat <<EOF\n$X",
        ] {
            assert!(!dynamic(text), "{text}");
        }
        for text in [
            "cat <<EOF\nx '\nEOF\n$X hi",
            "cat <<'EOF'\nx \"\nEOF\n\"$X\"",
            "cat <<EOF\n$($X hi)\nEOF",
            "cat <<EOF\n`$X`\nEOF",
            "cat <<A <<B\nx '\nA\ny\nB\n$X",
            "cat <<<'x' ; $X",
        ] {
            assert!(dynamic(text), "{text}");
        }
    }
}
