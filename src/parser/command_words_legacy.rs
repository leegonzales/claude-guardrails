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
//! The scan is deliberately simple. Where it cannot tell a position from an argument
//! it takes the position, so an input can be denied that the shell would accept. It
//! never skips a word that could be a command name.

use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Clone, Copy, PartialEq)]
enum Quote {
    None,
    Single,
    /// `$'...'`: a backslash escapes the next character, including `'`.
    Ansi,
    Double,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// `( ... )` at a word start: a subshell, or a case pattern.
    Group,
    /// `$( ... )`, `<( ... )`, `>( ... )`.
    Subst,
    /// A pair of backticks.
    Backtick,
    /// `x=( ... )`, `*( ... )`: the contents are not commands.
    WordParen,
    /// `${ ... }`: the contents are part of one word.
    Brace,
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
}

struct Frame {
    kind: Kind,
    /// The word that was being read when the frame opened (`Subst`, `Backtick`).
    saved: Scan,
    saved_quote: Quote,
    /// `WordParen`: `cmd_pos` once the frame closes.
    after: bool,
}

static ASSIGNMENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=").unwrap());
static REDIRECT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:[0-9]+|&)?(?:>>?|<<<?|>&|<&|>\||&>>?|<>)").unwrap());
static REDIRECT_ONLY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:[0-9]+|&)?(?:>>?|<<<?|>&|<&|>\||&>>?|<>)$").unwrap());

fn is_keyword(word: &str) -> bool {
    matches!(
        word,
        "!" | "{" | "then" | "do" | "else" | "elif" | "if" | "while" | "until"
    )
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

    /// End the word. True when it is a command word that holds `$` or a backtick.
    fn finish(&mut self, suppressed: bool) -> bool {
        if self.word.is_empty() {
            return false;
        }
        let word = std::mem::take(&mut self.word);
        let dynamic = std::mem::take(&mut self.dynamic);
        if suppressed || !self.at_cmd {
            return false;
        }
        if self.redirect {
            self.redirect = false;
            return false;
        }
        if is_keyword(&word) || ASSIGNMENT.is_match(&word) {
            return false;
        }
        if REDIRECT.is_match(&word) {
            self.redirect = REDIRECT_ONLY.is_match(&word);
            return false;
        }
        self.cmd_pos = false;
        dynamic
    }

    /// End the word and start a new command.
    fn boundary(&mut self, suppressed: bool) -> bool {
        let found = self.finish(suppressed);
        self.cmd_pos = true;
        self.redirect = false;
        found
    }
}

/// The index just after the `))` that closes an arithmetic expression, given the index
/// just after its opening `((`.
fn skip_arithmetic(chars: &[char], mut i: usize) -> usize {
    let mut depth = 2;
    while i < chars.len() {
        match chars[i] {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    i
}

/// True when a command word, at any command position, holds `$` or a backtick.
pub fn has_dynamic_command_word(command: &str) -> bool {
    let chars: Vec<char> = command.chars().collect();
    let mut s = Scan::new();
    let mut quote = Quote::None;
    let mut stack: Vec<Frame> = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        let next = chars.get(i + 1).copied();
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
            Quote::Double => {
                match ch {
                    '\\' => {
                        s.push(ch);
                        if let Some(n) = next {
                            s.push(n);
                            i += 1;
                        }
                    }
                    '"' => {
                        s.push(ch);
                        quote = Quote::None;
                    }
                    '$' if next == Some('(') && chars.get(i + 2) != Some(&'(') => {
                        s.push('$');
                        s.push('(');
                        s.dynamic = true;
                        stack.push(open(Kind::Subst, &s, quote));
                        s = inner();
                        quote = Quote::None;
                        i += 1;
                    }
                    '`' if stack.last().is_some_and(|f| f.kind == Kind::Backtick) => {
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
            Quote::None => {}
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
                    // Arithmetic: not a command.
                    s.push('$');
                    s.dynamic = true;
                    let end = skip_arithmetic(&chars, i + 3);
                    for c in &chars[i + 1..end] {
                        s.push(*c);
                    }
                    i = end - 1;
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
            ' ' | '\t' | '\r' => {
                if s.finish(suppressed) {
                    return true;
                }
            }
            '\n' | ';' | '|' => {
                if s.word.ends_with('>') && ch == '|' {
                    s.push(ch);
                } else {
                    let suppressed = leave_word_paren(&mut stack, ch != '\n');
                    if s.boundary(suppressed) {
                        return true;
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
                    if s.boundary(suppressed) {
                        return true;
                    }
                }
            }
            '(' => {
                if s.word.is_empty() {
                    if next == Some('(') {
                        // An arithmetic command.
                        let end = skip_arithmetic(&chars, i + 2);
                        s.cmd_pos = false;
                        i = end - 1;
                    } else {
                        let mut frame = open(Kind::Group, &s, quote);
                        frame.after = true;
                        stack.push(frame);
                        s.cmd_pos = true;
                        s.redirect = false;
                    }
                } else if s.word == "<" || s.word == ">" {
                    s.push(ch);
                    stack.push(open(Kind::Subst, &s, quote));
                    s = inner();
                } else if next == Some(')') {
                    // A function definition, `name()`: the body is a command.
                    if s.finish(suppressed) {
                        return true;
                    }
                    s.cmd_pos = true;
                    i += 1;
                } else {
                    // `x=( a b )`, `*(.)`: the contents are not commands.
                    if s.finish(suppressed) {
                        return true;
                    }
                    let mut frame = open(Kind::WordParen, &s, quote);
                    frame.after = s.cmd_pos;
                    stack.push(frame);
                    s.cmd_pos = false;
                }
            }
            ')' => {
                if s.finish(suppressed) {
                    return true;
                }
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
    if s.finish(in_word_paren(&stack)) {
        return true;
    }
    while let Some(frame) = stack.pop() {
        if matches!(frame.kind, Kind::Subst | Kind::Backtick) {
            s = frame.saved;
            if s.finish(in_word_paren(&stack)) {
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
            "2>/dev/null \"$X\"",
            "case x in x) $X ;; esac",
            "f() $X",
            "echo $($X hi)",
            "echo \"$($X hi)\"",
            "echo `$X hi`",
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
            "A=1 ls $X",
            "x=$(date); ls",
            "echo $(( $X + 1 ))",
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
}
