// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A small C lexer for the legacy sources and headers.
//!
//! The lexer does not preprocess. It removes comments and directives and
//! records, for each token, the line, the brace depth and the conditional
//! compilation context. Code in an `#if 0` branch gives no tokens.
//!
//! Conditional branches can open and close different numbers of braces.
//! The lexer keeps the brace depth of the first branch. Thus a function
//! header in an `#ifdef` does not change the depth of the code after it.

use std::collections::HashMap;

/// The class of a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// An identifier or keyword.
    Ident,
    /// A string literal. The text is the source text between the quotes.
    Str,
    /// A character literal.
    Char,
    /// A number.
    Num,
    /// One punctuation character.
    Punct,
}

/// One token.
#[derive(Clone, Debug)]
pub(crate) struct Token {
    /// The class.
    pub(crate) kind: Kind,
    /// The text. Escape sequences in literals stay as they are in the source.
    pub(crate) text: String,
    /// The 1-based source line.
    pub(crate) line: u32,
    /// The brace depth. A brace pair has the same depth on both tokens.
    pub(crate) depth: u32,
    /// The index of the condition in [`Lexed::conds`].
    pub(crate) cond: usize,
}

impl Token {
    /// Returns true when the token is the punctuation character `c`.
    pub(crate) fn is_punct(&self, c: char) -> bool {
        self.kind == Kind::Punct && self.text.len() == 1 && self.text.starts_with(c)
    }

    /// Returns true when the token is the identifier `s`.
    pub(crate) fn is_ident(&self, s: &str) -> bool {
        self.kind == Kind::Ident && self.text == s
    }
}

/// The tokens of one file.
#[derive(Debug)]
pub(crate) struct Lexed {
    /// The tokens in source order.
    pub(crate) tokens: Vec<Token>,
    /// The distinct conditions. Index 0 is the empty condition.
    pub(crate) conds: Vec<String>,
}

impl Lexed {
    /// Returns the condition text of a token. It is empty for code that
    /// is always compiled.
    pub(crate) fn cond_of(&self, t: &Token) -> &str {
        self.conds.get(t.cond).map_or("", String::as_str)
    }
}

/// One open `#if` group.
struct Frame {
    /// The expressions of the `#if` and `#elif` lines so far.
    exprs: Vec<String>,
    /// True after `#else`.
    in_else: bool,
    /// True for an include guard. A guard adds no condition.
    guard: bool,
    /// The brace depth at the `#if` line.
    depth_at_if: u32,
    /// The brace depth at the end of the first branch.
    first_end: Option<u32>,
}

impl Frame {
    /// Returns true when the active branch is never compiled.
    fn dead(&self) -> bool {
        if self.in_else {
            self.exprs.iter().any(|e| e == "1")
        } else {
            self.exprs.last().is_some_and(|e| e == "0")
        }
    }

    /// Adds the condition parts of the active branch to `out`.
    fn parts(&self, out: &mut Vec<String>) {
        if self.guard {
            return;
        }
        let (prior, own) = if self.in_else {
            (self.exprs.as_slice(), None)
        } else {
            match self.exprs.split_last() {
                Some((last, prior)) => (prior, Some(last)),
                None => (self.exprs.as_slice(), None),
            }
        };
        for e in prior {
            if e != "0" {
                out.push(negate(e));
            }
        }
        if let Some(e) = own {
            out.push(e.clone());
        }
    }
}

/// Returns the negation of a condition, without extra parentheses for a
/// single name.
fn negate(e: &str) -> String {
    if let Some(rest) = e.strip_prefix('!') {
        if is_name(rest) {
            return rest.to_owned();
        }
    }
    if is_name(e) {
        format!("!{e}")
    } else {
        format!("!({e})")
    }
}

/// Returns true for a C identifier.
fn is_name(s: &str) -> bool {
    let mut it = s.chars();
    it.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && it.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The lexer state.
struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    line_start: bool,
    depth: u32,
    frames: Vec<Frame>,
    conds: Vec<String>,
    cond_ids: HashMap<String, usize>,
    cond: usize,
    tokens: Vec<Token>,
}

/// Lexes one C file.
pub(crate) fn lex(src: &str) -> Lexed {
    let mut lx = Lexer {
        src: src.as_bytes(),
        pos: 0,
        line: 1,
        line_start: true,
        depth: 0,
        frames: Vec::new(),
        conds: vec![String::new()],
        cond_ids: HashMap::from([(String::new(), 0)]),
        cond: 0,
        tokens: Vec::new(),
    };
    lx.run();
    Lexed {
        tokens: lx.tokens,
        conds: lx.conds,
    }
}

impl Lexer<'_> {
    fn peek(&self, off: usize) -> Option<u8> {
        self.src.get(self.pos.saturating_add(off)).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek(0)?;
        self.pos = self.pos.saturating_add(1);
        if c == b'\n' {
            self.line = self.line.saturating_add(1);
        }
        Some(c)
    }

    fn dead(&self) -> bool {
        self.frames.iter().any(Frame::dead)
    }

    fn run(&mut self) {
        while let Some(c) = self.peek(0) {
            match c {
                b'\n' => {
                    self.bump();
                    self.line_start = true;
                }
                b' ' | b'\t' | b'\r' | 0x0c | 0x0b => {
                    self.bump();
                }
                b'\\' if self.peek(1) == Some(b'\n') => {
                    self.bump();
                    self.bump();
                }
                b'/' if self.peek(1) == Some(b'*') => self.block_comment(),
                b'/' if self.peek(1) == Some(b'/') => self.line_comment(),
                b'#' if self.line_start => self.directive(),
                _ => {
                    self.line_start = false;
                    self.token(c);
                }
            }
        }
    }

    fn block_comment(&mut self) {
        self.bump();
        self.bump();
        while let Some(c) = self.bump() {
            if c == b'*' && self.peek(0) == Some(b'/') {
                self.bump();
                return;
            }
        }
    }

    fn line_comment(&mut self) {
        while let Some(c) = self.peek(0) {
            if c == b'\n' {
                return;
            }
            if c == b'\\' && self.peek(1) == Some(b'\n') {
                self.bump();
            }
            self.bump();
        }
    }

    /// Reads a directive line without comments and line splices.
    fn directive_text(&mut self) -> String {
        let mut out = Vec::new();
        while let Some(c) = self.peek(0) {
            match c {
                b'\n' => break,
                b'\\' if self.peek(1) == Some(b'\n') => {
                    self.bump();
                    self.bump();
                    out.push(b' ');
                }
                b'/' if self.peek(1) == Some(b'*') => {
                    self.block_comment();
                    out.push(b' ');
                }
                b'/' if self.peek(1) == Some(b'/') => self.line_comment(),
                _ => {
                    out.push(c);
                    self.bump();
                }
            }
        }
        String::from_utf8_lossy(&out)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Returns true when the next directive after the current position is
    /// `#define name`.
    fn next_is_define(&self, name: &str) -> bool {
        let rest = self.src.get(self.pos..).unwrap_or_default();
        let rest = String::from_utf8_lossy(rest);
        for l in rest.lines() {
            let l = l.trim();
            if l.is_empty() {
                continue;
            }
            let l = l.trim_start_matches('#').trim_start();
            return l
                .strip_prefix("define")
                .is_some_and(|r| r.split_whitespace().next() == Some(name));
        }
        false
    }

    fn directive(&mut self) {
        self.bump();
        let text = self.directive_text();
        let (word, rest) = match text.split_once(' ') {
            Some((w, r)) => (w.to_owned(), r.trim().to_owned()),
            None => (text.clone(), String::new()),
        };
        match word.as_str() {
            "if" | "ifdef" | "ifndef" => {
                let expr = match word.as_str() {
                    "ifdef" => rest.clone(),
                    "ifndef" => negate(&rest),
                    _ => normalize_expr(&rest),
                };
                let guard =
                    word == "ifndef" && self.frames.is_empty() && self.next_is_define(&rest);
                self.frames.push(Frame {
                    exprs: vec![expr],
                    in_else: false,
                    guard,
                    depth_at_if: self.depth,
                    first_end: None,
                });
            }
            "elif" | "else" => {
                let depth = self.depth;
                if let Some(f) = self.frames.last_mut() {
                    if f.first_end.is_none() {
                        f.first_end = Some(depth);
                    }
                    if word == "elif" {
                        f.exprs.push(normalize_expr(&rest));
                    } else {
                        f.in_else = true;
                    }
                    self.depth = f.depth_at_if;
                }
            }
            "endif" => {
                if let Some(f) = self.frames.pop() {
                    if let Some(d) = f.first_end {
                        self.depth = d;
                    }
                }
            }
            _ => {}
        }
        self.update_cond();
    }

    fn update_cond(&mut self) {
        let mut parts = Vec::new();
        for f in &self.frames {
            f.parts(&mut parts);
        }
        let text = parts.join(" && ");
        let next = self.conds.len();
        let id = *self.cond_ids.entry(text.clone()).or_insert(next);
        if id == next {
            self.conds.push(text);
        }
        self.cond = id;
    }

    fn token(&mut self, c: u8) {
        let line = self.line;
        let (kind, text) = if c.is_ascii_alphabetic() || c == b'_' {
            (
                Kind::Ident,
                self.take_while(|b| b.is_ascii_alphanumeric() || b == b'_'),
            )
        } else if c.is_ascii_digit()
            || (c == b'.' && self.peek(1).is_some_and(|d| d.is_ascii_digit()))
        {
            (Kind::Num, self.number())
        } else if c == b'"' {
            (Kind::Str, self.quoted(b'"'))
        } else if c == b'\'' {
            (Kind::Char, self.quoted(b'\''))
        } else {
            self.bump();
            (Kind::Punct, char::from(c).to_string())
        };
        if self.dead() {
            return;
        }
        let mut depth = self.depth;
        if kind == Kind::Punct {
            if text == "{" {
                self.depth = self.depth.saturating_add(1);
            } else if text == "}" {
                self.depth = self.depth.saturating_sub(1);
                depth = self.depth;
            }
        }
        self.tokens.push(Token {
            kind,
            text,
            line,
            depth,
            cond: self.cond,
        });
    }

    fn take_while(&mut self, f: impl Fn(u8) -> bool) -> String {
        let start = self.pos;
        while self.peek(0).is_some_and(&f) {
            self.bump();
        }
        String::from_utf8_lossy(self.src.get(start..self.pos).unwrap_or_default()).into_owned()
    }

    fn number(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek(0) {
            let exp = matches!(c, b'+' | b'-')
                && self
                    .pos
                    .checked_sub(1)
                    .and_then(|p| self.src.get(p))
                    .is_some_and(|p| matches!(p, b'e' | b'E' | b'p' | b'P'));
            if c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || exp {
                self.bump();
            } else {
                break;
            }
        }
        String::from_utf8_lossy(self.src.get(start..self.pos).unwrap_or_default()).into_owned()
    }

    fn quoted(&mut self, q: u8) -> String {
        self.bump();
        let mut out = Vec::new();
        while let Some(c) = self.peek(0) {
            if c == q || c == b'\n' {
                break;
            }
            if c == b'\\' {
                if self.peek(1) == Some(b'\n') {
                    self.bump();
                    self.bump();
                    continue;
                }
                out.push(c);
                self.bump();
                if let Some(n) = self.bump() {
                    out.push(n);
                }
                continue;
            }
            out.push(c);
            self.bump();
        }
        if self.peek(0) == Some(q) {
            self.bump();
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

/// Normalizes the text of an `#if` expression. `defined(X)` and
/// `defined X` become `X`, and an expression with one name keeps no
/// parentheses.
fn normalize_expr(e: &str) -> String {
    let mut s = e.replace("defined(", "(").replace("defined ", "");
    while s.starts_with('(') && s.ends_with(')') && balanced_inner(&s) {
        s = s
            .get(1..s.len().saturating_sub(1))
            .unwrap_or_default()
            .trim()
            .to_owned();
    }
    let mut out = String::new();
    let mut rest = s.as_str();
    while let Some(i) = rest.find('(') {
        let (head, tail) = rest.split_at(i);
        let tail = tail.get(1..).unwrap_or_default();
        if let Some(j) = tail.find(')') {
            let inner = tail.get(..j).unwrap_or_default().trim();
            if is_name(inner)
                && !head
                    .trim_end()
                    .ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
            {
                out.push_str(head);
                out.push_str(inner);
                rest = tail.get(j.saturating_add(1)..).unwrap_or_default();
                continue;
            }
        }
        out.push_str(head);
        out.push('(');
        rest = tail;
    }
    out.push_str(rest);
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Returns true when the outer parentheses of `s` enclose all of it.
fn balanced_inner(s: &str) -> bool {
    let mut depth = 0_i32;
    let n = s.len();
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 && i.saturating_add(1) != n {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Splits the arguments of a call. `open` is the index of the `(` token.
/// Returns the argument token ranges and the index of the `)` token.
pub(crate) fn call_args(
    tokens: &[Token],
    open: usize,
) -> Option<(Vec<std::ops::Range<usize>>, usize)> {
    let mut nest = 0_u32;
    let mut args = Vec::new();
    let mut start = open.checked_add(1)?;
    let mut i = start;
    while let Some(t) = tokens.get(i) {
        if t.kind == Kind::Punct {
            match t.text.as_str() {
                "(" | "[" | "{" => nest = nest.saturating_add(1),
                ")" | "]" | "}" if nest > 0 => nest = nest.saturating_sub(1),
                ")" => {
                    args.push(start..i);
                    return Some((args, i));
                }
                "," if nest == 0 => {
                    args.push(start..i);
                    start = i.checked_add(1)?;
                }
                _ => {}
            }
        }
        i = i.checked_add(1)?;
    }
    None
}

/// Tracks the enclosing function of each token at file scope.
#[derive(Default)]
pub(crate) struct FuncTracker {
    candidate: Option<String>,
    paren: u32,
    last_ident: Option<String>,
    current: Option<String>,
}

impl FuncTracker {
    /// Feeds one token and returns the function that contains it.
    pub(crate) fn feed(&mut self, t: &Token) -> Option<&str> {
        if t.depth == 0 {
            match (t.kind, t.text.as_str()) {
                (Kind::Punct, "(") => {
                    if self.paren == 0 {
                        if let Some(id) = self.last_ident.take() {
                            if !id.starts_with("__attribute") {
                                self.candidate = Some(id);
                            }
                        }
                    }
                    self.paren = self.paren.saturating_add(1);
                }
                (Kind::Punct, ")") => self.paren = self.paren.saturating_sub(1),
                (Kind::Punct, ";" | "=" | "}") => {
                    self.candidate = None;
                    self.last_ident = None;
                    self.current = None;
                }
                (Kind::Punct, "{") => {
                    self.current = self.candidate.take();
                    self.last_ident = None;
                }
                (Kind::Ident, _) => self.last_ident = Some(t.text.clone()),
                _ => self.last_ident = None,
            }
        }
        self.current.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions_and_depth() {
        let src = "#ifndef G_H\n#define G_H\n#ifdef A\nint f(int a) {\n#else\nint f(void) {\n#endif\n  x(\"s\\\"t\", 'c');\n}\n#if 0\nint dead;\n#endif\n#endif\n";
        let lx = lex(src);
        let x = lx.tokens.iter().find(|t| t.is_ident("x"));
        assert_eq!(x.map(|t| (t.line, t.depth)), Some((8, 1)));
        assert_eq!(x.map(|t| lx.cond_of(t)), Some(""));
        let a = lx.tokens.iter().find(|t| t.is_ident("a"));
        assert_eq!(a.map(|t| lx.cond_of(t)), Some("A"));
        let v = lx.tokens.iter().find(|t| t.is_ident("void"));
        assert_eq!(v.map(|t| lx.cond_of(t)), Some("!A"));
        assert!(!lx.tokens.iter().any(|t| t.is_ident("dead")));
        let s = lx.tokens.iter().find(|t| t.kind == Kind::Str);
        assert_eq!(s.map(|t| t.text.as_str()), Some("s\\\"t"));
    }

    #[test]
    fn function_tracking() {
        let lx = lex(
            "static int g = 1;\nvoid __attribute__((x)) h(int a)\n{\n  call(1);\n}\nstruct s { int (*fp)(void); };\n",
        );
        let mut ft = FuncTracker::default();
        let mut seen = Vec::new();
        for t in &lx.tokens {
            let f = ft.feed(t).map(str::to_owned);
            if t.is_ident("call") || t.is_ident("fp") {
                seen.push(f);
            }
        }
        assert_eq!(seen, vec![Some("h".to_owned()), None]);
    }

    #[test]
    fn expressions() {
        assert_eq!(
            normalize_expr("defined(_WIN32) && !defined(X)"),
            "_WIN32 && !X"
        );
        assert_eq!(normalize_expr("(A)"), "A");
        assert_eq!(negate("!A"), "A");
        assert_eq!(negate("A || B"), "!(A || B)");
    }
}
