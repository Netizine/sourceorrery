//! Reading `.env` files for `sourceorrery import`, without ever repeating a
//! value.
//!
//! The syntax is the common ground of python-dotenv, dotenv for Node and
//! godotenv:
//!
//! * `KEY=value`, optionally preceded by `export `; spaces around `=` are
//!   allowed. Blank lines and lines starting with `#` are ignored.
//! * An unquoted value runs to the end of the line, without trailing
//!   whitespace; a `#` preceded by whitespace starts a comment.
//! * `'single'` and `` `backtick` `` quotes are literal. `"double"` quotes
//!   understand `\n`, `\r`, `\t`, `\"` and `\\`; any other backslash is
//!   kept as written. Quoted values may span lines.
//! * Nothing is expanded: `${OTHER}` is stored as written and flagged.
//!
//! Errors carry a line number and a reason, never the text of the file:
//! a malformed line is as likely to hold a secret as a good one.

use sourceorrery_core::SecretBytes;

/// One `KEY=value` assignment.
pub struct Assignment {
    /// The variable name as written.
    pub key: String,
    /// Line the assignment starts on (1-based).
    pub line: usize,
    /// The value, unquoted and unescaped.
    pub value: SecretBytes,
    /// The value mentions `${...}`, which some loaders expand; it is
    /// stored as written.
    pub references_variable: bool,
}

/// Why a file could not be read. Never contains file content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// Line of the problem (1-based).
    pub line: usize,
    /// What is wrong.
    pub reason: &'static str,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "line {}: {} (the line is not repeated, in case it holds a secret)",
            self.line, self.reason
        )
    }
}

impl std::error::Error for ParseError {}

/// Parse a whole file.
pub fn parse(text: &str) -> Result<Vec<Assignment>, ParseError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut cursor = Cursor {
        bytes: text.as_bytes(),
        pos: 0,
        line: 1,
    };
    let mut assignments = Vec::new();
    loop {
        cursor.skip_blank();
        let Some(next) = cursor.peek() else {
            return Ok(assignments);
        };
        if next == b'#' {
            cursor.skip_line();
            continue;
        }
        assignments.push(cursor.assignment()?);
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    line: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        if byte == b'\n' {
            self.line += 1;
        }
        Some(byte)
    }

    /// Spaces, tabs and line breaks.
    fn skip_blank(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.bump();
        }
    }

    /// Spaces and tabs only.
    fn skip_inline_space(&mut self) -> bool {
        let start = self.pos;
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
        self.pos > start
    }

    /// Up to and including the next line break.
    fn skip_line(&mut self) {
        while let Some(byte) = self.bump() {
            if byte == b'\n' {
                break;
            }
        }
    }

    fn word(&mut self) -> &str {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte == b'=' || byte.is_ascii_whitespace() || byte == b'#' {
                break;
            }
            self.pos += 1;
        }
        // Splitting at ASCII bytes keeps the slice on character boundaries.
        std::str::from_utf8(&self.bytes[start..self.pos]).unwrap_or("")
    }

    fn assignment(&mut self) -> Result<Assignment, ParseError> {
        let line = self.line;
        let first = self.word().to_owned();
        let key = if first == "export" && self.skip_inline_space() && self.peek() != Some(b'=') {
            self.word().to_owned()
        } else {
            first
        };
        if key.is_empty() {
            return Err(error(line, "expected KEY=value"));
        }
        self.skip_inline_space();
        if self.peek() != Some(b'=') {
            return Err(error(line, "expected `=` after the variable name"));
        }
        self.pos += 1;
        let spaced = self.skip_inline_space();
        let (value, references_variable) = if let Some(quote @ (b'\'' | b'"' | b'`')) = self.peek()
        {
            let value = self.quoted(quote, line)?;
            // Single quotes are literal in every loader: nothing to expand.
            let references = quote != b'\'' && contains_reference(&value);
            self.after_quoted(line)?;
            (value, references)
        } else {
            let value = self.unquoted(spaced);
            let references = contains_reference(&value);
            (value, references)
        };
        Ok(Assignment {
            key,
            line,
            value: SecretBytes::new(value),
            references_variable,
        })
    }

    fn quoted(&mut self, quote: u8, line: usize) -> Result<Vec<u8>, ParseError> {
        self.pos += 1;
        let mut value = Vec::with_capacity(self.bytes.len() - self.pos);
        loop {
            let Some(byte) = self.bump() else {
                return Err(error(line, "a quoted value is never closed"));
            };
            if byte == quote {
                value.shrink_to_fit();
                return Ok(value);
            }
            if byte == b'\\' && quote == b'"' {
                match self.peek() {
                    Some(b'n') => value.push(b'\n'),
                    Some(b'r') => value.push(b'\r'),
                    Some(b't') => value.push(b'\t'),
                    Some(b'"') => value.push(b'"'),
                    Some(b'\\') => value.push(b'\\'),
                    _ => {
                        value.push(b'\\');
                        continue;
                    }
                }
                self.pos += 1;
                continue;
            }
            // A CRLF file's line break inside a quoted value is one newline.
            if byte == b'\r' && self.peek() == Some(b'\n') {
                continue;
            }
            value.push(byte);
        }
    }

    /// After a closing quote: only whitespace or a comment may follow.
    fn after_quoted(&mut self, line: usize) -> Result<(), ParseError> {
        self.skip_inline_space();
        match self.peek() {
            None | Some(b'\n' | b'\r') => Ok(()),
            Some(b'#') => {
                self.skip_line();
                Ok(())
            }
            Some(_) => Err(error(line, "unexpected text after a quoted value")),
        }
    }

    /// To the end of the line; `spaced` says whitespace preceded the value,
    /// in which case a leading `#` is a comment.
    fn unquoted(&mut self, spaced: bool) -> Vec<u8> {
        let start = self.pos;
        let mut end = start;
        let mut previous_space = spaced;
        while let Some(byte) = self.peek() {
            if byte == b'\n' || byte == b'\r' {
                break;
            }
            if byte == b'#' && previous_space {
                break;
            }
            previous_space = byte == b' ' || byte == b'\t';
            self.pos += 1;
            if !previous_space {
                end = self.pos;
            }
        }
        if self.peek() == Some(b'#') {
            self.skip_line();
        }
        self.bytes[start..end].to_vec()
    }
}

fn error(line: usize, reason: &'static str) -> ParseError {
    ParseError { line, reason }
}

fn contains_reference(value: &[u8]) -> bool {
    value.windows(2).any(|pair| pair == b"${")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(text: &str) -> Vec<(String, String)> {
        parse(text)
            .unwrap()
            .into_iter()
            .map(|a| (a.key, String::from_utf8(a.value.expose().to_vec()).unwrap()))
            .collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn reads_the_common_forms() {
        let lines = [
            "\u{feff}# a comment",
            "DATABASE_URL=postgres://u@h/db",
            "export API_KEY = abc123   # trailing comment",
            "EMPTY=",
            "SPACED= # only a comment",
            "HASH=a#b",
            "LEADING_HASH=#abc",
            r"SINGLE='literal \n ${NOT_EXPANDED}'",
            r#"DOUBLE="line\nnext \"quoted\" \\ \x""#,
            "TICK=`back tick` # comment",
            "",
            "MULTI=\"first\r\nsecond\"\r",
            "export=keyword",
        ];
        let text = format!("{}\nLAST=no newline", lines.join("\n"));
        assert_eq!(
            values(&text),
            pairs(&[
                ("DATABASE_URL", "postgres://u@h/db"),
                ("API_KEY", "abc123"),
                ("EMPTY", ""),
                ("SPACED", ""),
                ("HASH", "a#b"),
                ("LEADING_HASH", "#abc"),
                ("SINGLE", r"literal \n ${NOT_EXPANDED}"),
                ("DOUBLE", "line\nnext \"quoted\" \\ \\x"),
                ("TICK", "back tick"),
                ("MULTI", "first\nsecond"),
                ("export", "keyword"),
                ("LAST", "no newline"),
            ])
        );
    }

    #[test]
    fn records_lines_and_variable_references() {
        let parsed = parse("A=1\n\nB=\"x ${A}\"\nC='${A}'\nD=${A}\n").unwrap();
        let summary: Vec<_> = parsed
            .iter()
            .map(|a| (a.key.as_str(), a.line, a.references_variable))
            .collect();
        assert_eq!(
            summary,
            [
                ("A", 1, false),
                ("B", 3, true),
                ("C", 4, false),
                ("D", 5, true)
            ]
        );
    }

    #[test]
    fn errors_name_the_line_and_never_the_value() {
        const CANARY: &str = "dotenv-canary-5e2f";
        for (text, line, reason) in [
            (
                format!("OK=1\nBROKEN {CANARY}\n"),
                2,
                "expected `=` after the variable name",
            ),
            (
                format!("OK=1\nOPEN=\"{CANARY}\n"),
                2,
                "a quoted value is never closed",
            ),
            (
                format!("Q='{CANARY}' {CANARY}\n"),
                1,
                "unexpected text after a quoted value",
            ),
            (format!("={CANARY}\n"), 1, "expected KEY=value"),
        ] {
            let err = parse(&text).err().unwrap();
            assert_eq!((err.line, err.reason), (line, reason), "{text:?}");
            assert!(!err.to_string().contains(CANARY), "{err}");
        }
    }
}
