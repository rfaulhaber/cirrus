//! Escaping for terms interpolated into a SOSL `FIND` clause.
//!
//! `FIND {...}` reserves nineteen characters, and a term that carries one
//! unescaped changes the clause instead of being searched for: a `}` ends
//! the clause, `*` and `?` are wildcards, `"` opens a phrase. [`escape_term`]
//! precedes each reserved character with a backslash, which Salesforce
//! requires "even if the SearchQuery is enclosed in double quotes".
//!
//! ```
//! use cirrus::sosl;
//!
//! let term = "{1+1}:2";
//! let sosl = format!("FIND {{{}}} RETURNING Account(Id)", sosl::escape_term(term));
//! assert_eq!(sosl, r"FIND {\{1\+1\}\:2} RETURNING Account(Id)");
//! ```
//!
//! Source: [FIND {SearchQuery}] in the SOQL and SOSL Reference, whose
//! escaping example this is.
//!
//! [FIND {SearchQuery}]: https://developer.salesforce.com/docs/platform/salesforce-soql-sosl/guide/sforce-api-calls-sosl-find.html

/// The characters a `FIND` clause reserves, each of which [`escape_term`]
/// precedes with a backslash.
pub const RESERVED: [char; 19] = [
    '?', '&', '|', '!', '{', '}', '[', ']', '(', ')', '^', '~', '*', ':', '\\', '"', '\'', '+', '-',
];

/// Escapes `term` for use inside `FIND {...}`.
///
/// Every character in [`RESERVED`] is preceded by a backslash, so the
/// result searches for the term as typed: `*` and `?` lose their wildcard
/// meaning and a `}` cannot end the clause. Append a wildcard after
/// escaping to keep it (`format!("{}*", escape_term(prefix))`). The words
/// `AND`, `OR` and `AND NOT` stay operators unless the term is surrounded
/// by double quotes, which is also how to search for a phrase in the order
/// typed: `format!("\"{}\"", escape_term(phrase))`.
pub fn escape_term(term: &str) -> String {
    let mut out = String::with_capacity(term.len());
    for c in term.chars() {
        if RESERVED.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_term_leaves_a_plain_term_alone() {
        assert_eq!(escape_term("MyProspect"), "MyProspect");
        assert_eq!(escape_term("John Smith"), "John Smith");
        assert_eq!(escape_term(""), "");
        assert_eq!(escape_term("東京都"), "東京都");
    }

    #[test]
    fn escape_term_escapes_every_reserved_character() {
        // The documented example and the full reserved list.
        assert_eq!(escape_term("{1+1}:2"), r"\{1\+1\}\:2");
        assert_eq!(escape_term("Why not?"), r"Why not\?");
        let all: String = RESERVED.iter().collect();
        let escaped = escape_term(&all);
        assert_eq!(escaped.len(), all.len() * 2);
        for (escaped_pair, original) in escaped.as_bytes().chunks(2).zip(all.bytes()) {
            assert_eq!(escaped_pair, [b'\\', original]);
        }
    }

    #[test]
    fn escape_term_keeps_a_term_inside_its_braces() {
        let hostile = "x} RETURNING User(Id, Email) LIMIT 1 ";
        let sosl = format!("FIND {{{}}} RETURNING Account(Id)", escape_term(hostile));
        assert_eq!(
            sosl,
            r"FIND {x\} RETURNING User\(Id, Email\) LIMIT 1 } RETURNING Account(Id)"
        );
    }

    #[test]
    fn escape_term_escapes_wildcards_and_quotes_so_the_caller_adds_its_own() {
        assert_eq!(escape_term("mi* \"meyers\""), r#"mi\* \"meyers\""#);
        assert_eq!(format!("{}*", escape_term("john")), "john*");
    }
}
