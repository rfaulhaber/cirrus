//! Escaping for values interpolated into SOQL.
//!
//! The query resources take the whole statement as one string and have no
//! bind parameters, so a value that reaches a statement from outside the
//! program is escaped by the caller or it rewrites the statement. Inside a
//! string literal Salesforce reserves the single quote and the backslash;
//! inside a `LIKE` pattern `%` and `_` are wildcards as well.
//!
//! - [`quote`] renders a value as a complete string literal.
//! - [`escape_like`] renders a value as part of a `LIKE` pattern, so the
//!   caller can put its own wildcards around it.
//!
//! The percent-encoding the client applies to the `q` parameter is
//! transport encoding; it does not make a value safe inside the SOQL.
//!
//! ```
//! use cirrus::soql;
//!
//! let name = "Bob's BBQ";
//! let soql = format!("SELECT Id FROM Account WHERE Name = {}", soql::quote(name));
//! assert_eq!(soql, r"SELECT Id FROM Account WHERE Name = 'Bob\'s BBQ'");
//!
//! let prefix = "100%";
//! let soql = format!(
//!     "SELECT Id FROM Account WHERE Name LIKE '{}%'",
//!     soql::escape_like(prefix)
//! );
//! assert_eq!(soql, r"SELECT Id FROM Account WHERE Name LIKE '100\%%'");
//! ```
//!
//! Sources: [Reserved Characters] and [Quoted String Escape Sequences] in
//! the SOQL and SOSL Reference.
//!
//! [Reserved Characters]: https://developer.salesforce.com/docs/platform/salesforce-soql-sosl/guide/sforce-api-calls-soql-select-reservedcharacters.html
//! [Quoted String Escape Sequences]: https://developer.salesforce.com/docs/platform/salesforce-soql-sosl/guide/sforce-api-calls-soql-select-quotedstringescapes.html

/// Renders `value` as a SOQL string literal, quotes included.
///
/// A backslash and a single quote, the two characters Salesforce reserves
/// inside a literal, are each preceded by a backslash. Everything else
/// passes through unchanged, including `%` and `_`, which only a `LIKE`
/// pattern reads as wildcards (see [`escape_like`]).
pub fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    escape_into(&mut out, value, &['\\', '\'']);
    out.push('\'');
    out
}

/// Renders `value` as a fragment of a `LIKE` pattern, without quotes.
///
/// Escapes what [`quote`] escapes plus `%` and `_`, which `LIKE` reads as
/// wildcards, so the fragment matches the value literally and the caller
/// adds the wildcards it means: `format!("LIKE '{}%'", escape_like(prefix))`.
/// The `\%` and `\_` sequences are valid only inside a `LIKE` pattern, which
/// is why this is not [`quote`].
pub fn escape_like(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    escape_into(&mut out, value, &['\\', '\'', '%', '_']);
    out
}

fn escape_into(out: &mut String, value: &str, reserved: &[char]) {
    for c in value.chars() {
        if reserved.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_wraps_a_plain_value() {
        assert_eq!(quote("Acme"), "'Acme'");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn quote_escapes_the_two_reserved_characters() {
        // The documented example: "Bob's BBQ" is written 'Bob\'s BBQ'.
        assert_eq!(quote("Bob's BBQ"), r"'Bob\'s BBQ'");
        assert_eq!(quote(r"C:\temp"), r"'C:\\temp'");
        assert_eq!(quote(r"\'"), r"'\\\''");
    }

    #[test]
    fn quote_neutralizes_a_value_that_would_rewrite_the_where_clause() {
        let hostile = "x' OR LastName != '";
        let soql = format!("SELECT Id FROM Contact WHERE LastName = {}", quote(hostile));
        assert_eq!(
            soql,
            r"SELECT Id FROM Contact WHERE LastName = 'x\' OR LastName != \''"
        );
    }

    #[test]
    fn quote_passes_like_wildcards_and_other_characters_through() {
        assert_eq!(quote("50%_off"), "'50%_off'");
        assert_eq!(quote("a \"b\" \n é 東京"), "'a \"b\" \n é 東京'");
    }

    #[test]
    fn escape_like_escapes_the_wildcards_and_leaves_the_quotes_to_the_caller() {
        assert_eq!(escape_like("50%_off"), r"50\%\_off");
        assert_eq!(escape_like("Ter%"), r"Ter\%");
        assert_eq!(escape_like("Bob's"), r"Bob\'s");
        assert_eq!(escape_like(r"a\b"), r"a\\b");
        assert_eq!(escape_like(""), "");
        assert_eq!(format!("LIKE '{}%'", escape_like("Ter%")), r"LIKE 'Ter\%%'");
    }
}
