//! The SOAP headers Salesforce documents for the Metadata API.
//!
//! Beyond `SessionHeader`, which the client always sends, the Metadata
//! API defines `CallOptions` (every call but `describeValueType`),
//! `AllOrNoneHeader` (the CRUD writes) and `DebuggingHeader` (`deploy`
//! and `deployRecentValidation`), and answers `checkDeployStatus` with a
//! `DebuggingInfo` output header. This module holds the typed request
//! and response pieces; the methods that send them live on
//! [`MetadataClient`](crate::MetadataClient).

use crate::envelope::xml_escape;
use serde::Deserialize;

/// The `DebuggingHeader` of a deployment: which Apex debug log
/// categories to record, and at what level.
///
/// Send it with [`MetadataClient::deploy_with_debugging`] or
/// [`MetadataClient::deploy_recent_validation_with_debugging`]. Once the
/// deployment has finished and ran tests, the log comes back in the
/// [`DebuggingInfo`] header of the status check; read it with
/// [`MetadataClient::check_deploy_status_with_debugging`] or
/// [`MetadataClient::wait_for_deploy_with_debugging`].
///
/// The Metadata API Developer Guide documents the header on its
/// `DebuggingHeader` page. Its deprecated `debugLevel` field is not
/// modeled; the log is configured through `categories` alone.
///
/// [`MetadataClient::deploy_with_debugging`]: crate::MetadataClient::deploy_with_debugging
/// [`MetadataClient::deploy_recent_validation_with_debugging`]: crate::MetadataClient::deploy_recent_validation_with_debugging
/// [`MetadataClient::check_deploy_status_with_debugging`]: crate::MetadataClient::check_deploy_status_with_debugging
/// [`MetadataClient::wait_for_deploy_with_debugging`]: crate::MetadataClient::wait_for_deploy_with_debugging
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebuggingHeader {
    /// The categories to log, each with its level.
    pub categories: Vec<LogInfo>,
}

/// One debug log category and the level it is recorded at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogInfo {
    /// What to log.
    pub category: LogCategory,
    /// How verbosely to log it.
    pub level: LogCategoryLevel,
}

/// A debug log category.
///
/// Salesforce adds categories over time, so the enum is
/// `#[non_exhaustive]`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogCategory {
    /// Database activity.
    Db,
    /// Workflow rules and actions.
    Workflow,
    /// Validation rules.
    Validation,
    /// Callouts to external services.
    Callout,
    /// Apex code.
    ApexCode,
    /// Apex code profiling.
    ApexProfiling,
    /// Visualforce.
    Visualforce,
    /// System calls.
    System,
    /// Analytics (Wave).
    Wave,
    /// Next Best Action.
    Nba,
    /// Data access.
    DataAccess,
    /// Every category.
    All,
}

impl LogCategory {
    // Wire-shape provenance (API 66.0 Metadata WSDL,
    // sforce.660.metadata.wsdl): the `LogCategory` enumeration values,
    // with the underscore spellings the server validates.
    pub(crate) fn as_wire(&self) -> &'static str {
        match self {
            Self::Db => "Db",
            Self::Workflow => "Workflow",
            Self::Validation => "Validation",
            Self::Callout => "Callout",
            Self::ApexCode => "Apex_code",
            Self::ApexProfiling => "Apex_profiling",
            Self::Visualforce => "Visualforce",
            Self::System => "System",
            Self::Wave => "Wave",
            Self::Nba => "Nba",
            Self::DataAccess => "Data_access",
            Self::All => "All",
        }
    }
}

/// How verbosely a [`LogCategory`] is recorded, from `Finest` (most
/// detail) down to `Error`, or `None` to record nothing.
///
/// Salesforce adds levels over time, so the enum is
/// `#[non_exhaustive]`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogCategoryLevel {
    /// Record nothing.
    None,
    /// Most detail.
    Finest,
    /// Very fine detail.
    Finer,
    /// Fine detail.
    Fine,
    /// Debug messages.
    Debug,
    /// Informational messages.
    Info,
    /// Warnings.
    Warn,
    /// Errors only.
    Error,
}

impl LogCategoryLevel {
    // Wire-shape provenance (API 66.0 Metadata WSDL,
    // sforce.660.metadata.wsdl): the `LogCategoryLevel` enumeration
    // values. The DebuggingHeader doc page prints them upper-case; the
    // schema the server validates against is mixed case.
    pub(crate) fn as_wire(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Finest => "Finest",
            Self::Finer => "Finer",
            Self::Fine => "Fine",
            Self::Debug => "Debug",
            Self::Info => "Info",
            Self::Warn => "Warn",
            Self::Error => "Error",
        }
    }
}

/// The Apex debug log of a deployment, from the `DebuggingInfo` output
/// header of a status check.
///
/// The log can run to megabytes, so the `Debug` output reports its
/// length instead of its text.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebuggingInfo {
    /// The debug log text.
    pub debug_log: String,
}

impl std::fmt::Debug for DebuggingInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DebuggingInfo")
            .field("debug_log_len", &self.debug_log.len())
            .finish()
    }
}

/// The output headers of one SOAP call.
///
/// Only `DebuggingInfo` is documented for the Metadata API.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct SoapResponseHeaders {
    /// The deployment's debug log, on a `checkDeployStatus` response
    /// for a deploy that requested one.
    pub debugging_info: Option<DebuggingInfo>,
}

// Wire-shape provenance (api_meta doc page IDs): `meta_calloptions`
// documents `client` ("A value that identifies an API client"); the
// element layout is `CallOptions{client: string}` in the API 66.0
// Metadata WSDL (sforce.660.metadata.wsdl).
pub(crate) fn render_call_options(client: &str, out: &mut String) {
    out.push_str("<met:CallOptions><met:client>");
    out.push_str(&xml_escape(client));
    out.push_str("</met:client></met:CallOptions>");
}

// Wire-shape provenance (api_meta doc page IDs): `meta_allornoneheader`
// (API 34.0 and later; an absent header is equivalent to
// `allOrNone=false`, so only `true` is ever rendered). Element layout
// `AllOrNoneHeader{allOrNone: boolean}` per the API 66.0 Metadata WSDL
// (sforce.660.metadata.wsdl).
pub(crate) fn render_all_or_none(out: &mut String) {
    out.push_str("<met:AllOrNoneHeader><met:allOrNone>true</met:allOrNone></met:AllOrNoneHeader>");
}

// Wire-shape provenance (api_meta doc page IDs): `meta_debuggingheader`
// documents `categories` (LogInfo[]) and deprecates `debugLevel` ("If
// you provide values for both debugLevel and categories, the
// categories value is used"); its Java sample sets only categories.
// The API 66.0 Metadata WSDL (sforce.660.metadata.wsdl) still declares
// `debugLevel` without `minOccurs="0"`, so the schema requires the
// element. Salesforce's reference client (WSC, `TypeMapper.writeObject`)
// writes an unset required element as `xsi:nil="true"`, which is what
// this sends after the categories.
pub(crate) fn render_debugging_header(header: &DebuggingHeader, out: &mut String) {
    out.push_str("<met:DebuggingHeader>");
    for info in &header.categories {
        out.push_str("<met:categories><met:category>");
        out.push_str(info.category.as_wire());
        out.push_str("</met:category><met:level>");
        out.push_str(info.level.as_wire());
        out.push_str("</met:level></met:categories>");
    }
    out.push_str(r#"<met:debugLevel xsi:nil="true"/></met:DebuggingHeader>"#);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn call_options_renders_the_client_element() {
        let mut out = String::new();
        render_call_options("cirrus-tests/1.0", &mut out);
        assert_eq!(
            out,
            "<met:CallOptions><met:client>cirrus-tests/1.0</met:client></met:CallOptions>"
        );
    }

    #[test]
    fn call_options_escapes_the_client() {
        let mut out = String::new();
        render_call_options("a<b&c", &mut out);
        assert_eq!(
            out,
            "<met:CallOptions><met:client>a&lt;b&amp;c</met:client></met:CallOptions>"
        );
    }

    #[test]
    fn all_or_none_renders_true() {
        let mut out = String::new();
        render_all_or_none(&mut out);
        assert_eq!(
            out,
            "<met:AllOrNoneHeader><met:allOrNone>true</met:allOrNone></met:AllOrNoneHeader>"
        );
    }

    #[test]
    fn debugging_header_renders_each_category_then_a_nil_debug_level() {
        let header = DebuggingHeader {
            categories: vec![
                LogInfo {
                    category: LogCategory::ApexCode,
                    level: LogCategoryLevel::Fine,
                },
                LogInfo {
                    category: LogCategory::Db,
                    level: LogCategoryLevel::Info,
                },
            ],
        };
        let mut out = String::new();
        render_debugging_header(&header, &mut out);
        assert_eq!(
            out,
            "<met:DebuggingHeader>\
             <met:categories><met:category>Apex_code</met:category><met:level>Fine</met:level></met:categories>\
             <met:categories><met:category>Db</met:category><met:level>Info</met:level></met:categories>\
             <met:debugLevel xsi:nil=\"true\"/>\
             </met:DebuggingHeader>"
        );
    }

    #[test]
    fn empty_debugging_header_still_carries_the_required_debug_level() {
        let mut out = String::new();
        render_debugging_header(&DebuggingHeader::default(), &mut out);
        assert_eq!(
            out,
            "<met:DebuggingHeader><met:debugLevel xsi:nil=\"true\"/></met:DebuggingHeader>"
        );
    }

    #[test]
    fn log_category_wire_spellings_match_the_wsdl() {
        let expected = [
            (LogCategory::Db, "Db"),
            (LogCategory::Workflow, "Workflow"),
            (LogCategory::Validation, "Validation"),
            (LogCategory::Callout, "Callout"),
            (LogCategory::ApexCode, "Apex_code"),
            (LogCategory::ApexProfiling, "Apex_profiling"),
            (LogCategory::Visualforce, "Visualforce"),
            (LogCategory::System, "System"),
            (LogCategory::Wave, "Wave"),
            (LogCategory::Nba, "Nba"),
            (LogCategory::DataAccess, "Data_access"),
            (LogCategory::All, "All"),
        ];
        for (variant, wire) in expected {
            assert_eq!(variant.as_wire(), wire);
        }
    }

    #[test]
    fn log_category_level_wire_spellings_match_the_wsdl() {
        let expected = [
            (LogCategoryLevel::None, "None"),
            (LogCategoryLevel::Finest, "Finest"),
            (LogCategoryLevel::Finer, "Finer"),
            (LogCategoryLevel::Fine, "Fine"),
            (LogCategoryLevel::Debug, "Debug"),
            (LogCategoryLevel::Info, "Info"),
            (LogCategoryLevel::Warn, "Warn"),
            (LogCategoryLevel::Error, "Error"),
        ];
        for (variant, wire) in expected {
            assert_eq!(variant.as_wire(), wire);
        }
    }

    #[test]
    fn debugging_info_debug_omits_the_log_text() {
        let info = DebuggingInfo {
            debug_log: "x".repeat(1024 * 1024),
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("debug_log_len"), "{dbg}");
        assert!(dbg.len() < 128, "{}", dbg.len());
    }

    #[test]
    fn debugging_info_deserializes_from_the_header_element() {
        let info: DebuggingInfo = quick_xml::de::from_str(
            "<DebuggingInfo><debugLog>line one &amp; two</debugLog></DebuggingInfo>",
        )
        .unwrap();
        assert_eq!(info.debug_log, "line one & two");
    }
}
