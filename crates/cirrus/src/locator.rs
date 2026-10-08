//! Confinement of server-issued locators — a `nextRecordsUrl`, an
//! EventLogFile `LogFile` value — to the resource they are documented to
//! name, on this session's own instance.
//!
//! A locator is a path the org handed back, and callers store it and hand
//! it back later, sometimes by way of a browser client. The verbs send any
//! path with the session's bearer token, so before a locator reaches one
//! it has to look like the documented resource: the instance's origin if
//! it is absolute, no query string or fragment, no percent-encoding or
//! backslash, no dot segment, and exactly the documented segments.

/// One segment of a documented locator shape.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Segment {
    /// A fixed resource name, matched exactly.
    Literal(&'static str),
    /// A `vNN.N` API version.
    Version,
    /// One opaque value: a query locator, a record id.
    Value,
}

/// Returns `value` as an instance-rooted path (with its leading `/`) when
/// it names one of `shapes` on `instance_url`, else a description of the
/// mismatch. The description never echoes the value: a substituted
/// locator is exactly the kind of text that should not reach a log.
pub(crate) fn confine(
    instance_url: &str,
    value: &str,
    shapes: &[&[Segment]],
) -> Result<String, String> {
    let path = if value.starts_with("http://") || value.starts_with("https://") {
        let candidate = url::Url::parse(value).map_err(|e| format!("is not a valid URL: {e}"))?;
        let instance = url::Url::parse(instance_url)
            .map_err(|e| format!("cannot be checked, the instance URL is invalid: {e}"))?;
        if candidate.origin() != instance.origin() {
            return Err(format!(
                "points at {}, not the org instance {}",
                candidate.origin().ascii_serialization(),
                instance.origin().ascii_serialization(),
            ));
        }
        if candidate.query().is_some() || candidate.fragment().is_some() {
            return Err(
                "carries a query string or fragment, which no documented locator does".into(),
            );
        }
        candidate.path().to_owned()
    } else {
        value.to_owned()
    };

    if let Some(c) = ['?', '#', '%', '\\']
        .into_iter()
        .find(|c| path.contains(*c))
    {
        return Err(format!("contains `{c}`, which no documented locator does"));
    }

    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let matches = |shape: &&[Segment]| {
        shape.len() == segments.len()
            && shape
                .iter()
                .zip(&segments)
                .all(|(expected, segment)| match expected {
                    Segment::Literal(name) => segment == name,
                    Segment::Version => is_api_version_segment(segment),
                    Segment::Value => !segment.is_empty() && *segment != "." && *segment != "..",
                })
    };
    if shapes.iter().any(matches) {
        Ok(format!("/{}", segments.join("/")))
    } else {
        Err(format!("does not have the shape {}", describe(shapes)))
    }
}

/// Whether `segment` is a `vNN.N` API version: the `v` prefix and bare
/// ASCII digits on both sides of the dot. `u32::from_str` would also take
/// a leading sign, which is not a path segment the API answers.
pub(crate) fn is_api_version_segment(segment: &str) -> bool {
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    segment
        .strip_prefix('v')
        .and_then(|rest| rest.split_once('.'))
        .is_some_and(|(major, minor)| digits(major) && digits(minor))
}

fn describe(shapes: &[&[Segment]]) -> String {
    let one = |shape: &&[Segment]| {
        shape
            .iter()
            .map(|segment| match segment {
                Segment::Literal(name) => (*name).to_owned(),
                Segment::Version => "vNN.N".to_owned(),
                Segment::Value => "{value}".to_owned(),
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    shapes
        .iter()
        .map(|shape| format!("`/{}`", one(shape)))
        .collect::<Vec<_>>()
        .join(" or ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::Segment::{Literal, Value, Version};
    use super::*;

    const SHAPE: &[&[Segment]] = &[&[
        Literal("services"),
        Literal("data"),
        Version,
        Literal("query"),
        Value,
    ]];
    const INSTANCE: &str = "https://my-org.my.salesforce.com";

    #[test]
    fn a_bare_path_is_rooted_with_or_without_its_leading_slash() {
        let want = "/services/data/v66.0/query/01gXXX-2000";
        assert_eq!(confine(INSTANCE, want, SHAPE).unwrap(), want);
        assert_eq!(confine(INSTANCE, &want[1..], SHAPE).unwrap(), want);
        assert_eq!(confine(INSTANCE, &format!("/{want}"), SHAPE).unwrap(), want);
    }

    #[test]
    fn a_same_origin_url_is_reduced_to_its_path() {
        let want = "/services/data/v66.0/query/01gXXX-2000";
        assert_eq!(
            confine(INSTANCE, &format!("{INSTANCE}{want}"), SHAPE).unwrap(),
            want
        );
        // Origin comparison ignores the case of the host but not the scheme.
        assert_eq!(
            confine(
                INSTANCE,
                &format!("https://MY-ORG.my.salesforce.com{want}"),
                SHAPE
            )
            .unwrap(),
            want
        );
        assert!(
            confine(
                INSTANCE,
                &format!("http://my-org.my.salesforce.com{want}"),
                SHAPE
            )
            .is_err()
        );
    }

    #[test]
    fn the_error_names_the_expected_shape_and_never_the_value() {
        let err = confine(
            INSTANCE,
            "/services/data/v66.0/sobjects/Contact/003SECRET",
            SHAPE,
        )
        .unwrap_err();
        assert!(
            err.contains("`/services/data/vNN.N/query/{value}`"),
            "{err}"
        );
        assert!(!err.contains("003SECRET"), "{err}");
        let err = confine(
            INSTANCE,
            "/services/data/v66.0/query?q=SELECT+Email+FROM+Contact",
            SHAPE,
        )
        .unwrap_err();
        assert!(!err.contains("Email"), "{err}");
    }

    #[test]
    fn is_api_version_segment_wants_v_and_bare_digits() {
        assert!(is_api_version_segment("v66.0"));
        assert!(is_api_version_segment("v9.0"));
        assert!(!is_api_version_segment("66.0"));
        assert!(!is_api_version_segment("v+66.0"));
        assert!(!is_api_version_segment("v66"));
        assert!(!is_api_version_segment("v66."));
        assert!(!is_api_version_segment("v.0"));
        assert!(!is_api_version_segment("latest"));
    }
}
