//! Typed builder for `package.xml` manifests.
//!
//! `package.xml` is the platform-defined manifest format for the
//! Metadata API — it tells deploy and retrieve calls which metadata
//! components to act on. The shape is fixed (the same XML is consumed
//! by `deploy()` inside a zip and by `retrieve()` as the `unpackaged`
//! SOAP parameter), so we model it as a typed builder rather than
//! asking callers to hand-render the XML.
//!
//! ## Quick start
//!
//! ```
//! use cirrus_metadata::{MetadataType, PackageManifest};
//!
//! let pkg = PackageManifest::new("66.0")
//!     .add(MetadataType::APEX_CLASS, ["Foo", "Bar"])
//!     .add(MetadataType::CUSTOM_OBJECT, ["Account__c"])
//!     .all(MetadataType::CUSTOM_TAB);
//!
//! let xml: String = pkg.to_xml();
//! assert!(xml.contains("<members>Foo</members>"));
//! assert!(xml.contains("<members>*</members>"));
//! ```
//!
//! ## Wire shape
//!
//! The emitted XML is the canonical `package.xml`:
//!
//! ```xml
//! <?xml version="1.0" encoding="UTF-8"?>
//! <Package xmlns="http://soap.sforce.com/2006/04/metadata">
//!     <types>
//!         <members>Foo</members>
//!         <members>Bar</members>
//!         <name>ApexClass</name>
//!     </types>
//!     <version>66.0</version>
//! </Package>
//! ```
//!
//! For the SOAP `retrieve()` `unpackaged` parameter, `cirrus-metadata`
//! emits the same structure with the `met:` namespace prefix internally —
//! callers don't need a different builder. Just pass the same
//! `PackageManifest` to [`RetrieveRequest::unpackaged`].
//!
//! ## `MetadataType` registry coverage
//!
//! Constants on [`MetadataType`] cover the ~40 most-commonly-used
//! types. For anything not enumerated, use [`MetadataType::new`] with
//! the Salesforce-defined name — the `xml_name` field returned by
//! [`MetadataClient::describe_metadata`] is the authoritative source.
//!
//! [`RetrieveRequest::unpackaged`]: crate::RetrieveRequest::unpackaged
//! [`MetadataClient::describe_metadata`]: crate::MetadataClient::describe_metadata

use crate::envelope::xml_escape;
use std::borrow::Cow;

/// Identifier for a metadata type — the `xml_name` value that goes in
/// `<types><name>` and as the SOAP type parameter.
///
/// Use the associated constants ([`Self::APEX_CLASS`], etc.) for
/// common types, or [`Self::new`] for any Salesforce-defined type
/// that isn't covered by a constant. The constants are
/// `const`-constructible, so they cost nothing at runtime — they're
/// just typed wrappers around `&'static str` values.
///
/// ```
/// use cirrus_metadata::MetadataType;
///
/// // Use a constant for a common type:
/// let t = MetadataType::APEX_CLASS;
/// assert_eq!(t.as_str(), "ApexClass");
///
/// // Or pass an arbitrary type name:
/// let t = MetadataType::new("MyCustomFeatureType");
/// assert_eq!(t.as_str(), "MyCustomFeatureType");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MetadataType(Cow<'static, str>);

impl MetadataType {
    /// Construct from any string: a literal, a `String`, or a borrowed
    /// name such as the `xml_name` of a
    /// [`DescribeMetadataObject`](crate::DescribeMetadataObject).
    pub fn new(name: impl Into<String>) -> Self {
        Self(Cow::Owned(name.into()))
    }

    /// The bare name as it appears in `package.xml`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for MetadataType {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MetadataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// A borrowed name is copied rather than held for `'static`, so the
// names `describe_metadata` returns can feed a manifest directly.
impl From<&str> for MetadataType {
    fn from(s: &str) -> Self {
        Self(Cow::Owned(s.to_owned()))
    }
}

impl From<&String> for MetadataType {
    fn from(s: &String) -> Self {
        Self(Cow::Owned(s.clone()))
    }
}

impl From<String> for MetadataType {
    fn from(s: String) -> Self {
        Self(Cow::Owned(s))
    }
}

impl From<&MetadataType> for MetadataType {
    fn from(t: &MetadataType) -> Self {
        t.clone()
    }
}

// Common type constants. This is a curated subset, not exhaustive —
// Salesforce ships ~200 metadata types and the list grows every
// release. For anything not listed here, use [`MetadataType::new`].
//
// Constants are grouped by area (Apex, customization, security,
// reporting, Lightning) and use SCREAMING_SNAKE_CASE per Rust
// convention.
impl MetadataType {
    // -- Apex --
    /// An Apex class, a template or blueprint from which Apex objects
    /// are created.
    pub const APEX_CLASS: MetadataType = MetadataType(Cow::Borrowed("ApexClass"));
    /// A Visualforce component.
    pub const APEX_COMPONENT: MetadataType = MetadataType(Cow::Borrowed("ApexComponent"));
    /// A Visualforce page.
    pub const APEX_PAGE: MetadataType = MetadataType(Cow::Borrowed("ApexPage"));
    /// An Apex trigger, Apex code that runs before or after specific
    /// DML events such as an insert or a delete.
    pub const APEX_TRIGGER: MetadataType = MetadataType(Cow::Borrowed("ApexTrigger"));
    /// A suite of Apex test classes to include in a test run.
    pub const APEX_TEST_SUITE: MetadataType = MetadataType(Cow::Borrowed("ApexTestSuite"));

    // -- Customization --
    /// A custom object that stores data unique to the org, or an
    /// external object that maps to data stored outside it. Also
    /// carries customizations of standard objects such as accounts.
    pub const CUSTOM_OBJECT: MetadataType = MetadataType(Cow::Borrowed("CustomObject"));
    /// A field definition: custom fields on standard, custom and
    /// external objects, and the customizable standard fields of
    /// standard objects.
    pub const CUSTOM_FIELD: MetadataType = MetadataType(Cow::Borrowed("CustomField"));
    /// A custom tab, which displays custom object data or other web
    /// content in Salesforce.
    pub const CUSTOM_TAB: MetadataType = MetadataType(Cow::Borrowed("CustomTab"));
    /// A custom or standard application: a list of tab references with
    /// a description and a logo. API version 29.0 and earlier represent
    /// custom applications only.
    pub const CUSTOM_APPLICATION: MetadataType = MetadataType(Cow::Borrowed("CustomApplication"));
    /// The container of every custom label in the org. Salesforce only
    /// retrieves it whole: use it with [`PackageManifest::all`], since
    /// named members under `CustomLabels` do not select labels by
    /// name. Named labels, and the CRUD-based calls, take
    /// [`CUSTOM_LABEL`](Self::CUSTOM_LABEL).
    pub const CUSTOM_LABELS: MetadataType = MetadataType(Cow::Borrowed("CustomLabels"));
    /// One custom label. The type for retrieving labels by name
    /// (`add(MetadataType::CUSTOM_LABEL, ["quoteManual"])`) and for the
    /// CRUD-based calls; [`CUSTOM_LABELS`](Self::CUSTOM_LABELS) is the
    /// wildcard-only container.
    pub const CUSTOM_LABEL: MetadataType = MetadataType(Cow::Borrowed("CustomLabel"));
    /// A record of a custom metadata type.
    pub const CUSTOM_METADATA: MetadataType = MetadataType(Cow::Borrowed("CustomMetadata"));
    /// The translations of a custom object for a variety of languages.
    /// Translating component labels is part of the Translation
    /// Workbench.
    pub const CUSTOM_OBJECT_TRANSLATION: MetadataType =
        MetadataType(Cow::Borrowed("CustomObjectTranslation"));
    /// The translations for the supported languages. Translating
    /// component labels is part of the Translation Workbench.
    pub const TRANSLATIONS: MetadataType = MetadataType(Cow::Borrowed("Translations"));
    /// The set of values in a standard picklist field.
    pub const STANDARD_VALUE_SET: MetadataType = MetadataType(Cow::Borrowed("StandardValueSet"));
    /// A global picklist value set: the shared values custom picklist
    /// fields can use. It is not a field itself.
    pub const GLOBAL_VALUE_SET: MetadataType = MetadataType(Cow::Borrowed("GlobalValueSet"));
    /// A record type, which offers different business processes,
    /// picklist values and page layouts to different users. Defined for
    /// a custom object.
    pub const RECORD_TYPE: MetadataType = MetadataType(Cow::Borrowed("RecordType"));
    /// A page layout.
    pub const LAYOUT: MetadataType = MetadataType(Cow::Borrowed("Layout"));
    /// A list view, a filtered list of records. A list view set to
    /// "Visible only to me" is not accessible through the Metadata API.
    pub const LIST_VIEW: MetadataType = MetadataType(Cow::Borrowed("ListView"));
    /// A field set, a grouping of fields that Visualforce pages can
    /// reference dynamically.
    pub const FIELD_SET: MetadataType = MetadataType(Cow::Borrowed("FieldSet"));
    /// A validation rule, which verifies that the data a user enters in
    /// a record is valid and can be saved.
    pub const VALIDATION_RULE: MetadataType = MetadataType(Cow::Borrowed("ValidationRule"));
    /// A custom button or link defined in a custom object.
    pub const WEB_LINK: MetadataType = MetadataType(Cow::Borrowed("WebLink"));
    /// A create or update quick action for an object, made available in
    /// the Chatter publisher.
    pub const QUICK_ACTION: MetadataType = MetadataType(Cow::Borrowed("QuickAction"));

    // -- Security --
    /// A user profile, which defines a user's permission to perform
    /// different functions within Salesforce.
    pub const PROFILE: MetadataType = MetadataType(Cow::Borrowed("Profile"));
    /// A set of permissions that grants more access to one or more
    /// users without changing their profile. It grants access but
    /// cannot deny it.
    pub const PERMISSION_SET: MetadataType = MetadataType(Cow::Borrowed("PermissionSet"));
    /// A group of permission sets and the permissions within them, for
    /// organizing permissions by job function or task.
    pub const PERMISSION_SET_GROUP: MetadataType =
        MetadataType(Cow::Borrowed("PermissionSetGroup"));
    /// A role in the org.
    pub const ROLE: MetadataType = MetadataType(Cow::Borrowed("Role"));
    /// A set of public groups, which can have users, roles and other
    /// groups.
    pub const GROUP: MetadataType = MetadataType(Cow::Borrowed("Group"));
    /// A holding area for items before they are processed.
    pub const QUEUE: MetadataType = MetadataType(Cow::Borrowed("Queue"));
    /// The base container for sharing rules: criteria-based,
    /// ownership-based, territory-based or for guest user access.
    pub const SHARING_RULES: MetadataType = MetadataType(Cow::Borrowed("SharingRules"));

    // -- Process automation --
    /// A flow: its structure, logic and run-time behavior.
    pub const FLOW: MetadataType = MetadataType(Cow::Borrowed("Flow"));
    /// A flow's description and its active version number. From API
    /// version 44.0 Salesforce recommends activating and deactivating
    /// flows through [`FLOW`](Self::FLOW) instead.
    pub const FLOW_DEFINITION: MetadataType = MetadataType(Cow::Borrowed("FlowDefinition"));
    /// Workflow rules, which set workflow actions in motion when their
    /// conditions are met.
    pub const WORKFLOW: MetadataType = MetadataType(Cow::Borrowed("Workflow"));
    /// An approval process, which automates how records are approved:
    /// each step, who to request approval from, and what to do at each
    /// point.
    pub const APPROVAL_PROCESS: MetadataType = MetadataType(Cow::Borrowed("ApprovalProcess"));

    // -- Reporting --
    /// A custom report. Standard reports are not supported.
    pub const REPORT: MetadataType = MetadataType(Cow::Borrowed("Report"));
    /// A custom report type, the framework from which users create and
    /// customize reports.
    pub const REPORT_TYPE: MetadataType = MetadataType(Cow::Borrowed("ReportType"));
    /// A dashboard, a visual representation of data for seeing key
    /// metrics at a glance.
    pub const DASHBOARD: MetadataType = MetadataType(Cow::Borrowed("Dashboard"));
    /// A document. Every document must be in a document folder, as in
    /// `sampleFolder/TestDocument`.
    pub const DOCUMENT: MetadataType = MetadataType(Cow::Borrowed("Document"));
    /// A template for an email, mass email, list email or Sales
    /// Engagement email. Supported in first-generation managed packages
    /// only.
    pub const EMAIL_TEMPLATE: MetadataType = MetadataType(Cow::Borrowed("EmailTemplate"));

    // -- Lightning / static assets --
    /// A Lightning web component bundle, which contains the component's
    /// resources.
    pub const LIGHTNING_COMPONENT_BUNDLE: MetadataType =
        MetadataType(Cow::Borrowed("LightningComponentBundle"));
    /// An Aura definition bundle: one definition (component,
    /// application, event, interface or tokens collection) and its
    /// related resources.
    pub const AURA_DEFINITION_BUNDLE: MetadataType =
        MetadataType(Cow::Borrowed("AuraDefinitionBundle"));
    /// A static resource file, often a code library in a ZIP file, that
    /// Visualforce pages can reference. Usable only within the org.
    pub const STATIC_RESOURCE: MetadataType = MetadataType(Cow::Borrowed("StaticResource"));
    /// An asset file, which lets a Salesforce file be used for org
    /// setup and configuration purposes.
    pub const CONTENT_ASSET: MetadataType = MetadataType(Cow::Borrowed("ContentAsset"));

    // -- Integration / connected apps --
    /// A connected app, through which an external application
    /// integrates with Salesforce over protocols such as SAML, OAuth
    /// and OpenID Connect. Salesforce restricts creating new ones as of
    /// Spring '26 and recommends external client apps instead.
    pub const CONNECTED_APP: MetadataType = MetadataType(Cow::Borrowed("ConnectedApp"));
    /// A named credential: the URL of a callout endpoint and its
    /// authentication parameters in one definition.
    pub const NAMED_CREDENTIAL: MetadataType = MetadataType(Cow::Borrowed("NamedCredential"));
    /// An authentication provider, which lets users log in to
    /// Salesforce from an external service provider such as Facebook,
    /// Google or GitHub.
    pub const AUTH_PROVIDER: MetadataType = MetadataType(Cow::Borrowed("AuthProvider"));
    /// A remote site setting. An external site must be registered as
    /// one before Visualforce, Apex callouts or JavaScript
    /// XmlHttpRequest code can call it.
    pub const REMOTE_SITE_SETTING: MetadataType = MetadataType(Cow::Borrowed("RemoteSiteSetting"));
}

// -- Manifest ---------------------------------------------------------------

/// Builder for `package.xml` and the SOAP `unpackaged` retrieve
/// parameter.
///
/// Constructed via [`Self::new`], then chained: [`Self::add`] for
/// explicit member lists, [`Self::all`] for a `*` wildcard,
/// [`Self::full_name`] for managed-package manifests.
///
/// Insertion order is preserved — entries appear in the emitted XML
/// in the order they were added. Members within a type also preserve
/// caller order, with no de-duplication; the one exception is the `*`
/// wildcard, which is kept once and hoisted to the front of the type's
/// member list. Adding the same metadata type more than once merges
/// the member lists in order.
#[derive(Debug, Clone)]
pub struct PackageManifest {
    api_version: String,
    full_name: Option<String>,
    entries: Vec<TypeEntry>,
}

#[derive(Debug, Clone)]
struct TypeEntry {
    type_name: String,
    members: Vec<String>,
}

impl TypeEntry {
    // The <types> blocks this entry renders as. A `*` wildcard never
    // shares a block with explicit member names, so an entry carrying
    // both emits two blocks under the same <name>: the wildcard first,
    // then the named members.
    //
    // Salesforce documents that shape for standard objects, which a
    // `*` on CustomObject does not match: "You can only overwrite
    // these standard objects and fields by explicitly creating
    // separate types elements for the objects or fields."
    // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_profile.htm
    //
    // Two <types> blocks sharing a <name> is itself a documented
    // manifest shape — the "Custom and Standard Fields" sample emits
    // two <name>CustomField</name> blocks.
    // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/manifest_samples.htm
    fn blocks(&self) -> impl Iterator<Item = &[String]> {
        let (wildcard, explicit) = match self.members.split_first() {
            Some((first, rest)) if first == WILDCARD => (&self.members[..1], rest),
            _ => (&self.members[..0], self.members.as_slice()),
        };
        // An empty member list renders nothing at all: <types> without
        // <members> is invalid per Salesforce's schema.
        [wildcard, explicit]
            .into_iter()
            .filter(|block| !block.is_empty())
    }
}

/// The `members` value that stands for "every component of this type".
const WILDCARD: &str = "*";

/// Keeps a type's member list in the shape [`TypeEntry::blocks`]
/// expects: at most one `*`, positioned first. Explicit names keep
/// caller order and are not de-duplicated.
fn hoist_wildcard(members: &mut Vec<String>) {
    if members.iter().any(|m| m == WILDCARD) {
        members.retain(|m| m != WILDCARD);
        members.insert(0, WILDCARD.to_string());
    }
}

impl PackageManifest {
    /// Create a new empty manifest at the given API version.
    ///
    /// `api_version` is the Salesforce version string (e.g. `"66.0"`).
    /// It is emitted as the manifest's `<version>` element — in
    /// `package.xml` and in the SOAP `unpackaged` parameter alike.
    ///
    /// This is a separate value from
    /// [`RetrieveRequest::api_version`], which is emitted as the
    /// retrieve request's own `<apiVersion>` element. In API version
    /// 31.0 and later Salesforce uses the version specified in
    /// `package.xml` for the retrieve, overriding `<apiVersion>` — so
    /// keep the two in sync unless you specifically want the manifest
    /// version to win.
    ///
    /// [`RetrieveRequest::api_version`]: crate::RetrieveRequest::api_version
    pub fn new(api_version: impl Into<String>) -> Self {
        Self {
            api_version: api_version.into(),
            full_name: None,
            entries: Vec::new(),
        }
    }

    /// Set a `<fullName>` element — only meaningful for first- and
    /// second-generation packaged manifests (i.e. you're deploying a
    /// named managed-package). Omit for the much more common
    /// unpackaged case.
    pub fn full_name(mut self, name: impl Into<String>) -> Self {
        self.full_name = Some(name.into());
        self
    }

    /// Add components of one metadata type. If the type has already
    /// been added, the new members are appended to its existing list.
    ///
    /// A type may carry the `*` wildcard (from [`Self::all`] or an
    /// explicit `"*"` member) alongside named members. The two never
    /// share a `<types>` block: such a type renders as a wildcard block
    /// followed by a block of the named members, both under the same
    /// `<name>`. That is how Salesforce documents pulling in standard
    /// objects, which a `*` on `CustomObject` doesn't match. A repeated
    /// `"*"` is kept once.
    ///
    /// Each member name is the metadata component's `fullName` —
    /// `"Foo"` for `MetadataType::APEX_CLASS`, `"Account__c"` for
    /// `MetadataType::CUSTOM_OBJECT`, `"Account.MyField__c"` for
    /// `MetadataType::CUSTOM_FIELD`, etc.
    pub fn add<T, M, S>(mut self, type_name: T, members: M) -> Self
    where
        T: Into<MetadataType>,
        M: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let type_name: MetadataType = type_name.into();
        let new_members = members.into_iter().map(Into::into);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.type_name == type_name.as_str())
        {
            entry.members.extend(new_members);
            hoist_wildcard(&mut entry.members);
        } else {
            let mut members: Vec<String> = new_members.collect();
            hoist_wildcard(&mut members);
            self.entries.push(TypeEntry {
                type_name: type_name.as_str().to_string(),
                members,
            });
        }
        self
    }

    /// Add a metadata type with the `*` wildcard member, retrieving
    /// every component of that type.
    ///
    /// Explicit members added for the same type are kept: the wildcard
    /// renders as its own `<types>` block ahead of a second block
    /// holding the named members, both under the same `<name>`. That
    /// combination is how Salesforce documents including standard
    /// objects in a wildcarded `CustomObject` manifest — `*` doesn't
    /// match standard objects, so each one has to be named. Repeated
    /// `all` calls for the same type stay a single `"*"`.
    ///
    /// Not all metadata types support the wildcard —
    /// `StandardValueSet`, `RecordType`, `Report`, `Dashboard`,
    /// `Document` and `EmailTemplate` are among the types that must be
    /// listed by explicit `fullName`. Whether a given type accepts `*`
    /// is stated in the "Wildcard Support in the Manifest File" section
    /// of that type's reference page in the Metadata API Developer
    /// Guide; the [Metadata Types] page is the index of those pages and
    /// carries no wildcard column of its own. This builder doesn't
    /// validate, so a wildcard on a non-supporting type surfaces as a
    /// server-side error at deploy/retrieve time.
    ///
    /// [Metadata Types]: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_types_list.htm
    pub fn all<T: Into<MetadataType>>(self, type_name: T) -> Self {
        self.add(type_name, [WILDCARD])
    }

    /// Returns the API version this manifest targets.
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Returns the optional `<fullName>` for packaged manifests.
    pub fn full_name_str(&self) -> Option<&str> {
        self.full_name.as_deref()
    }

    /// Number of distinct metadata types in this manifest.
    pub fn type_count(&self) -> usize {
        self.entries.len()
    }

    /// Iterate over the distinct `(type_name, members)` pairs in
    /// insertion order. A type that carries both the `*` wildcard and
    /// named members yields one pair holding all of them, with the
    /// wildcard first; the split into two `<types>` blocks happens at
    /// render time.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.entries
            .iter()
            .map(|e| (e.type_name.as_str(), e.members.as_slice()))
    }

    /// Render as `package.xml` file content.
    ///
    /// The output is the canonical Salesforce form — XML declaration,
    /// `<Package>` element with the metadata namespace as default,
    /// one `<types>` block per metadata type with `<members>` before
    /// `<name>`, and a final `<version>`. Suitable for inclusion in a
    /// deploy zip. A type carrying both the `*` wildcard and named
    /// members emits two blocks under the same `<name>`.
    pub fn to_xml(&self) -> String {
        let mut out = String::with_capacity(128 + self.entries.len() * 64);
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str("<Package xmlns=\"http://soap.sforce.com/2006/04/metadata\">\n");
        if let Some(full) = &self.full_name {
            out.push_str("    <fullName>");
            out.push_str(&xml_escape(full));
            out.push_str("</fullName>\n");
        }
        for entry in &self.entries {
            for block in entry.blocks() {
                out.push_str("    <types>\n");
                for member in block {
                    out.push_str("        <members>");
                    out.push_str(&xml_escape(member));
                    out.push_str("</members>\n");
                }
                out.push_str("        <name>");
                out.push_str(&xml_escape(&entry.type_name));
                out.push_str("</name>\n");
                out.push_str("    </types>\n");
            }
        }
        out.push_str("    <version>");
        out.push_str(&xml_escape(&self.api_version));
        out.push_str("</version>\n");
        out.push_str("</Package>\n");
        out
    }

    /// Render the inner XML for a SOAP `<met:unpackaged>` element.
    ///
    /// Used internally by the retrieve handler — emits the same
    /// content as [`Self::to_xml`] but with the `met:` namespace
    /// prefix on every element and without the `<Package>` wrapper
    /// or XML declaration. Not exposed publicly because the only
    /// supported use is inside a SOAP retrieve envelope.
    pub(crate) fn render_soap_inner(&self) -> String {
        let mut out = String::with_capacity(64 + self.entries.len() * 64);
        if let Some(full) = &self.full_name {
            out.push_str("<met:fullName>");
            out.push_str(&xml_escape(full));
            out.push_str("</met:fullName>");
        }
        for entry in &self.entries {
            for block in entry.blocks() {
                out.push_str("<met:types>");
                for member in block {
                    out.push_str("<met:members>");
                    out.push_str(&xml_escape(member));
                    out.push_str("</met:members>");
                }
                out.push_str("<met:name>");
                out.push_str(&xml_escape(&entry.type_name));
                out.push_str("</met:name>");
                out.push_str("</met:types>");
            }
        }
        out.push_str("<met:version>");
        out.push_str(&xml_escape(&self.api_version));
        out.push_str("</met:version>");
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn metadata_type_constants_round_trip() {
        assert_eq!(MetadataType::APEX_CLASS.as_str(), "ApexClass");
        assert_eq!(MetadataType::CUSTOM_OBJECT.as_str(), "CustomObject");
        assert_eq!(MetadataType::PROFILE.as_str(), "Profile");
        assert_eq!(MetadataType::FLOW.as_str(), "Flow");
    }

    #[test]
    fn metadata_type_new_accepts_arbitrary_names() {
        let t = MetadataType::new("FrobnozzWidget");
        assert_eq!(t.as_str(), "FrobnozzWidget");
        let t2 = MetadataType::new(String::from("OwnedString"));
        assert_eq!(t2.as_str(), "OwnedString");
    }

    #[test]
    fn metadata_type_into_from_static_str() {
        let t: MetadataType = "MyType".into();
        assert_eq!(t.as_str(), "MyType");
    }

    /// `describe_metadata` hands back owned `xml_name`s; the obvious
    /// loop over them has to borrow-check without a clone per entry.
    #[test]
    fn metadata_type_converts_from_borrowed_strings() {
        let names = vec![String::from("Bot"), String::from("ApexClass")];
        let mut pkg = PackageManifest::new("66.0");
        for name in &names {
            pkg = pkg.all(name.as_str());
        }
        for name in &names {
            pkg = pkg.add(name, ["Explicit"]);
        }
        assert_eq!(pkg.type_count(), 2);
        let xml = pkg.to_xml();
        assert!(xml.contains("<name>Bot</name>"), "{xml}");
        assert!(xml.contains("<members>Explicit</members>"), "{xml}");

        assert_eq!(MetadataType::new(names[0].as_str()).as_str(), "Bot");
        let from_ref: MetadataType = (&MetadataType::APEX_CLASS).into();
        assert_eq!(from_ref, MetadataType::APEX_CLASS);
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_customlabels.htm
    /// "CustomLabels doesn't support retrieving one or more custom
    /// labels by name. To retrieve specific labels by name, use
    /// CustomLabel and specify the label names as members."
    #[test]
    fn custom_label_is_the_singular_type_for_named_members() {
        assert_eq!(MetadataType::CUSTOM_LABEL.as_str(), "CustomLabel");
        assert_eq!(MetadataType::CUSTOM_LABELS.as_str(), "CustomLabels");
        let xml = PackageManifest::new("66.0")
            .add(MetadataType::CUSTOM_LABEL, ["quoteManual", "quoteAuto"])
            .to_xml();
        assert!(xml.contains("<name>CustomLabel</name>"), "{xml}");
    }

    #[test]
    fn metadata_type_implements_display() {
        assert_eq!(MetadataType::APEX_CLASS.to_string(), "ApexClass");
    }

    #[test]
    fn manifest_empty_emits_just_version() {
        let pkg = PackageManifest::new("66.0");
        let xml = pkg.to_xml();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("<Package xmlns=\"http://soap.sforce.com/2006/04/metadata\">"));
        assert!(xml.contains("<version>66.0</version>"));
        assert!(xml.contains("</Package>"));
        // No <types> blocks for an empty manifest.
        assert!(!xml.contains("<types>"));
    }

    #[test]
    fn manifest_emits_types_in_insertion_order() {
        let pkg = PackageManifest::new("66.0")
            .add(MetadataType::APEX_CLASS, ["Foo", "Bar"])
            .add(MetadataType::CUSTOM_OBJECT, ["Account__c"]);
        let xml = pkg.to_xml();
        let i_apex = xml.find("<name>ApexClass</name>").unwrap();
        let i_obj = xml.find("<name>CustomObject</name>").unwrap();
        assert!(i_apex < i_obj);
        assert!(xml.contains("<members>Foo</members>"));
        assert!(xml.contains("<members>Bar</members>"));
        assert!(xml.contains("<members>Account__c</members>"));
    }

    #[test]
    fn manifest_merges_repeated_type_adds() {
        let pkg = PackageManifest::new("66.0")
            .add(MetadataType::APEX_CLASS, ["Foo"])
            .add(MetadataType::CUSTOM_OBJECT, ["Acct__c"])
            .add(MetadataType::APEX_CLASS, ["Bar", "Baz"]);
        let xml = pkg.to_xml();
        // ApexClass should appear once with all three members.
        assert_eq!(xml.matches("<name>ApexClass</name>").count(), 1);
        let apex_section = {
            let start = xml.find("<types>").unwrap();
            let end = xml[start..].find("</types>").unwrap() + start;
            &xml[start..=end]
        };
        assert!(apex_section.contains("Foo"));
        assert!(apex_section.contains("Bar"));
        assert!(apex_section.contains("Baz"));
        assert_eq!(pkg.type_count(), 2);
    }

    #[test]
    fn manifest_all_emits_wildcard_member() {
        let pkg = PackageManifest::new("66.0").all(MetadataType::CUSTOM_TAB);
        let xml = pkg.to_xml();
        assert!(xml.contains("<members>*</members>"));
        assert!(xml.contains("<name>CustomTab</name>"));
    }

    #[test]
    fn manifest_all_keeps_prior_explicit_members_in_a_second_block() {
        let pkg = PackageManifest::new("66.0")
            .add(MetadataType::APEX_CLASS, ["Foo", "Bar"])
            .all(MetadataType::APEX_CLASS);
        let xml = pkg.to_xml();
        // Two <types> blocks under one <name>: the wildcard on its own,
        // then the named members.
        assert_eq!(xml.matches("<name>ApexClass</name>").count(), 2);
        assert_eq!(xml.matches("<members>*</members>").count(), 1);
        assert!(xml.contains("<members>Foo</members>"));
        assert!(xml.contains("<members>Bar</members>"));
        let i_wildcard = xml.find("<members>*</members>").unwrap();
        let i_foo = xml.find("<members>Foo</members>").unwrap();
        assert!(i_wildcard < i_foo);
    }

    #[test]
    fn manifest_wildcard_plus_standard_object_renders_separate_blocks() {
        // `*` on CustomObject doesn't match standard objects; Salesforce
        // documents naming them in a separate <types> element.
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_profile.htm
        let pkg = PackageManifest::new("66.0")
            .all(MetadataType::CUSTOM_OBJECT)
            .add(MetadataType::CUSTOM_OBJECT, ["Account"])
            .all(MetadataType::PROFILE);
        let xml = pkg.to_xml();
        assert_eq!(xml.matches("<name>CustomObject</name>").count(), 2);
        assert!(xml.contains("<members>Account</members>"));
        assert_eq!(pkg.type_count(), 2);
        assert!(
            xml.contains(
                "    <types>\n        <members>*</members>\n        \
                 <name>CustomObject</name>\n    </types>\n    <types>\n        \
                 <members>Account</members>\n        <name>CustomObject</name>\n    </types>\n"
            ),
            "unexpected block layout:\n{xml}"
        );
    }

    #[test]
    fn manifest_repeated_all_collapses_to_single_wildcard() {
        let pkg = PackageManifest::new("66.0")
            .all(MetadataType::APEX_CLASS)
            .all(MetadataType::APEX_CLASS);
        let xml = pkg.to_xml();
        assert_eq!(xml.matches("<members>*</members>").count(), 1);
    }

    #[test]
    fn manifest_escapes_special_xml_chars_in_members() {
        let pkg = PackageManifest::new("66.0").add(MetadataType::APEX_CLASS, ["Foo<&>"]);
        let xml = pkg.to_xml();
        assert!(xml.contains("<members>Foo&lt;&amp;&gt;</members>"));
        assert!(!xml.contains("Foo<&>"));
    }

    #[test]
    fn manifest_skips_types_with_empty_member_lists() {
        // Edge case: add() with empty iterator. Emitting <types> with
        // no <members> is invalid per Salesforce's schema; skip
        // silently instead.
        let pkg = PackageManifest::new("66.0")
            .add(MetadataType::APEX_CLASS, Vec::<String>::new())
            .add(MetadataType::CUSTOM_OBJECT, ["Foo__c"]);
        let xml = pkg.to_xml();
        assert!(!xml.contains("<name>ApexClass</name>"));
        assert!(xml.contains("<name>CustomObject</name>"));
    }

    #[test]
    fn manifest_full_name_emitted_for_packaged_variant() {
        let pkg = PackageManifest::new("66.0")
            .full_name("MyManagedPackage")
            .add(MetadataType::APEX_CLASS, ["Foo"]);
        let xml = pkg.to_xml();
        assert!(xml.contains("<fullName>MyManagedPackage</fullName>"));
        // <fullName> must come before <types> per the WSDL.
        let i_full = xml.find("<fullName>").unwrap();
        let i_types = xml.find("<types>").unwrap();
        assert!(i_full < i_types);
    }

    #[test]
    fn manifest_accepts_arbitrary_string_type() {
        // Caller can use a type not in the constants list.
        let pkg =
            PackageManifest::new("66.0").add(MetadataType::new("ExperimentalType"), ["X1", "X2"]);
        let xml = pkg.to_xml();
        assert!(xml.contains("<name>ExperimentalType</name>"));
        assert!(xml.contains("<members>X1</members>"));
    }

    #[test]
    fn manifest_entries_iterator_preserves_order() {
        let pkg = PackageManifest::new("66.0")
            .add(MetadataType::APEX_CLASS, ["Foo"])
            .add(MetadataType::PROFILE, ["Admin"]);
        let entries: Vec<_> = pkg.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "ApexClass");
        assert_eq!(entries[0].1, &["Foo".to_string()]);
        assert_eq!(entries[1].0, "Profile");
        assert_eq!(entries[1].1, &["Admin".to_string()]);
    }

    #[test]
    fn soap_inner_uses_met_prefix() {
        let pkg = PackageManifest::new("66.0").add(MetadataType::APEX_CLASS, ["Foo"]);
        let inner = pkg.render_soap_inner();
        assert!(inner.contains("<met:types>"));
        assert!(inner.contains("<met:members>Foo</met:members>"));
        assert!(inner.contains("<met:name>ApexClass</met:name>"));
        assert!(inner.contains("<met:version>66.0</met:version>"));
        // No XML declaration, no <Package> wrapper.
        assert!(!inner.contains("<?xml"));
        assert!(!inner.contains("<Package"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    /// Names we'd realistically see as Salesforce metadata type or
    /// member identifiers — leading letter, then alphanumerics +
    /// underscore + dot (for the `Object.Field` syntax used by
    /// `CustomField`). 1-16 chars keeps shrinking fast.
    fn name() -> impl Strategy<Value = String> {
        "[A-Za-z][A-Za-z0-9_.]{0,15}"
    }

    /// One `(type, members)` add() input. Members may be empty —
    /// `add(t, [])` is legal and historically tested as a no-op for
    /// rendering but should still count toward the type list.
    fn add_op() -> impl Strategy<Value = (String, Vec<String>)> {
        (name(), proptest::collection::vec(name(), 0..4))
    }

    proptest! {
        /// For any sequence of `add(t, m)` calls, the number of
        /// distinct types added equals `type_count()`. Two `add`s
        /// with the same type *don't* produce two entries — the
        /// merge-on-existing behavior is the documented contract.
        #[test]
        fn add_groups_by_type_name(ops in proptest::collection::vec(add_op(), 0..8)) {
            let mut pkg = PackageManifest::new("66.0");
            let mut distinct = std::collections::BTreeSet::new();
            for (ty, members) in &ops {
                pkg = pkg.add(MetadataType::new(ty.clone()), members.clone());
                distinct.insert(ty.clone());
            }
            prop_assert_eq!(
                pkg.type_count(),
                distinct.len(),
                "type_count diverged from distinct-types set; ops={:?}",
                ops,
            );
        }

        /// `add` preserves insertion order on first-seen types.
        /// Re-adding an existing type doesn't reorder the entry list
        /// (the merge happens in-place at the existing entry's slot).
        /// This is the contract `entries()` advertises.
        #[test]
        fn entries_preserve_first_insertion_order(
            ops in proptest::collection::vec(add_op(), 0..8),
        ) {
            let mut pkg = PackageManifest::new("66.0");
            // Build the expected order: first occurrence of each type, in op order.
            let mut expected: Vec<String> = Vec::new();
            for (ty, members) in &ops {
                if !expected.contains(ty) {
                    expected.push(ty.clone());
                }
                pkg = pkg.add(MetadataType::new(ty.clone()), members.clone());
            }
            let actual: Vec<String> = pkg.entries().map(|(t, _)| t.to_string()).collect();
            prop_assert_eq!(actual, expected);
        }

        /// The mirror order of `all_after_add_hoists_wildcard`: once a
        /// type is wildcarded, later `add(t, m)` calls append `m` after
        /// the `"*"` in the same entry, so the wildcard-plus-named
        /// manifest stays expressible.
        #[test]
        fn add_after_all_appends_after_wildcard(
            ty in name(),
            extra_members in proptest::collection::vec(name(), 0..4),
        ) {
            let pkg = PackageManifest::new("66.0")
                .all(MetadataType::new(ty.clone()))
                .add(MetadataType::new(ty.clone()), extra_members.clone());
            let mut expected = vec!["*".to_string()];
            expected.extend(extra_members);
            let entries: Vec<_> = pkg.entries().collect();
            prop_assert_eq!(entries.len(), 1, "expected exactly one entry");
            prop_assert_eq!(entries[0].0, ty.as_str());
            prop_assert_eq!(entries[0].1, expected.as_slice());
        }

        /// An explicit `"*"` passed through `add` behaves like `all`:
        /// the wildcard is hoisted to the front of the member list and
        /// the named members are kept behind it.
        #[test]
        fn add_with_explicit_star_hoists_wildcard(
            ty in name(),
            extra_members in proptest::collection::vec(name(), 0..4),
        ) {
            let mut members = extra_members.clone();
            members.push("*".to_string());
            let pkg = PackageManifest::new("66.0")
                .add(MetadataType::new(ty.clone()), members);
            let mut expected = vec!["*".to_string()];
            expected.extend(extra_members);
            let entries: Vec<_> = pkg.entries().collect();
            prop_assert_eq!(entries.len(), 1, "expected exactly one entry");
            prop_assert_eq!(entries[0].1, expected.as_slice());
        }

        /// `all(t)` after `add(t, m)` puts the `"*"` ahead of `m`
        /// without dropping it, and repeated `all(t)` keeps exactly one
        /// wildcard.
        #[test]
        fn all_after_add_hoists_wildcard(
            ty in name(),
            extra_members in proptest::collection::vec(name(), 0..4),
        ) {
            let pkg = PackageManifest::new("66.0")
                .add(MetadataType::new(ty.clone()), extra_members.clone())
                .all(MetadataType::new(ty.clone()))
                .all(MetadataType::new(ty.clone()));
            let mut expected = vec!["*".to_string()];
            expected.extend(extra_members);
            let entries: Vec<_> = pkg.entries().collect();
            prop_assert_eq!(entries.len(), 1, "expected exactly one entry after all()");
            prop_assert_eq!(entries[0].0, ty.as_str());
            prop_assert_eq!(entries[0].1, expected.as_slice());
        }

        /// Every entry renders as one `<types>` block, or two when the
        /// type carries the wildcard alongside named members.
        #[test]
        fn each_type_renders_one_block_per_member_kind(
            ops in proptest::collection::vec(add_op(), 0..8),
            wildcarded in proptest::collection::vec(name(), 0..3),
        ) {
            let mut pkg = PackageManifest::new("66.0");
            for (ty, members) in &ops {
                pkg = pkg.add(MetadataType::new(ty.clone()), members.clone());
            }
            for ty in &wildcarded {
                pkg = pkg.all(MetadataType::new(ty.clone()));
            }
            let expected: usize = pkg
                .entries()
                .map(|(_, members)| match members {
                    [] => 0,
                    [first, rest @ ..] if first == "*" && !rest.is_empty() => 2,
                    _ => 1,
                })
                .sum();
            let xml = pkg.to_xml();
            prop_assert_eq!(xml.matches("<types>").count(), expected);
            prop_assert_eq!(
                pkg.render_soap_inner().matches("<met:types>").count(),
                expected
            );
        }

        /// `to_xml()` always emits `<version>` regardless of the
        /// add sequence. The version is the only field Salesforce
        /// requires unconditionally in `package.xml`.
        #[test]
        fn to_xml_always_emits_version(
            api_version in "[0-9]{1,3}\\.[0-9]{1,2}",
            ops in proptest::collection::vec(add_op(), 0..6),
        ) {
            let mut pkg = PackageManifest::new(&api_version);
            for (ty, members) in &ops {
                pkg = pkg.add(MetadataType::new(ty.clone()), members.clone());
            }
            let xml = pkg.to_xml();
            let expected = format!("<version>{api_version}</version>");
            prop_assert!(
                xml.contains(&expected),
                "package.xml missing <version> tag with {api_version:?}; got:\n{xml}",
            );
            // Sanity: well-formed enough that quick-xml can stream it
            // without erroring.
            let mut reader = quick_xml::Reader::from_str(&xml);
            loop {
                match reader.read_event() {
                    Ok(quick_xml::events::Event::Eof) => break,
                    Ok(_) => {}
                    Err(e) => prop_assert!(false, "package.xml didn't parse: {e}; xml={xml}"),
                }
            }
        }
    }
}
