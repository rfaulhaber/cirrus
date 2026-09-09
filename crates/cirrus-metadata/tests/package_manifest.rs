//! End-to-end tests for [`PackageManifest`] — exercising both forms
//! (standalone `package.xml` and SOAP `unpackaged`) and confirming
//! quick-xml can round-trip the standalone output.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cirrus_metadata::{MetadataType, PackageManifest};
use quick_xml::Reader;
use quick_xml::escape::unescape;
use quick_xml::events::Event;

#[test]
fn to_xml_is_well_formed_and_parses() {
    let pkg = PackageManifest::new("66.0")
        .add(MetadataType::APEX_CLASS, ["Foo", "Bar"])
        .add(MetadataType::CUSTOM_OBJECT, ["Account__c"])
        .all(MetadataType::CUSTOM_TAB);

    let xml = pkg.to_xml();

    // Sanity-check by walking the document with a real XML parser.
    // If the manifest emits malformed XML, read_event() will return
    // Err on the bad token.
    let mut reader = Reader::from_str(&xml);
    let mut depth: i32 = 0;
    let mut saw_package = false;
    let mut saw_version = false;
    let mut type_names = Vec::new();
    let mut members = Vec::new();
    let mut current_tag: Option<Vec<u8>> = None;

    loop {
        match reader.read_event().unwrap() {
            Event::Start(e) => {
                depth += 1;
                let local = e.name().local_name().as_ref().to_vec();
                if local == b"Package" {
                    saw_package = true;
                }
                current_tag = Some(local);
            }
            Event::End(_) => {
                depth -= 1;
                current_tag = None;
            }
            Event::Text(t) => {
                if let Some(tag) = &current_tag {
                    let text = unescape(&t.decode().unwrap()).unwrap().into_owned();
                    if tag == b"name" {
                        type_names.push(text);
                    } else if tag == b"members" {
                        members.push(text);
                    } else if tag == b"version" {
                        assert_eq!(text, "66.0");
                        saw_version = true;
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    assert!(saw_package, "missing <Package> root");
    assert!(saw_version, "missing <version> element");
    assert_eq!(depth, 0, "unbalanced elements");
    assert_eq!(
        type_names,
        vec![
            "ApexClass".to_string(),
            "CustomObject".to_string(),
            "CustomTab".to_string()
        ]
    );
    assert!(members.contains(&"Foo".to_string()));
    assert!(members.contains(&"Bar".to_string()));
    assert!(members.contains(&"Account__c".to_string()));
    assert!(members.contains(&"*".to_string()));
}

#[test]
fn to_xml_handles_special_characters_safely() {
    // Member names with XML-reserved chars must be escaped — passing
    // the rendered output through quick-xml shouldn't fail on the
    // ampersand or angle brackets.
    let pkg = PackageManifest::new("66.0").add(MetadataType::APEX_CLASS, ["A&B", "C<D>E"]);
    let xml = pkg.to_xml();
    let mut reader = Reader::from_str(&xml);
    // Walk without panicking; that's the assertion.
    while reader.read_event().unwrap() != Event::Eof {}
    assert!(xml.contains("A&amp;B"));
    assert!(xml.contains("C&lt;D&gt;E"));
}

#[test]
fn empty_manifest_renders_minimal_valid_xml() {
    let pkg = PackageManifest::new("58.0");
    let xml = pkg.to_xml();
    let mut reader = Reader::from_str(&xml);
    let mut depth: i32 = 0;
    loop {
        match reader.read_event().unwrap() {
            Event::Start(_) => depth += 1,
            Event::End(_) => depth -= 1,
            Event::Eof => break,
            _ => {}
        }
    }
    assert_eq!(depth, 0);
    assert!(xml.contains("<version>58.0</version>"));
}

#[test]
fn packaged_manifest_emits_full_name_before_types() {
    let pkg = PackageManifest::new("66.0")
        .full_name("MyManagedPkg")
        .add(MetadataType::APEX_CLASS, ["Foo"]);

    let xml = pkg.to_xml();
    let mut reader = Reader::from_str(&xml);
    let mut element_order = Vec::new();
    loop {
        match reader.read_event().unwrap() {
            Event::Start(e) => {
                let local = e.name().local_name().as_ref().to_vec();
                element_order.push(local);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    // Find positions of <fullName>, <types>, <version> at top level.
    let i_full = element_order.iter().position(|t| t == b"fullName").unwrap();
    let i_types = element_order.iter().position(|t| t == b"types").unwrap();
    let i_version = element_order.iter().position(|t| t == b"version").unwrap();
    assert!(i_full < i_types);
    assert!(i_types < i_version);
}

#[test]
fn wildcard_and_named_members_render_as_separate_types_blocks() {
    // A `*` on CustomObject doesn't match standard objects, so the way
    // to retrieve profile permissions for both every custom object and
    // the standard Account object is a separate <types> element naming
    // Account. The manifest below is the union of the two package.xml
    // samples on that page; combining samples into one manifest is
    // documented on manifest_samples.htm.
    // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_profile.htm
    // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/manifest_samples.htm
    let pkg = PackageManifest::new("67.0")
        .all(MetadataType::CUSTOM_OBJECT)
        .add(MetadataType::CUSTOM_OBJECT, ["Account"])
        .all(MetadataType::PROFILE);

    let xml = pkg.to_xml();

    // Walk the document, collecting each <types> block as
    // (name, members) so the assertion is about parsed structure
    // rather than substring positions.
    let mut reader = Reader::from_str(&xml);
    let mut blocks: Vec<(String, Vec<String>)> = Vec::new();
    let mut members: Vec<String> = Vec::new();
    let mut name: Option<String> = None;
    let mut current_tag: Option<Vec<u8>> = None;
    loop {
        match reader.read_event().unwrap() {
            Event::Start(e) => current_tag = Some(e.name().local_name().as_ref().to_vec()),
            Event::Text(t) => {
                let text = unescape(&t.decode().unwrap()).unwrap().into_owned();
                match current_tag.as_deref() {
                    Some(b"members") => members.push(text),
                    Some(b"name") => name = Some(text),
                    _ => {}
                }
            }
            Event::End(e) => {
                if e.name().local_name().as_ref() == b"types" {
                    blocks.push((name.take().unwrap(), std::mem::take(&mut members)));
                }
                current_tag = None;
            }
            Event::Eof => break,
            _ => {}
        }
    }

    assert_eq!(
        blocks,
        vec![
            ("CustomObject".to_string(), vec!["*".to_string()]),
            ("CustomObject".to_string(), vec!["Account".to_string()]),
            ("Profile".to_string(), vec!["*".to_string()]),
        ]
    );
    // The builder still reports one entry per metadata type.
    assert_eq!(pkg.type_count(), 2);
}
