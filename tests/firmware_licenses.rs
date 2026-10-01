//! The vendored firmware licence texts (`firmware-licenses/`) are consistent
//! with the vendored `WHENCE` excerpt that maps shipped firmware to them.
//!
//! The image build checks that every shipped firmware file is listed in that
//! `WHENCE`; this test checks the other half — that every licence text those
//! stanzas cite is present, and that nothing unreferenced rides along — and runs
//! in CI, where the image is not built.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// Files in `firmware-licenses/` that are not licence texts.
const NOT_LICENCES: [&str; 2] = ["README.md", "WHENCE"];

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("firmware-licenses")
}

/// Every `LICENCE.*` / `LICENSE.*` name the vendored WHENCE cites.
fn cited_licences() -> BTreeSet<String> {
    let whence = fs::read_to_string(dir().join("WHENCE")).expect("firmware-licenses/WHENCE");
    whence
        .split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')')
        .map(|w| w.trim_end_matches('.'))
        .filter(|w| w.starts_with("LICENCE.") || w.starts_with("LICENSE."))
        .map(str::to_string)
        .collect()
}

#[test]
fn every_cited_licence_text_is_vendored() {
    let cited = cited_licences();
    assert!(!cited.is_empty(), "the vendored WHENCE cites no licence");
    for name in &cited {
        let path = dir().join(name);
        let len = fs::metadata(&path)
            .unwrap_or_else(|_| {
                panic!("WHENCE cites {name}, but firmware-licenses/{name} is missing")
            })
            .len();
        assert!(len > 0, "firmware-licenses/{name} is empty");
    }
}

#[test]
fn no_uncited_licence_text_is_vendored() {
    let cited = cited_licences();
    for entry in fs::read_dir(dir()).expect("firmware-licenses/") {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if NOT_LICENCES.contains(&name.as_str()) {
            continue;
        }
        assert!(
            cited.contains(&name),
            "firmware-licenses/{name} is not cited by the vendored WHENCE"
        );
    }
}
