//! beskar7-inspector library crate.
//!
//! Houses the contract-facing types and the modules the PID 1 init composes:
//! cmdline parsing, hardware probing, the verified-TLS callback client, target
//! image fetch + whole-disk deploy, ESP and `COS_OEM` location, and target-disk
//! selection. The binary (`src/main.rs`) is a thin PID 1 orchestrator over
//! [`run`], so every module is unit- and contract-testable without booting a
//! ramdisk.

pub mod client;
pub mod cmdline;
pub mod deploy;
pub mod esp;
pub mod image;
pub mod modules;
pub mod net;
pub mod oem;
pub mod probe;
pub mod report;
pub mod run;
pub mod secret;
pub mod smbios;
pub mod target_disk;

/// The controller↔inspector contract version this build implements
/// (`docs/inspector-contract.md` in the beskar7 repo).
///
/// Changing the wire format, auth, endpoints, or cmdline parameters is a
/// contract version change that must be coordinated across both repos and the
/// shared golden fixture (see that document's "Versioning and anti-drift").
pub const CONTRACT_VERSION: &str = "v4.2";
