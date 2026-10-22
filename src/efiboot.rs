//! Register a UEFI boot entry for the freshly-written disk — what `efibootmgr`
//! does, done natively over `efivarfs` (the initramfs has no shell or helpers).
//!
//! The first reboot after the whole-disk write has no NVRAM boot entry for the new
//! disk. [`ensure_disk_boot_entry`] gives it one, then places it in `BootOrder`:
//!   1. **Reuse** an active `Boot####` that starts exactly what was just written:
//!      its `HD()` node names the ESP (unique GUID, partition number, start and
//!      size all match the GPT), and its `File()` path is [`ESP_LOADER_PATH`]
//!      (ignoring case, FAT is case-insensitive) or absent (a path ending at the
//!      partition boots that same removable-media loader). That is the firmware's
//!      own entry for the disk, or the one a previous attempt created. An entry
//!      for the same GUID that starts another file (a distro loader, or a loader
//!      of an earlier image built from the same base) is not reused.
//!   2. Otherwise write a short-form
//!      `HD(<n>,GPT,<guid>,<start>,<size>)/File(`[`ESP_LOADER_PATH`]`)` entry, the
//!      shape `efibootmgr` writes by default. It **replaces** an existing entry
//!      described `beskar7` (the lowest-numbered one), so redeploying images with
//!      different ESP GUIDs doesn't pile up dead entries in a small NVRAM; only when
//!      there is none is the lowest free `Boot####` **created**.
//!   3. Move it in `BootOrder` to **right after the network entries that lead the
//!      boot order** (device paths with a MAC, IPv4, IPv6 or URI node), counting
//!      only entries the firmware would boot on its own: active, BOOT category.
//!      Inactive and APP-category entries (setup, boot menu, often the shell) and
//!      numbers with no `Boot####` keep their places and are skipped over. When the
//!      first bootable entry isn't network, the disk goes right before it. PXE
//!      keeps the priority it had; when it didn't come first, the controller's
//!      one-time network-boot override already handles reprovisioning.
//!
//! ## Writing variables
//! An `efivarfs` file holds the 4-byte attributes followed by the value, and a
//! write must hand both to the kernel in **one** `write(2)`. A variable the kernel
//! marks immutable has `FS_IMMUTABLE_FL` cleared first, as libefivar does. Any
//! failure is returned as [`EfiBootError`]; the caller logs it and carries on,
//! since a firmware that refuses `SetVariable` (boot order locked in setup, full
//! NVRAM) still finds the removable-media loader on its own.
//!
//! ## Secret hygiene (§9)
//! No secrets pass through here. [`EfiBootError`] carries only variable names and
//! I/O errors.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use nix::errno::Errno;
use nix::mount::{mount, MsFlags};

use crate::deploy::ESP_LOADER_PATH;
use crate::esp::{EspPartition, GptEsp};

/// Where the kernel exposes `efivarfs` (the directory exists when booted via UEFI).
const EFIVARFS_MOUNT: &str = "/sys/firmware/efi/efivars";
/// `EFI_GLOBAL_VARIABLE`, the vendor GUID of `Boot####` and `BootOrder`.
const EFI_GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
/// `NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS`: the attributes every boot
/// variable carries.
const EFI_VARIABLE_ATTRS: u32 = 0x07;
/// `LOAD_OPTION_ACTIVE`: the firmware only boots active load options.
const LOAD_OPTION_ACTIVE: u32 = 0x01;
/// `LOAD_OPTION_CATEGORY` mask. `0` is `CATEGORY_BOOT`, the only category the
/// firmware boots on its own; `CATEGORY_APP` (`0x100`) entries run only when picked
/// from a menu.
const LOAD_OPTION_CATEGORY: u32 = 0x1F00;
/// The description of the entry the inspector creates (shown in the boot menu).
const DESCRIPTION: &str = "beskar7";
/// `FS_IMMUTABLE_FL`, from `linux/fs.h`.
const FS_IMMUTABLE_FL: nix::libc::c_int = 0x10;

// FS_IOC_GETFLAGS / FS_IOC_SETFLAGS are declared _IOR/_IOW('f', 1/2, long), but the
// kernel reads and writes an int — so the request codes use long's size, the
// argument is an int (as e2fsprogs and libefivar pass it).
nix::ioctl_read_bad!(
    fs_ioc_getflags,
    nix::request_code_read!(b'f', 1, std::mem::size_of::<nix::libc::c_long>()),
    nix::libc::c_int
);
nix::ioctl_write_ptr_bad!(
    fs_ioc_setflags,
    nix::request_code_write!(b'f', 2, std::mem::size_of::<nix::libc::c_long>()),
    nix::libc::c_int
);

/// Device-path node types and subtypes this module builds or recognises (UEFI
/// spec §10.3).
const DP_MESSAGING: u8 = 0x03;
const DP_MEDIA: u8 = 0x04;
const DP_END: u8 = 0x7F;
const DP_MEDIA_HD: u8 = 0x01;
const DP_MEDIA_FILE: u8 = 0x04;
const DP_END_ENTIRE: u8 = 0xFF;
/// Messaging subtypes that mark a network boot entry: MAC, IPv4, IPv6, URI.
const DP_NETWORK_SUBTYPES: [u8; 4] = [11, 12, 13, 24];
/// HD node: `MBRType` 0x02 (GPT) and `SignatureType` 0x02 (GUID).
const HD_GPT: u8 = 0x02;
/// HD node total length: header (4) + partition number (4) + start (8) + size (8)
/// + signature (16) + MBR type (1) + signature type (1).
const HD_NODE_LEN: u16 = 42;

/// Why the boot entry could not be registered. Every variant carries only
/// variable names and I/O errors — nothing secret.
#[derive(Debug, thiserror::Error)]
pub enum EfiBootError {
    /// Mounting `efivarfs` failed (e.g. the `efivarfs` module is missing).
    #[error("mounting efivarfs at {EFIVARFS_MOUNT}")]
    Mount(#[source] Errno),
    /// Listing the `efivarfs` variables failed.
    #[error("listing the UEFI variables")]
    ListVars(#[source] io::Error),
    /// Reading a UEFI variable failed.
    #[error("reading UEFI variable {name}")]
    ReadVar {
        /// The variable name (e.g. `BootOrder`).
        name: String,
        /// The underlying read error.
        #[source]
        source: io::Error,
    },
    /// Writing a UEFI variable failed (the firmware's `SetVariable` refused it, or
    /// the write was short).
    #[error("writing UEFI variable {name}")]
    WriteVar {
        /// The variable name (e.g. `Boot0003`).
        name: String,
        /// The underlying write error.
        #[source]
        source: io::Error,
    },
    /// `BootOrder` is not a whole number of 16-bit entries.
    #[error("the UEFI BootOrder variable is malformed")]
    BadBootOrder,
    /// All 65536 `Boot####` numbers are taken.
    #[error("no free Boot#### number")]
    NoFreeEntry,
}

/// How the boot entry was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A new `Boot####` was written.
    Created,
    /// An existing entry already starts the disk's loader; nothing was written.
    Reused,
    /// The previous `beskar7` entry was overwritten for this disk.
    Replaced,
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Outcome::Created => "created",
            Outcome::Reused => "reused",
            Outcome::Replaced => "replaced",
        })
    }
}

/// The registered boot entry.
#[derive(Debug, PartialEq, Eq)]
pub struct BootEntry {
    /// The `Boot####` number.
    pub number: u16,
    /// Whether it was created, reused or replaced.
    pub outcome: Outcome,
    /// `BootOrder` as the firmware had it before this run.
    pub previous_order: Vec<u16>,
    /// The resulting `BootOrder`.
    pub boot_order: Vec<u16>,
}

/// A parsed `EFI_LOAD_OPTION` (the value of a `Boot####` variable).
#[derive(Clone, Debug, PartialEq, Eq)]
struct LoadOption {
    attributes: u32,
    description: String,
    device_path: Vec<u8>,
}

/// The fields of a GPT `HD()` device-path node.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HdNode {
    number: u32,
    start: u64,
    size: u64,
    guid: [u8; 16],
}

impl HdNode {
    /// Whether this node names exactly the partition `gpt` describes.
    fn is(&self, gpt: &GptEsp) -> bool {
        self.guid == gpt.unique_guid
            && self.number == gpt.number
            && self.start == gpt.first_lba
            && self.size == gpt.size_lba()
    }
}

impl LoadOption {
    fn is_active(&self) -> bool {
        self.attributes & LOAD_OPTION_ACTIVE != 0
    }

    /// Whether the firmware would boot this entry on its own: active and BOOT
    /// category. `LOAD_OPTION_HIDDEN` only hides it from the menu, so it doesn't
    /// matter here.
    fn is_auto_bootable(&self) -> bool {
        self.is_active() && self.attributes & LOAD_OPTION_CATEGORY == 0
    }

    /// The first GPT `HD()` node of the device path.
    fn hd(&self) -> Option<HdNode> {
        device_path_nodes(&self.device_path)
            .into_iter()
            .find_map(|(ty, sub, data)| {
                // data: number 0..4, start 4..12, size 12..20, signature 20..36,
                // MBR type 36, signature type 37.
                (ty == DP_MEDIA && sub == DP_MEDIA_HD && data.len() >= 38 && data[37] == HD_GPT)
                    .then(|| HdNode {
                        number: u32::from_le_bytes(data[0..4].try_into().unwrap()),
                        start: u64::from_le_bytes(data[4..12].try_into().unwrap()),
                        size: u64::from_le_bytes(data[12..20].try_into().unwrap()),
                        guid: data[20..36].try_into().unwrap(),
                    })
            })
    }

    /// The file the entry starts on its partition: the `File()` nodes after the
    /// `HD()` node, joined (UEFI allows a path split across several nodes) with
    /// backslashes normalized and a leading `\`. `None` when the path ends at the
    /// partition, which boots its removable-media loader.
    fn loader_path(&self) -> Option<String> {
        let nodes = device_path_nodes(&self.device_path);
        let after_hd = nodes
            .iter()
            .position(|&(ty, sub, _)| ty == DP_MEDIA && sub == DP_MEDIA_HD)?
            + 1;
        let parts: Vec<String> = nodes[after_hd..]
            .iter()
            .take_while(|&&(ty, sub, _)| ty == DP_MEDIA && sub == DP_MEDIA_FILE)
            .map(|&(_, _, data)| ucs2_until_nul(data))
            .collect();
        if parts.is_empty() {
            return None;
        }
        let mut path = String::new();
        for part in parts.iter().flat_map(|p| p.split(['\\', '/'])) {
            if !part.is_empty() {
                path.push('\\');
                path.push_str(part);
            }
        }
        Some(path)
    }
}

/// Access to the UEFI variables under the global vendor GUID, by bare name
/// (`Boot0001`, `BootOrder`). The live store is `efivarfs`; tests use a map.
trait VarStore {
    /// The bare names of every global-GUID variable.
    fn list(&self) -> io::Result<Vec<String>>;
    /// A variable's value (without the attribute bytes), or `None` if unset.
    fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>>;
    /// Set a variable to `value` with [`EFI_VARIABLE_ATTRS`].
    fn write(&self, name: &str, value: &[u8]) -> io::Result<()>;
}

/// Register a boot entry for `esp` and place it after the network entries (see
/// the module docs). Mounts `efivarfs` first; the caller only calls this when the
/// host booted via UEFI.
pub fn ensure_disk_boot_entry(esp: &EspPartition) -> Result<BootEntry, EfiBootError> {
    mount_efivarfs()?;
    ensure_in(
        &EfivarFs {
            dir: PathBuf::from(EFIVARFS_MOUNT),
        },
        &esp.gpt,
    )
}

/// Mount `efivarfs` at [`EFIVARFS_MOUNT`] (`nodev,nosuid,noexec`). `EBUSY` means it
/// is already mounted.
fn mount_efivarfs() -> Result<(), EfiBootError> {
    let flags = MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;
    match mount(
        Some("efivarfs"),
        EFIVARFS_MOUNT,
        Some("efivarfs"),
        flags,
        None::<&str>,
    ) {
        Ok(()) | Err(Errno::EBUSY) => Ok(()),
        Err(source) => Err(EfiBootError::Mount(source)),
    }
}

/// The reuse / replace / create + reorder logic over any [`VarStore`].
fn ensure_in(store: &impl VarStore, gpt: &GptEsp) -> Result<BootEntry, EfiBootError> {
    let (entries, used) = read_boot_entries(store)?;
    let previous_order = match store
        .read("BootOrder")
        .map_err(|source| EfiBootError::ReadVar {
            name: "BootOrder".into(),
            source,
        })? {
        Some(raw) => parse_boot_order(&raw).ok_or(EfiBootError::BadBootOrder)?,
        None => Vec::new(),
    };

    let (number, outcome) = match pick_existing(&entries, gpt, ESP_LOADER_PATH) {
        Some(n) => (n, Outcome::Reused),
        None => {
            let (n, outcome) = match previous_entry(&entries) {
                Some(n) => (n, Outcome::Replaced),
                None => (
                    free_boot_number(&used).ok_or(EfiBootError::NoFreeEntry)?,
                    Outcome::Created,
                ),
            };
            let dp = hd_file_device_path(gpt, ESP_LOADER_PATH);
            let name = boot_var_name(n);
            store
                .write(
                    &name,
                    &encode_load_option(LOAD_OPTION_ACTIVE, DESCRIPTION, &dp),
                )
                .map_err(|source| EfiBootError::WriteVar { name, source })?;
            (n, outcome)
        }
    };

    let option = |n: u16| entries.iter().find(|(m, _)| *m == n).map(|(_, o)| o);
    let boot_order = place_after_network(
        &previous_order,
        number,
        |n| option(n).is_some_and(LoadOption::is_auto_bootable),
        |n| option(n).is_some_and(|o| is_network(&o.device_path)),
    );
    if boot_order != previous_order {
        store
            .write("BootOrder", &encode_boot_order(&boot_order))
            .map_err(|source| EfiBootError::WriteVar {
                name: "BootOrder".into(),
                source,
            })?;
    }

    Ok(BootEntry {
        number,
        outcome,
        previous_order,
        boot_order,
    })
}

/// Every `Boot####` that parses as a load option, plus every `Boot####` number in
/// use (a malformed entry is never matched, but its number is never reused).
#[allow(clippy::type_complexity)]
fn read_boot_entries(
    store: &impl VarStore,
) -> Result<(Vec<(u16, LoadOption)>, Vec<u16>), EfiBootError> {
    let mut entries = Vec::new();
    let mut used = Vec::new();
    for name in store.list().map_err(EfiBootError::ListVars)? {
        let Some(n) = parse_boot_var_name(&name) else {
            continue;
        };
        used.push(n);
        let value = store.read(&name).map_err(|source| EfiBootError::ReadVar {
            name: name.clone(),
            source,
        })?;
        if let Some(opt) = value.as_deref().and_then(parse_load_option) {
            entries.push((n, opt));
        }
    }
    entries.sort_by_key(|(n, _)| *n);
    used.sort_unstable();
    Ok((entries, used))
}

/// `Boot####` for `n` (four uppercase hex digits, as the UEFI spec names them).
fn boot_var_name(n: u16) -> String {
    format!("Boot{n:04X}")
}

/// The number of a `Boot####` variable name, or `None` for any other variable
/// (`BootOrder`, `BootCurrent`, …).
fn parse_boot_var_name(name: &str) -> Option<u16> {
    let hex = name.strip_prefix("Boot")?;
    if hex.len() != 4 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(hex, 16).ok()
}

/// The lowest-numbered **active** entry that starts `loader` on exactly the
/// partition `gpt` describes (see the module docs) — the one to reuse.
fn pick_existing(entries: &[(u16, LoadOption)], gpt: &GptEsp, loader: &str) -> Option<u16> {
    entries
        .iter()
        .filter(|(_, opt)| {
            opt.is_active()
                && opt.hd().is_some_and(|hd| hd.is(gpt))
                && opt
                    .loader_path()
                    .is_none_or(|p| p.eq_ignore_ascii_case(loader))
        })
        .map(|(n, _)| *n)
        .min()
}

/// The lowest-numbered entry described [`DESCRIPTION`]: the one a previous deploy
/// wrote, to overwrite rather than allocate another number.
fn previous_entry(entries: &[(u16, LoadOption)]) -> Option<u16> {
    entries
        .iter()
        .filter(|(_, opt)| opt.description == DESCRIPTION)
        .map(|(n, _)| *n)
        .min()
}

/// The lowest `Boot####` number not in `used`.
fn free_boot_number(used: &[u16]) -> Option<u16> {
    (0..=u16::MAX).find(|n| !used.contains(n))
}

/// `order` with `n` moved to right after the network entries that lead it. Only
/// entries the firmware would boot on its own (`bootable`) count: the disk goes
/// right before the first bootable entry that isn't network (`is_net`), or right
/// after the last bootable network entry when none follows. Every other entry
/// keeps its place.
fn place_after_network(
    order: &[u16],
    n: u16,
    bootable: impl Fn(u16) -> bool,
    is_net: impl Fn(u16) -> bool,
) -> Vec<u16> {
    let mut out: Vec<u16> = order.iter().copied().filter(|&e| e != n).collect();
    let first_other = out
        .iter()
        .position(|&e| bootable(e) && !is_net(e))
        .unwrap_or(out.len());
    let at = out[..first_other]
        .iter()
        .rposition(|&e| bootable(e) && is_net(e))
        .map_or(first_other, |i| i + 1);
    out.insert(at, n);
    out
}

/// `BootOrder` is an array of little-endian `u16`; `None` on an odd length.
fn parse_boot_order(raw: &[u8]) -> Option<Vec<u16>> {
    if raw.len() % 2 != 0 {
        return None;
    }
    Some(
        raw.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect(),
    )
}

fn encode_boot_order(order: &[u16]) -> Vec<u8> {
    order.iter().flat_map(|n| n.to_le_bytes()).collect()
}

/// UCS-2 (little-endian) `data` up to its first NUL.
fn ucs2_until_nul(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// `s` as NUL-terminated UCS-2 (little-endian).
fn ucs2_nul(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// The short-form device path `HD(<n>,GPT,<guid>,<start>,<size>)/File(<loader>)`
/// followed by the End-Entire node.
fn hd_file_device_path(gpt: &GptEsp, loader: &str) -> Vec<u8> {
    let mut dp = Vec::new();
    dp.extend([DP_MEDIA, DP_MEDIA_HD]);
    dp.extend(HD_NODE_LEN.to_le_bytes());
    dp.extend(gpt.number.to_le_bytes());
    dp.extend(gpt.first_lba.to_le_bytes());
    dp.extend(gpt.size_lba().to_le_bytes());
    dp.extend(gpt.unique_guid);
    dp.extend([HD_GPT, HD_GPT]);

    let path = ucs2_nul(loader);
    dp.extend([DP_MEDIA, DP_MEDIA_FILE]);
    dp.extend((4 + path.len() as u16).to_le_bytes());
    dp.extend(path);

    dp.extend([DP_END, DP_END_ENTIRE, 0x04, 0x00]);
    dp
}

/// An `EFI_LOAD_OPTION`: attributes, `FilePathListLength`, the NUL-terminated
/// UCS-2 description, then the device path (no optional data).
fn encode_load_option(attributes: u32, description: &str, device_path: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(attributes.to_le_bytes());
    out.extend((device_path.len() as u16).to_le_bytes());
    out.extend(ucs2_nul(description));
    out.extend(device_path);
    out
}

/// Parse an `EFI_LOAD_OPTION`; `None` if it is truncated or its description is
/// unterminated.
fn parse_load_option(raw: &[u8]) -> Option<LoadOption> {
    let attributes = u32::from_le_bytes(raw.get(0..4)?.try_into().ok()?);
    let dp_len = u16::from_le_bytes(raw.get(4..6)?.try_into().ok()?) as usize;
    let mut units = Vec::new();
    let mut at = 6;
    loop {
        let u = u16::from_le_bytes(raw.get(at..at + 2)?.try_into().ok()?);
        at += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    let device_path = raw.get(at..at + dp_len)?.to_vec();
    Some(LoadOption {
        attributes,
        description: String::from_utf16_lossy(&units),
        device_path,
    })
}

/// The `(type, subtype, data)` of each node of `dp`, up to the End-Entire node.
/// Stops early at a node shorter than its header or running past the buffer.
fn device_path_nodes(dp: &[u8]) -> Vec<(u8, u8, &[u8])> {
    let mut nodes = Vec::new();
    let mut rest = dp;
    while rest.len() >= 4 {
        let (ty, sub) = (rest[0], rest[1]);
        let len = u16::from_le_bytes([rest[2], rest[3]]) as usize;
        if len < 4 || len > rest.len() || (ty == DP_END && sub == DP_END_ENTIRE) {
            break;
        }
        nodes.push((ty, sub, &rest[4..len]));
        rest = &rest[len..];
    }
    nodes
}

/// Whether `dp` is a network boot path (it has a MAC, IPv4, IPv6 or URI node).
fn is_network(dp: &[u8]) -> bool {
    device_path_nodes(dp)
        .iter()
        .any(|&(ty, sub, _)| ty == DP_MESSAGING && DP_NETWORK_SUBTYPES.contains(&sub))
}

/// The live [`VarStore`]: files `<name>-<global GUID>` under the `efivarfs` mount.
struct EfivarFs {
    dir: PathBuf,
}

impl EfivarFs {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}-{EFI_GLOBAL_GUID}"))
    }
}

impl VarStore for EfivarFs {
    fn list(&self) -> io::Result<Vec<String>> {
        let suffix = format!("-{EFI_GLOBAL_GUID}");
        Ok(fs::read_dir(&self.dir)?
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter_map(|n| n.strip_suffix(&suffix).map(str::to_string))
            .collect())
    }

    fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        match fs::read(self.path(name)) {
            // Strip the 4 attribute bytes efivarfs prefixes the value with.
            Ok(raw) => Ok(Some(raw.get(4..).unwrap_or_default().to_vec())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write(&self, name: &str, value: &[u8]) -> io::Result<()> {
        let path = self.path(name);
        // An immutable variable cannot even be opened for writing: clear the flag
        // first (best-effort — if it stays set, the open below fails with EPERM).
        if let Ok(f) = File::open(&path) {
            clear_immutable(&f);
        }
        // No O_TRUNC: an efivarfs write replaces the whole variable.
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o644)
            .open(&path)?;
        let mut buf = Vec::with_capacity(4 + value.len());
        buf.extend(EFI_VARIABLE_ATTRS.to_le_bytes());
        buf.extend(value);
        // One write(2): efivarfs sets the variable from exactly this buffer.
        let n = file.write(&buf)?;
        if n != buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short efivarfs write",
            ));
        }
        Ok(())
    }
}

/// Clear `FS_IMMUTABLE_FL` on `file` if set. Best-effort: errors are ignored.
fn clear_immutable(file: &File) {
    let mut flags: nix::libc::c_int = 0;
    // SAFETY: `file` is an open fd and `flags` a valid int for both ioctls.
    unsafe {
        if fs_ioc_getflags(file.as_raw_fd(), &mut flags).is_ok() && flags & FS_IMMUTABLE_FL != 0 {
            let cleared = flags & !FS_IMMUTABLE_FL;
            let _ = fs_ioc_setflags(file.as_raw_fd(), &cleared);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// An in-memory [`VarStore`]; `fail_write` makes every write to that name fail
    /// with EIO (as a firmware `SetVariable` refusal surfaces through efivarfs).
    #[derive(Default)]
    struct MemVars {
        vars: RefCell<BTreeMap<String, Vec<u8>>>,
        fail_write: Option<&'static str>,
        writes: RefCell<Vec<String>>,
    }

    impl MemVars {
        fn with(vars: &[(&str, Vec<u8>)]) -> Self {
            let m = MemVars::default();
            for (n, v) in vars {
                m.vars.borrow_mut().insert(n.to_string(), v.clone());
            }
            m
        }
        fn get(&self, name: &str) -> Option<Vec<u8>> {
            self.vars.borrow().get(name).cloned()
        }
    }

    impl VarStore for MemVars {
        fn list(&self) -> io::Result<Vec<String>> {
            Ok(self.vars.borrow().keys().cloned().collect())
        }
        fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
            Ok(self.get(name))
        }
        fn write(&self, name: &str, value: &[u8]) -> io::Result<()> {
            if self.fail_write == Some(name) {
                return Err(io::Error::from_raw_os_error(nix::libc::EIO));
            }
            self.writes.borrow_mut().push(name.to_string());
            self.vars
                .borrow_mut()
                .insert(name.to_string(), value.to_vec());
            Ok(())
        }
    }

    const GUID: [u8; 16] = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
        0xEF,
    ];

    fn esp() -> GptEsp {
        GptEsp {
            number: 1,
            unique_guid: GUID,
            first_lba: 2048,
            last_lba: 2048 + 1023,
        }
    }

    /// A PXE-style `PciRoot(0)/Pci(3,0)/MAC(..)/IPv4(..)` device path.
    fn pxe_path() -> Vec<u8> {
        let mut dp = vec![0x02, 0x01, 12, 0, 0x41, 0xD0, 0x0A, 0x03, 0, 0, 0, 0]; // ACPI
        dp.extend([0x01, 0x01, 6, 0, 0, 3]); // PCI
        let mut mac = vec![0x03, 11, 37, 0];
        mac.extend([0u8; 33]);
        dp.extend(mac);
        let mut ipv4 = vec![0x03, 12, 27, 0];
        ipv4.extend([0u8; 23]);
        dp.extend(ipv4);
        dp.extend([DP_END, DP_END_ENTIRE, 4, 0]);
        dp
    }

    /// A `PciRoot(0)/Pci(4,0)/NVMe(..)` whole-disk path (no partition GUID).
    fn disk_path() -> Vec<u8> {
        let mut dp = vec![0x02, 0x01, 12, 0, 0x41, 0xD0, 0x0A, 0x03, 0, 0, 0, 0];
        dp.extend([0x01, 0x01, 6, 0, 0, 4]);
        let mut nvme = vec![0x03, 23, 16, 0];
        nvme.extend([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        dp.extend(nvme);
        dp.extend([DP_END, DP_END_ENTIRE, 4, 0]);
        dp
    }

    fn option(attrs: u32, desc: &str, dp: &[u8]) -> Vec<u8> {
        encode_load_option(attrs, desc, dp)
    }

    fn order(o: &[u16]) -> Vec<u8> {
        encode_boot_order(o)
    }

    #[test]
    fn hd_file_device_path_matches_the_spec_layout() {
        let dp = hd_file_device_path(&esp(), r"\EFI\BOOT\BOOTX64.EFI");
        let mut want = vec![0x04, 0x01, 42, 0];
        want.extend(1u32.to_le_bytes());
        want.extend(2048u64.to_le_bytes());
        want.extend(1024u64.to_le_bytes());
        want.extend(GUID);
        want.extend([0x02, 0x02]);
        let path: Vec<u8> = r"\EFI\BOOT\BOOTX64.EFI"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(path.len(), 44, "21 UCS-2 chars + NUL");
        want.extend([0x04, 0x04, 48, 0]);
        want.extend(path);
        want.extend([0x7F, 0xFF, 0x04, 0x00]);
        assert_eq!(dp, want);
    }

    #[test]
    fn the_file_node_carries_each_architectures_loader() {
        // The File() node is the UCS-2 loader path + NUL, whatever the arch.
        for loader in [r"\EFI\BOOT\BOOTX64.EFI", r"\EFI\BOOT\BOOTAA64.EFI"] {
            let dp = hd_file_device_path(&esp(), loader);
            let nodes = device_path_nodes(&dp);
            assert_eq!(nodes.len(), 2, "HD + File");
            let (ty, sub, data) = nodes[1];
            assert_eq!((ty, sub), (DP_MEDIA, DP_MEDIA_FILE));
            assert_eq!(data, ucs2_nul(loader).as_slice(), "{loader}");
        }
    }

    #[test]
    fn load_option_round_trips() {
        let dp = hd_file_device_path(&esp(), ESP_LOADER_PATH);
        let raw = encode_load_option(LOAD_OPTION_ACTIVE, DESCRIPTION, &dp);
        let opt = parse_load_option(&raw).expect("parses");
        assert_eq!(opt.attributes, LOAD_OPTION_ACTIVE);
        assert_eq!(opt.description, "beskar7");
        assert_eq!(opt.device_path, dp);
    }

    #[test]
    fn truncated_load_options_do_not_parse() {
        let raw = encode_load_option(1, "x", &hd_file_device_path(&esp(), ESP_LOADER_PATH));
        for cut in [0, 3, 6, 8, raw.len() - 1] {
            assert_eq!(parse_load_option(&raw[..cut]), None, "cut at {cut}");
        }
    }

    /// `HD(<gpt>)` followed by one `File()` node per entry of `files` (none: an
    /// HD-only path), after an optional `prefix` of hardware nodes.
    fn hd_path(prefix: &[u8], gpt: &GptEsp, files: &[&str]) -> Vec<u8> {
        let full = hd_file_device_path(gpt, "x");
        let mut dp = prefix.to_vec();
        dp.extend(&full[..HD_NODE_LEN as usize]);
        for f in files {
            let path = ucs2_nul(f);
            dp.extend([DP_MEDIA, DP_MEDIA_FILE]);
            dp.extend((4 + path.len() as u16).to_le_bytes());
            dp.extend(path);
        }
        dp.extend([DP_END, DP_END_ENTIRE, 4, 0]);
        dp
    }

    /// `PciRoot(0)/Pci(4,0)`: the hardware prefix of a firmware's full-path entry.
    const PCI_PREFIX: [u8; 18] = [
        0x02, 0x01, 12, 0, 0x41, 0xD0, 0x0A, 0x03, 0, 0, 0, 0, 0x01, 0x01, 6, 0, 0, 4,
    ];

    /// An `Fv(..)/FvFile(..)` path, the shape of firmware-internal apps (setup,
    /// boot menu, shell).
    fn fv_path() -> Vec<u8> {
        let mut dp = vec![0x04, 0x07, 20, 0];
        dp.extend([0u8; 16]);
        dp.extend([0x04, 0x06, 20, 0]);
        dp.extend([1u8; 16]);
        dp.extend([DP_END, DP_END_ENTIRE, 4, 0]);
        dp
    }

    /// The removable-media loader of the architecture this build does NOT target.
    fn other_arch_loader() -> &'static str {
        if ESP_LOADER_PATH.ends_with("BOOTX64.EFI") {
            r"\EFI\BOOT\BOOTAA64.EFI"
        } else {
            r"\EFI\BOOT\BOOTX64.EFI"
        }
    }

    const APP: u32 = LOAD_OPTION_ACTIVE | 0x100;

    fn parsed(attrs: u32, desc: &str, dp: &[u8]) -> LoadOption {
        parse_load_option(&option(attrs, desc, dp)).unwrap()
    }

    #[test]
    fn recognises_network_and_partition_paths() {
        assert!(is_network(&pxe_path()));
        assert!(!is_network(&disk_path()));
        let hd = parsed(1, "x", &hd_file_device_path(&esp(), ESP_LOADER_PATH));
        assert!(!is_network(&hd.device_path));
        assert_eq!(
            hd.hd(),
            Some(HdNode {
                number: 1,
                start: 2048,
                size: 1024,
                guid: GUID,
            })
        );
        assert!(hd.hd().unwrap().is(&esp()));
        assert_eq!(parsed(1, "pxe", &pxe_path()).hd(), None);
    }

    #[test]
    fn hd_node_must_match_the_whole_gpt_entry() {
        let hd = parsed(1, "x", &hd_file_device_path(&esp(), ESP_LOADER_PATH))
            .hd()
            .unwrap();
        let moved = GptEsp {
            first_lba: 4096,
            last_lba: 4096 + 1023,
            ..esp()
        };
        let resized = GptEsp {
            last_lba: 2048 + 2047,
            ..esp()
        };
        let renumbered = GptEsp { number: 2, ..esp() };
        let other_guid = GptEsp {
            unique_guid: [0xAA; 16],
            ..esp()
        };
        for gpt in [moved, resized, renumbered, other_guid] {
            assert!(!hd.is(&gpt), "{gpt:?}");
        }
    }

    #[test]
    fn loader_path_joins_and_normalizes_file_nodes() {
        let path = |files: &[&str]| parsed(1, "x", &hd_path(&[], &esp(), files)).loader_path();
        assert_eq!(
            path(&[r"\EFI\BOOT\BOOTX64.EFI"]).as_deref(),
            Some(r"\EFI\BOOT\BOOTX64.EFI")
        );
        // A path split across File() nodes, with and without separators.
        assert_eq!(
            path(&[r"\EFI", r"BOOT\BOOTX64.EFI"]).as_deref(),
            Some(r"\EFI\BOOT\BOOTX64.EFI")
        );
        assert_eq!(
            path(&[r"\EFI\", r"\BOOT\", "BOOTX64.EFI"]).as_deref(),
            Some(r"\EFI\BOOT\BOOTX64.EFI")
        );
        // Forward slashes and doubled separators are normalized.
        assert_eq!(
            path(&["EFI//BOOT/BOOTX64.EFI"]).as_deref(),
            Some(r"\EFI\BOOT\BOOTX64.EFI")
        );
        // A path ending at the partition boots its removable-media loader.
        assert_eq!(path(&[]), None);
        // A firmware's full path: the hardware prefix doesn't matter.
        let full = parsed(1, "fw", &hd_path(&PCI_PREFIX, &esp(), &[ESP_LOADER_PATH]));
        assert_eq!(full.loader_path().as_deref(), Some(ESP_LOADER_PATH));
        assert!(full.hd().unwrap().is(&esp()));
    }

    #[test]
    fn only_active_boot_category_entries_are_auto_bootable() {
        let dp = disk_path();
        assert!(parsed(LOAD_OPTION_ACTIVE, "x", &dp).is_auto_bootable());
        // LOAD_OPTION_HIDDEN only hides the entry from the menu.
        assert!(parsed(LOAD_OPTION_ACTIVE | 0x8, "x", &dp).is_auto_bootable());
        assert!(!parsed(0, "x", &dp).is_auto_bootable(), "inactive");
        assert!(!parsed(APP, "x", &dp).is_auto_bootable(), "CATEGORY_APP");
        // OVMF's BootManagerMenuApp: ACTIVE | HIDDEN | CATEGORY_APP.
        assert!(!parsed(0x109, "x", &dp).is_auto_bootable());
    }

    #[test]
    fn device_path_walk_stops_on_a_bad_node_length() {
        // A node claiming length 2 (< header) or running past the buffer ends the walk.
        assert!(device_path_nodes(&[0x03, 11, 2, 0, 0, 0]).is_empty());
        assert!(device_path_nodes(&[0x03, 11, 200, 0]).is_empty());
    }

    #[test]
    fn boot_var_names() {
        assert_eq!(boot_var_name(0x1A), "Boot001A");
        assert_eq!(parse_boot_var_name("Boot001A"), Some(0x1A));
        assert_eq!(parse_boot_var_name("Boot001a"), Some(0x1A));
        for other in [
            "BootOrder",
            "BootNext",
            "BootCurrent",
            "Boot12",
            "Driver0001",
        ] {
            assert_eq!(parse_boot_var_name(other), None, "{other}");
        }
    }

    /// Placement over a described order: 1, 2 = network; 5, 6 = disks; 3 = a
    /// BOOT-category shell; 0, 7, 8 = APP entries (menu, setup, shell); 4 = an
    /// inactive network entry; 42 has no Boot#### at all.
    fn place(order: &[u16]) -> Vec<u16> {
        let bootable = |n: u16| matches!(n, 1 | 2 | 3 | 5 | 6);
        let net = |n: u16| matches!(n, 1 | 2 | 4);
        place_after_network(order, 9, bootable, net)
    }

    #[test]
    fn placement_goes_after_the_leading_network_entries() {
        // Network first: the disk follows the leading network run.
        assert_eq!(place(&[1, 2, 5]), vec![1, 2, 9, 5]);
        // The reviewer's cases: a BOOT-category shell or an old OS disk ahead of
        // PXE puts the disk first, so neither the shell nor the old disk wins.
        assert_eq!(place(&[3, 1]), vec![9, 3, 1]);
        assert_eq!(place(&[5, 1, 3]), vec![9, 5, 1, 3]);
        // A network entry further down doesn't pull the disk below other disks.
        assert_eq!(place(&[1, 5, 2, 6]), vec![1, 9, 5, 2, 6]);
        // No network entries at all.
        assert_eq!(place(&[5, 6]), vec![9, 5, 6]);
        assert_eq!(place(&[]), vec![9]);
    }

    #[test]
    fn placement_skips_entries_the_firmware_never_boots_on_its_own() {
        // OVMF: [Menu(app), Setup(app), PXE, HTTP, Shell(app)]. The app entries
        // keep their places; the disk goes after HTTP, not to index 0 ahead of PXE.
        assert_eq!(place(&[0, 7, 1, 2, 8]), vec![0, 7, 1, 2, 9, 8]);
        // OVMF with its whole-disk entry ahead of PXE: the disk goes before it.
        assert_eq!(place(&[0, 7, 5, 1]), vec![0, 7, 9, 5, 1]);
        // A dangling number and an inactive PXE entry don't count.
        assert_eq!(place(&[42, 4, 1, 5]), vec![42, 4, 1, 9, 5]);
        assert_eq!(place(&[4, 5, 1]), vec![4, 9, 5, 1]);
        // Only non-bootable entries: after them.
        assert_eq!(place(&[0, 7]), vec![0, 7, 9]);
    }

    #[test]
    fn placement_moves_an_entry_already_in_the_order() {
        assert_eq!(place(&[9, 1, 5]), vec![1, 9, 5]);
        assert_eq!(place(&[1, 9, 5]), vec![1, 9, 5], "already in place");
        assert_eq!(place(&[1, 5, 9]), vec![1, 9, 5]);
    }

    #[test]
    fn pick_existing_reuses_only_an_entry_starting_our_loader() {
        let gpt = esp();
        let reusable =
            |dp: Vec<u8>| pick_existing(&[(4, parsed(1, "x", &dp))], &gpt, ESP_LOADER_PATH);
        // Our loader, short-form or a firmware's full path.
        assert_eq!(reusable(hd_path(&[], &gpt, &[ESP_LOADER_PATH])), Some(4));
        assert_eq!(
            reusable(hd_path(&PCI_PREFIX, &gpt, &[ESP_LOADER_PATH])),
            Some(4)
        );
        // FAT is case-insensitive.
        let lower = ESP_LOADER_PATH.to_lowercase();
        assert_eq!(reusable(hd_path(&[], &gpt, &[&lower])), Some(4));
        // Split across File() nodes.
        let (dir, file) = ESP_LOADER_PATH.rsplit_once('\\').unwrap();
        assert_eq!(reusable(hd_path(&[], &gpt, &[dir, file])), Some(4));
        // A path ending at the partition boots the same removable-media loader.
        assert_eq!(reusable(hd_path(&[], &gpt, &[])), Some(4));
        // Another file on the same partition GUID: an earlier image's loader, a
        // distro loader, or the other architecture's fallback.
        for other in [
            r"\EFI\oldos\grubx64.efi",
            r"\EFI\ubuntu\shimx64.efi",
            other_arch_loader(),
        ] {
            assert_eq!(reusable(hd_path(&[], &gpt, &[other])), None, "{other}");
        }
        // Our loader on a partition with another layout.
        let resized = GptEsp {
            last_lba: 2048 + 4095,
            ..esp()
        };
        assert_eq!(reusable(hd_path(&[], &resized, &[ESP_LOADER_PATH])), None);
    }

    #[test]
    fn pick_existing_skips_inactive_entries_and_takes_the_lowest() {
        let hd = hd_file_device_path(&esp(), ESP_LOADER_PATH);
        let entries = vec![
            (3, parsed(0, "x", &hd)),
            (7, parsed(LOAD_OPTION_ACTIVE, "x", &hd)),
            (8, parsed(1, "x", &hd)),
        ];
        assert_eq!(pick_existing(&entries, &esp(), ESP_LOADER_PATH), Some(7));
        assert_eq!(pick_existing(&entries[..1], &esp(), ESP_LOADER_PATH), None);
    }

    #[test]
    fn free_boot_number_and_boot_order_parsing() {
        assert_eq!(free_boot_number(&[]), Some(0));
        assert_eq!(free_boot_number(&[0, 1, 3]), Some(2));
        assert_eq!(parse_boot_order(&[1, 0, 2, 0]), Some(vec![1, 2]));
        assert_eq!(parse_boot_order(&[1, 0, 2]), None);
    }

    #[test]
    fn creates_an_entry_after_the_network_entries() {
        let vars = MemVars::with(&[
            ("Boot0000", option(1, "UEFI PXEv4", &pxe_path())),
            ("Boot0001", option(1, "UEFI NVMe", &disk_path())),
            ("BootOrder", order(&[0, 1])),
            ("BootCurrent", vec![0, 0]),
        ]);
        let got = ensure_in(&vars, &esp()).unwrap();
        assert_eq!(
            got,
            BootEntry {
                number: 2,
                outcome: Outcome::Created,
                previous_order: vec![0, 1],
                boot_order: vec![0, 2, 1],
            }
        );
        let opt = parse_load_option(&vars.get("Boot0002").unwrap()).unwrap();
        assert!(opt.is_auto_bootable());
        assert_eq!(opt.description, "beskar7");
        assert!(opt.hd().unwrap().is(&esp()));
        assert_eq!(opt.loader_path().as_deref(), Some(ESP_LOADER_PATH));
        assert_eq!(vars.get("BootOrder").unwrap(), order(&[0, 2, 1]));
    }

    #[test]
    fn ovmf_boot_order_places_the_disk_after_its_network_entries() {
        // The NVRAM an OVMF host has before provisioning (e2e seed-nodisk).
        let vars = MemVars::with(&[
            ("Boot0000", option(0x109, "BootManagerMenuApp", &fv_path())),
            ("Boot0001", option(APP, "EFI Firmware Setup", &fv_path())),
            ("Boot0002", option(1, "UEFI PXEv4", &pxe_path())),
            ("Boot0003", option(1, "UEFI HTTPv4", &pxe_path())),
            ("Boot0004", option(APP, "EFI Internal Shell", &fv_path())),
            ("BootOrder", order(&[0, 1, 2, 3, 4])),
        ]);
        let got = ensure_in(&vars, &esp()).unwrap();
        assert_eq!(got.number, 5);
        assert_eq!(got.boot_order, vec![0, 1, 2, 3, 5, 4]);
    }

    #[test]
    fn reuses_the_firmware_entry_that_starts_our_loader() {
        let fw = hd_path(&PCI_PREFIX, &esp(), &[ESP_LOADER_PATH]);
        let vars = MemVars::with(&[
            ("Boot0000", option(1, "UEFI PXEv4", &pxe_path())),
            ("Boot0004", option(1, "UEFI HARDDISK", &fw)),
            ("BootOrder", order(&[4, 0])),
        ]);
        let got = ensure_in(&vars, &esp()).unwrap();
        assert_eq!((got.number, got.outcome), (4, Outcome::Reused));
        assert_eq!(got.boot_order, vec![0, 4]);
        assert_eq!(*vars.writes.borrow(), vec!["BootOrder".to_string()]);
    }

    #[test]
    fn does_not_reuse_an_entry_starting_another_loader() {
        // Same partition GUID (images built from the same base share it), but the
        // entry starts a file the new image may not have.
        for (desc, file) in [
            ("oldos", r"\EFI\oldos\grubx64.efi"),
            ("ubuntu", r"\EFI\ubuntu\shimx64.efi"),
        ] {
            let stale = option(1, desc, &hd_path(&[], &esp(), &[file]));
            let vars = MemVars::with(&[
                ("Boot0000", option(1, "UEFI PXEv4", &pxe_path())),
                ("Boot0004", stale.clone()),
                ("BootOrder", order(&[0, 4])),
            ]);
            let got = ensure_in(&vars, &esp()).unwrap();
            assert_eq!((got.number, got.outcome), (1, Outcome::Created), "{file}");
            assert_eq!(got.boot_order, vec![0, 1, 4]);
            assert_eq!(vars.get("Boot0004").unwrap(), stale, "left untouched");
        }
    }

    #[test]
    fn replaces_the_previous_beskar7_entry_in_place() {
        // A previous deploy of an image with another ESP GUID left Boot0003.
        let old_gpt = GptEsp {
            unique_guid: [0x55; 16],
            ..esp()
        };
        let old = hd_file_device_path(&old_gpt, ESP_LOADER_PATH);
        let vars = MemVars::with(&[
            ("Boot0000", option(1, "UEFI PXEv4", &pxe_path())),
            ("Boot0001", option(1, "UEFI NVMe", &disk_path())),
            ("Boot0003", option(1, DESCRIPTION, &old)),
            ("BootOrder", order(&[0, 3, 1])),
        ]);
        let got = ensure_in(&vars, &esp()).unwrap();
        assert_eq!((got.number, got.outcome), (3, Outcome::Replaced));
        assert_eq!(got.boot_order, vec![0, 3, 1], "keeps its slot");
        assert_eq!(
            *vars.writes.borrow(),
            vec!["Boot0003".to_string()],
            "no new number, no BootOrder write"
        );
        let opt = parse_load_option(&vars.get("Boot0003").unwrap()).unwrap();
        assert!(opt.hd().unwrap().is(&esp()), "now points at the new ESP");
    }

    #[test]
    fn replaces_the_lowest_of_several_beskar7_entries() {
        let old = |g: u8| {
            let gpt = GptEsp {
                unique_guid: [g; 16],
                ..esp()
            };
            option(1, DESCRIPTION, &hd_file_device_path(&gpt, ESP_LOADER_PATH))
        };
        let vars = MemVars::with(&[
            ("Boot0006", old(0x66)),
            ("Boot0002", old(0x22)),
            ("BootOrder", order(&[6, 2])),
        ]);
        let got = ensure_in(&vars, &esp()).unwrap();
        assert_eq!((got.number, got.outcome), (2, Outcome::Replaced));
    }

    #[test]
    fn a_matching_beskar7_entry_is_reused_not_replaced() {
        let vars = MemVars::with(&[
            ("Boot0000", option(1, "UEFI PXEv4", &pxe_path())),
            ("BootOrder", order(&[0])),
        ]);
        let first = ensure_in(&vars, &esp()).unwrap();
        assert_eq!(first.outcome, Outcome::Created);
        vars.writes.borrow_mut().clear();
        let second = ensure_in(&vars, &esp()).unwrap();
        assert_eq!(
            (second.number, second.outcome),
            (first.number, Outcome::Reused)
        );
        assert_eq!(second.previous_order, first.boot_order);
        assert!(vars.writes.borrow().is_empty(), "no NVRAM write on a rerun");
    }

    #[test]
    fn a_missing_boot_order_is_created() {
        let vars = MemVars::default();
        let got = ensure_in(&vars, &esp()).unwrap();
        assert_eq!(got.previous_order, Vec::<u16>::new());
        assert_eq!(got.boot_order, vec![0]);
        assert_eq!(vars.get("BootOrder").unwrap(), order(&[0]));
    }

    #[test]
    fn a_malformed_entry_is_never_matched_nor_reused() {
        let vars = MemVars::with(&[("Boot0000", vec![1, 2, 3])]);
        let got = ensure_in(&vars, &esp()).unwrap();
        assert_eq!(
            got.number, 1,
            "Boot0000 is taken even though it is malformed"
        );
    }

    #[test]
    fn a_malformed_boot_order_is_an_error_and_nothing_is_written() {
        let vars = MemVars::with(&[("BootOrder", vec![0, 0, 1])]);
        let err = ensure_in(&vars, &esp()).unwrap_err();
        assert!(matches!(err, EfiBootError::BadBootOrder), "got {err:?}");
        assert!(vars.writes.borrow().is_empty());
    }

    #[test]
    fn a_refused_entry_write_is_an_error_and_leaves_boot_order_alone() {
        let vars = MemVars {
            fail_write: Some("Boot0001"),
            ..MemVars::with(&[
                ("Boot0000", option(1, "UEFI PXEv4", &pxe_path())),
                ("BootOrder", order(&[0])),
            ])
        };
        let err = ensure_in(&vars, &esp()).unwrap_err();
        assert!(
            matches!(&err, EfiBootError::WriteVar { name, .. } if name == "Boot0001"),
            "got {err:?}"
        );
        assert_eq!(vars.get("BootOrder").unwrap(), order(&[0]));
    }

    #[test]
    fn a_refused_boot_order_write_is_an_error() {
        let vars = MemVars {
            fail_write: Some("BootOrder"),
            ..MemVars::default()
        };
        let err = ensure_in(&vars, &esp()).unwrap_err();
        assert!(
            matches!(&err, EfiBootError::WriteVar { name, .. } if name == "BootOrder"),
            "got {err:?}"
        );
    }

    #[test]
    fn efivarfs_store_round_trips_through_attribute_bytes() {
        // A scratch dir stands in for efivarfs: the same <name>-<guid> files with a
        // 4-byte attribute prefix (the immutable-flag ioctls are best-effort).
        let s = crate::probe::testutil::Scratch::new("efivarfs");
        let store = EfivarFs {
            dir: s.path().to_path_buf(),
        };
        assert_eq!(store.read("BootOrder").unwrap(), None);
        store.write("BootOrder", &order(&[3, 1])).unwrap();
        let raw = fs::read(s.path().join(format!("BootOrder-{EFI_GLOBAL_GUID}"))).unwrap();
        assert_eq!(&raw[..4], &EFI_VARIABLE_ATTRS.to_le_bytes());
        assert_eq!(store.read("BootOrder").unwrap(), Some(order(&[3, 1])));
        fs::write(s.path().join("Other-1234"), b"x").unwrap();
        assert_eq!(store.list().unwrap(), vec!["BootOrder".to_string()]);
    }
}
