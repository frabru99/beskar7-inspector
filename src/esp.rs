//! Locate the EFI System Partition (ESP) on the **selected target disk**, so the
//! deploy step can check its loader ([`crate::deploy::verify_esp_loader`]) and
//! register a UEFI boot entry for it ([`crate::efiboot::ensure_disk_boot_entry`]).
//!
//! The first reboot after the whole-disk write has no UEFI NVRAM boot entry for
//! the new disk. The located [`EspPartition`] carries the GPT fields a `HD()`
//! device-path node needs (partition number, unique GUID, start and size), so the
//! inspector can create that entry itself, the way `efibootmgr` would. An image
//! with no GPT ([`EspError::NoGpt`]) or no ESP ([`EspError::NotFound`]) is
//! [absent](EspError::is_absent): the caller logs and skips the boot entry.
//!
//! ## How the ESP is identified
//! The same way the firmware does: by the GPT partition **type GUID**
//! `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`, not by a filesystem label. The GPT is
//! read from the target's whole-disk node, opened once and identity-checked
//! against [`TargetDisk::dev_number`] (as for the write, §5). The matching GPT
//! entry's number is then mapped to the target disk's own sysfs partition carrying
//! that `partition` number. As in [`crate::oem`], only `/sys/block/<target>/` is
//! enumerated, so the located partition is a child of the target by construction,
//! and [`EspPartition::dev_number`] lets the mount bind to that exact device.
//!
//! ## Secret hygiene (§9)
//! No secrets pass through here. [`EspError`] carries only the disk name and
//! non-secret device errors.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::deploy::{self, DeployError};
use crate::oem::target_partitions;
use crate::probe::read_trimmed;
use crate::target_disk::TargetDisk;

/// Kernel whole-block-device directory; a disk's partitions are its subdirectories.
const SYSFS_BLOCK: &str = "/sys/block";

/// The ESP partition type GUID `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` as stored on
/// disk: GPT GUIDs are mixed-endian (the first three fields little-endian).
const ESP_TYPE_GUID: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];
/// The GPT header signature at offset 0 of LBA 1.
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
/// Bytes of the GPT header this module reads (the UEFI-defined header is 92 bytes).
const GPT_HEADER_LEN: usize = 92;
/// Upper bound on the GPT entry count — the standard table has 128 entries; this
/// keeps a corrupt header from requesting a huge read.
const MAX_GPT_ENTRIES: u32 = 1024;
/// Smallest and largest accepted GPT entry size (the standard size is 128).
const GPT_ENTRY_SIZE_RANGE: std::ops::RangeInclusive<u32> = 128..=1024;
/// Logical block size assumed when sysfs does not report one.
const DEFAULT_BLOCK_SIZE: u64 = 512;

/// One GPT entry carrying the ESP type GUID: the fields a UEFI `HD()` device-path
/// node is built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GptEsp {
    /// The 1-based GPT entry number, which is also the kernel's `partition` number.
    pub number: u32,
    /// The partition's unique GUID, as the 16 bytes stored on disk (mixed-endian).
    pub unique_guid: [u8; 16],
    /// First LBA of the partition.
    pub first_lba: u64,
    /// Last LBA of the partition (inclusive).
    pub last_lba: u64,
}

impl GptEsp {
    /// The partition size in logical blocks (the GPT last LBA is inclusive).
    pub fn size_lba(&self) -> u64 {
        self.last_lba
            .saturating_sub(self.first_lba)
            .saturating_add(1)
    }
}

/// The located ESP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EspPartition {
    /// The partition's kernel name, e.g. `nvme0n1p1` or `sda1`.
    pub kname: String,
    /// The partition's `major:minor`, read from `/sys/block/<disk>/<kname>/dev` at
    /// enumeration time. The mount is bound to it (see [`crate::deploy`]).
    pub dev_number: String,
    /// The partition's GPT entry, for the UEFI boot entry (see [`crate::efiboot`]).
    pub gpt: GptEsp,
}

impl EspPartition {
    /// The `/dev` node path, used only in error messages.
    pub fn dev_path(&self) -> String {
        format!("/dev/{}", self.kname)
    }
}

/// Why the ESP could not be located. Every variant carries only non-secret data.
#[derive(Debug, thiserror::Error)]
pub enum EspError {
    /// Opening or identity-checking the whole-disk node failed.
    #[error(transparent)]
    Device(#[from] DeployError),
    /// Reading the GPT from the target disk failed.
    #[error("reading the GPT of target disk {disk:?}")]
    ReadGpt {
        /// The target disk kernel name.
        disk: String,
        /// The underlying read/seek error.
        #[source]
        source: std::io::Error,
    },
    /// The written image has no GPT (no `EFI PART` signature at LBA 1), so it has
    /// no ESP the firmware could use.
    #[error("target disk {disk:?} has no GPT after the image write")]
    NoGpt {
        /// The target disk kernel name.
        disk: String,
    },
    /// The GPT header describes an entry table outside the accepted bounds.
    #[error("target disk {disk:?} has a malformed GPT header")]
    BadGpt {
        /// The target disk kernel name.
        disk: String,
    },
    /// No GPT entry carries the ESP type GUID, or none maps to a partition the
    /// kernel exposes on the target disk.
    #[error("target disk {disk:?} has no EFI System Partition")]
    NotFound {
        /// The target disk kernel name.
        disk: String,
    },
}

impl EspError {
    /// Whether the image simply has no ESP ([`NoGpt`](Self::NoGpt) or
    /// [`NotFound`](Self::NotFound)): the caller logs and skips the UEFI boot
    /// entry. Every other variant is a disk or read failure and stays fatal.
    pub fn is_absent(&self) -> bool {
        matches!(self, EspError::NoGpt { .. } | EspError::NotFound { .. })
    }
}

/// Locate the ESP on `target` against the live host: read its GPT through an
/// identity-checked whole-disk fd, then map the ESP entry to a sysfs partition.
pub fn find_esp_partition(target: &TargetDisk) -> Result<EspPartition, EspError> {
    let path = target.dev_path();
    let mut file = File::open(&path).map_err(|source| DeployError::OpenTarget {
        path: path.clone(),
        source,
    })?;
    deploy::verify_node_identity(&file, &path, &target.dev_number)?;

    let block_dir = Path::new(SYSFS_BLOCK);
    let block_size = read_trimmed(
        &block_dir
            .join(&target.kname)
            .join("queue/logical_block_size"),
    )
    .and_then(|s| s.parse::<u64>().ok())
    .filter(|n| *n >= DEFAULT_BLOCK_SIZE && n.is_power_of_two())
    .unwrap_or(DEFAULT_BLOCK_SIZE);

    let entries = read_esp_entries(&mut file, block_size, &target.kname)?;
    find_esp_in(block_dir, &target.kname, &entries)
}

/// The layout of the GPT entry table, from the header.
#[derive(Debug, PartialEq, Eq)]
struct GptLayout {
    /// First LBA of the entry table.
    entries_lba: u64,
    /// Number of entries in the table.
    count: u32,
    /// Size of each entry in bytes.
    entry_size: u32,
}

/// Parse the GPT header at LBA 1. `Err(NoGpt)` without the signature, `Err(BadGpt)`
/// when the table location or size is out of bounds.
fn parse_gpt_header(header: &[u8], disk: &str) -> Result<GptLayout, EspError> {
    if header.len() < GPT_HEADER_LEN || &header[..8] != GPT_SIGNATURE {
        return Err(EspError::NoGpt {
            disk: disk.to_string(),
        });
    }
    let u32_at = |o: usize| u32::from_le_bytes(header[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(header[o..o + 8].try_into().unwrap());
    let layout = GptLayout {
        entries_lba: u64_at(72),
        count: u32_at(80),
        entry_size: u32_at(84),
    };
    // The entry table follows the header (LBA >= 2) and has a bounded size.
    if layout.entries_lba < 2
        || layout.count == 0
        || layout.count > MAX_GPT_ENTRIES
        || !GPT_ENTRY_SIZE_RANGE.contains(&layout.entry_size)
        || layout.entry_size % 8 != 0
    {
        return Err(EspError::BadGpt {
            disk: disk.to_string(),
        });
    }
    Ok(layout)
}

/// The GPT entries whose type GUID is the ESP's, by ascending 1-based number.
/// Entry `n` is the partition the kernel exposes with `partition` == `n`. Each
/// entry holds the type GUID (bytes `0..16`), the unique GUID (`16..32`), and the
/// first and last LBA (`32..40`, `40..48`, little-endian).
fn esp_entries(entries: &[u8], entry_size: usize) -> Vec<GptEsp> {
    let u64_at = |e: &[u8], o: usize| u64::from_le_bytes(e[o..o + 8].try_into().unwrap());
    entries
        .chunks_exact(entry_size)
        .zip(1u32..)
        .filter(|(entry, _)| entry[..16] == ESP_TYPE_GUID)
        .map(|(entry, number)| GptEsp {
            number,
            unique_guid: entry[16..32].try_into().unwrap(),
            first_lba: u64_at(entry, 32),
            last_lba: u64_at(entry, 40),
        })
        .collect()
}

/// Read the GPT header and entry table from `dev` (a whole disk with
/// `block_size`-byte logical blocks) and return the ESP entries. Generic over the
/// reader so the parsing is unit-tested against an in-memory disk.
fn read_esp_entries<R: Read + Seek>(
    dev: &mut R,
    block_size: u64,
    disk: &str,
) -> Result<Vec<GptEsp>, EspError> {
    let io_err = |source| EspError::ReadGpt {
        disk: disk.to_string(),
        source,
    };
    let mut header = [0u8; GPT_HEADER_LEN];
    dev.seek(SeekFrom::Start(block_size)).map_err(io_err)?;
    dev.read_exact(&mut header).map_err(io_err)?;
    let layout = parse_gpt_header(&header, disk)?;

    let offset = layout
        .entries_lba
        .checked_mul(block_size)
        .ok_or_else(|| EspError::BadGpt {
            disk: disk.to_string(),
        })?;
    // Bounded by MAX_GPT_ENTRIES * 1024 bytes = 1 MiB.
    let mut entries = vec![0u8; layout.count as usize * layout.entry_size as usize];
    dev.seek(SeekFrom::Start(offset)).map_err(io_err)?;
    dev.read_exact(&mut entries).map_err(io_err)?;
    Ok(esp_entries(&entries, layout.entry_size as usize))
}

/// Pure locator over an injected `/sys/block`-shaped `block_dir`: the target disk's
/// partition whose `partition` number is that of the first of `esp_entries` (in
/// ascending GPT order) the kernel exposes.
fn find_esp_in(
    block_dir: &Path,
    disk: &str,
    esp_entries: &[GptEsp],
) -> Result<EspPartition, EspError> {
    let parts: Vec<(u32, String)> = target_partitions(block_dir, disk)
        .into_iter()
        .filter_map(|part| {
            let n = read_trimmed(&block_dir.join(disk).join(&part).join("partition"))?
                .parse()
                .ok()?;
            Some((n, part))
        })
        .collect();
    for gpt in esp_entries {
        if let Some((_, part)) = parts.iter().find(|(pn, _)| *pn == gpt.number) {
            let dev_number =
                read_trimmed(&block_dir.join(disk).join(part).join("dev")).unwrap_or_default();
            return Ok(EspPartition {
                kname: part.clone(),
                dev_number,
                gpt: gpt.clone(),
            });
        }
    }
    Err(EspError::NotFound {
        disk: disk.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::testutil::{write, Scratch};
    use std::io::Cursor;

    /// A Linux filesystem data GUID (`0FC63DAF-…`), as stored on disk.
    const LINUX_FS_GUID: [u8; 16] = [
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
    ];

    /// The unique GUID [`gpt_disk`] gives entry `i` (0-based): every byte `i + 1`.
    fn unique_guid(i: usize) -> [u8; 16] {
        [i as u8 + 1; 16]
    }

    /// An `EspPartition`-ready GPT entry with distinct fields, for the locator tests.
    fn gpt_esp(number: u32) -> GptEsp {
        GptEsp {
            number,
            unique_guid: [number as u8; 16],
            first_lba: 2048 * number as u64,
            last_lba: 2048 * number as u64 + 1023,
        }
    }

    /// An in-memory disk with a GPT at LBA 1 and a 128 x 128-byte entry table at
    /// LBA 2, whose entries carry `types` in order. Entry `i` has unique GUID
    /// [`unique_guid`]`(i)` and spans LBAs `2048 * (i + 1)` to `2048 * (i + 1) + 1023`.
    fn gpt_disk(block: usize, types: &[[u8; 16]]) -> Vec<u8> {
        let mut disk = vec![0u8; block * 2 + 128 * 128];
        let h = &mut disk[block..block + GPT_HEADER_LEN];
        h[..8].copy_from_slice(GPT_SIGNATURE);
        h[72..80].copy_from_slice(&2u64.to_le_bytes());
        h[80..84].copy_from_slice(&128u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        for (i, t) in types.iter().enumerate() {
            let at = block * 2 + i * 128;
            let first = 2048 * (i as u64 + 1);
            disk[at..at + 16].copy_from_slice(t);
            disk[at + 16..at + 32].copy_from_slice(&unique_guid(i));
            disk[at + 32..at + 40].copy_from_slice(&first.to_le_bytes());
            disk[at + 40..at + 48].copy_from_slice(&(first + 1023).to_le_bytes());
        }
        disk
    }

    #[test]
    fn esp_guid_is_the_mixed_endian_encoding_of_the_spec_guid() {
        // C12A7328-F81F-11D2-BA4B-00A0C93EC93B: the first three fields are
        // byte-swapped on disk, the last two are stored as written.
        assert_eq!(&ESP_TYPE_GUID[..4], &0xC12A7328u32.to_le_bytes());
        assert_eq!(&ESP_TYPE_GUID[4..6], &0xF81Fu16.to_le_bytes());
        assert_eq!(&ESP_TYPE_GUID[6..8], &0x11D2u16.to_le_bytes());
        assert_eq!(
            &ESP_TYPE_GUID[8..],
            &[0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B]
        );
    }

    #[test]
    fn reads_the_esp_entry_from_a_512_byte_sector_gpt() {
        // Kairos layout: ESP first, then the ext partitions.
        let disk = gpt_disk(512, &[ESP_TYPE_GUID, LINUX_FS_GUID, LINUX_FS_GUID]);
        let got = read_esp_entries(&mut Cursor::new(disk), 512, "sda").unwrap();
        assert_eq!(
            got,
            vec![GptEsp {
                number: 1,
                unique_guid: unique_guid(0),
                first_lba: 2048,
                last_lba: 3071,
            }]
        );
        assert_eq!(got[0].size_lba(), 1024, "the GPT last LBA is inclusive");
    }

    #[test]
    fn reads_the_esp_entry_from_a_4k_sector_gpt() {
        let disk = gpt_disk(4096, &[LINUX_FS_GUID, ESP_TYPE_GUID]);
        let got = read_esp_entries(&mut Cursor::new(disk), 4096, "sda").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].number, 2);
        assert_eq!(got[0].unique_guid, unique_guid(1));
        assert_eq!((got[0].first_lba, got[0].last_lba), (4096, 5119));
    }

    #[test]
    fn a_gpt_without_an_esp_yields_no_entries() {
        let disk = gpt_disk(512, &[LINUX_FS_GUID, LINUX_FS_GUID]);
        let got = read_esp_entries(&mut Cursor::new(disk), 512, "sda").unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn a_disk_without_the_gpt_signature_is_no_gpt() {
        let disk = vec![0u8; 512 * 2 + 128 * 128];
        let err = read_esp_entries(&mut Cursor::new(disk), 512, "sda").unwrap_err();
        assert!(matches!(err, EspError::NoGpt { .. }), "got {err:?}");
    }

    #[test]
    fn only_no_gpt_and_not_found_are_absent() {
        // Absent means "skip the boot entry"; every other failure stays fatal.
        let disk = || "sda".to_string();
        assert!(EspError::NoGpt { disk: disk() }.is_absent());
        assert!(EspError::NotFound { disk: disk() }.is_absent());
        assert!(!EspError::BadGpt { disk: disk() }.is_absent());
        assert!(!EspError::ReadGpt {
            disk: disk(),
            source: std::io::Error::other("x"),
        }
        .is_absent());
        assert!(!EspError::Device(DeployError::NoDeviceNumber {
            path: "/dev/sda".into(),
        })
        .is_absent());
    }

    #[test]
    fn out_of_bounds_gpt_headers_are_rejected() {
        let mut header = [0u8; GPT_HEADER_LEN];
        header[..8].copy_from_slice(GPT_SIGNATURE);
        let set = |h: &mut [u8; GPT_HEADER_LEN], lba: u64, count: u32, size: u32| {
            h[72..80].copy_from_slice(&lba.to_le_bytes());
            h[80..84].copy_from_slice(&count.to_le_bytes());
            h[84..88].copy_from_slice(&size.to_le_bytes());
        };
        for (lba, count, size) in [
            (1, 128, 128),                 // table overlapping the header
            (2, 0, 128),                   // no entries
            (2, MAX_GPT_ENTRIES + 1, 128), // oversized table
            (2, 128, 64),                  // entry smaller than the spec minimum
            (2, 128, 2048),                // entry larger than accepted
            (2, 128, 130),                 // entry size not a multiple of 8
        ] {
            set(&mut header, lba, count, size);
            let err = parse_gpt_header(&header, "sda").unwrap_err();
            assert!(
                matches!(err, EspError::BadGpt { .. }),
                "({lba}, {count}, {size}) got {err:?}"
            );
        }
        set(&mut header, 2, 128, 128);
        assert_eq!(
            parse_gpt_header(&header, "sda").unwrap(),
            GptLayout {
                entries_lba: 2,
                count: 128,
                entry_size: 128
            }
        );
    }

    #[test]
    fn a_truncated_disk_is_a_read_error() {
        // The header is present, but the disk ends before the entry table.
        let mut disk = gpt_disk(512, &[ESP_TYPE_GUID]);
        disk.truncate(512 * 2 + 64);
        let err = read_esp_entries(&mut Cursor::new(disk), 512, "sda").unwrap_err();
        assert!(matches!(err, EspError::ReadGpt { .. }), "got {err:?}");
    }

    /// `/sys/block/<disk>/<part>/{partition,dev}` with the given partition numbers.
    fn write_partitions(root: &Path, disk: &str, parts: &[(&str, u32)]) {
        write(root, &format!("{disk}/queue/logical_block_size"), "512\n");
        for (p, n) in parts {
            write(root, &format!("{disk}/{p}/partition"), &format!("{n}\n"));
            write(root, &format!("{disk}/{p}/dev"), &format!("259:{n}\n"));
        }
    }

    #[test]
    fn maps_the_esp_entry_to_the_partition_with_that_number() {
        let s = Scratch::new("esp-found");
        write_partitions(
            s.path(),
            "nvme0n1",
            &[("nvme0n1p1", 1), ("nvme0n1p2", 2), ("nvme0n1p3", 3)],
        );
        let got = find_esp_in(s.path(), "nvme0n1", &[gpt_esp(1)]).unwrap();
        assert_eq!(got.kname, "nvme0n1p1");
        assert_eq!(got.dev_number, "259:1");
        assert_eq!(got.gpt, gpt_esp(1), "the GPT fields ride along");
        assert_eq!(got.dev_path(), "/dev/nvme0n1p1");
    }

    #[test]
    fn maps_by_partition_number_not_name_order() {
        // sda10 sorts before sda2 by name; the number decides.
        let s = Scratch::new("esp-order");
        write_partitions(s.path(), "sda", &[("sda10", 10), ("sda2", 2)]);
        assert_eq!(
            find_esp_in(s.path(), "sda", &[gpt_esp(2)]).unwrap().kname,
            "sda2"
        );
        assert_eq!(
            find_esp_in(s.path(), "sda", &[gpt_esp(10)]).unwrap().kname,
            "sda10"
        );
    }

    #[test]
    fn picks_the_lowest_numbered_of_several_esps() {
        let s = Scratch::new("esp-dup");
        write_partitions(s.path(), "sda", &[("sda1", 1), ("sda3", 3)]);
        let got = find_esp_in(s.path(), "sda", &[gpt_esp(1), gpt_esp(3)]).unwrap();
        assert_eq!(got.kname, "sda1");
        assert_eq!(got.gpt, gpt_esp(1));
    }

    #[test]
    fn not_found_when_no_entry_maps_to_a_partition() {
        let s = Scratch::new("esp-absent");
        write_partitions(s.path(), "sda", &[("sda1", 1), ("sda2", 2)]);
        let err = find_esp_in(s.path(), "sda", &[]).unwrap_err();
        assert!(matches!(err, EspError::NotFound { .. }), "got {err:?}");
        // An ESP entry the kernel did not expose (e.g. not re-read) is not found.
        let err = find_esp_in(s.path(), "sda", &[gpt_esp(5)]).unwrap_err();
        assert!(matches!(err, EspError::NotFound { .. }), "got {err:?}");
    }

    #[test]
    fn is_confined_to_the_target_disk() {
        // An ESP partition on another disk must never be matched.
        let s = Scratch::new("esp-scoped");
        write_partitions(s.path(), "sda", &[("sda2", 2)]); // target, no partition 1
        write_partitions(s.path(), "sdb", &[("sdb1", 1)]); // decoy
        let err = find_esp_in(s.path(), "sda", &[gpt_esp(1)]).unwrap_err();
        assert!(matches!(err, EspError::NotFound { .. }), "got {err:?}");
    }
}
