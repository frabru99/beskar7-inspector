//! Locate the `COS_OEM` partition on the **selected target disk** (contract §9.1
//! step 5.3, finding H1).
//!
//! After the whole-disk image is written ([`crate::deploy`]), the inspector must
//! mount the image's `COS_OEM` partition to inject the per-host Kairos
//! cloud-config carrying the CAPI join secret. *Which* partition that is matters
//! for security: a system-wide "find the filesystem labeled `COS_OEM`" scan is
//! ambiguous — a pre-existing or attacker-supplied disk could also carry that
//! label and capture the join secret. This module therefore locates `COS_OEM`
//! **only among the target disk's own partitions**, enumerated structurally from
//! `/sys/block/<target>/` — it never looks at another disk, so the located
//! *name* is provably a partition of the target by construction.
//!
//! That structural guarantee covers the *name*, not the device the deploy step
//! will later open by path. [`OemPartition`] therefore carries the partition's
//! `major:minor` ([`OemPartition::dev_number`]), read at enumeration time, so the
//! deploy orchestrator can `open("/dev/<kname>")` and verify the opened node's
//! `st_rdev` matches before mounting — closing the resolve-now / mount-later
//! TOCTOU window the same way [`crate::target_disk::TargetDisk`] does for the
//! whole-disk write (contract §9.1 5.3 "verify the partition's parent block
//! device is the selected target before mounting").
//!
//! ## How a label is read
//! The Kairos `COS_OEM` partition is an **ext2/3/4** filesystem; its label lives
//! in the ext superblock (`s_volume_name`, 16 bytes at superblock offset `0x78`,
//! the superblock itself starting 1024 bytes into the partition, magic `0xEF53`).
//! [`ext_label`] parses exactly those bytes — a partition that is not ext, or not
//! labeled, yields `None` and is skipped. Non-ext partitions on the disk (the
//! vfat EFI/GRUB partition, etc.) are simply not matched, which is correct: only
//! `COS_OEM` (ext) is the target.
//!
//! ## Scope
//! This module *finds* the partition. Re-reading the partition table after the
//! write, mounting it (`nodev,nosuid,noexec`), injecting `99_beskar7.yaml`, and
//! the unmount/reboot/cleanup invariants (§9.1 5.3–5.5) are the deploy
//! orchestrator's job (next module).
//!
//! ## Secret hygiene (§9)
//! No secrets pass through here — a filesystem label and partition/disk names are
//! non-secret. [`OemError`] carries only the target disk name, safe to log.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use crate::probe::read_trimmed;
use crate::target_disk::TargetDisk;

/// Kernel whole-block-device directory; a disk's partitions are its subdirectories.
const SYSFS_BLOCK: &str = "/sys/block";

/// The Kairos OEM filesystem label the per-host cloud-config is injected into.
const OEM_LABEL: &str = "COS_OEM";

/// ext2/3/4 superblock starts 1024 bytes into the partition.
const EXT_SB_OFFSET: usize = 1024;
/// `s_magic` (`__le16`) sits at superblock offset `0x38`.
const EXT_MAGIC_OFFSET: usize = EXT_SB_OFFSET + 0x38;
/// The ext superblock magic.
const EXT_MAGIC: u16 = 0xEF53;
/// `s_volume_name` (the label) is 16 bytes at superblock offset `0x78`.
const EXT_LABEL_OFFSET: usize = EXT_SB_OFFSET + 0x78;
/// Length of the `s_volume_name` field.
const EXT_LABEL_LEN: usize = 16;
/// How many bytes to read from a partition to cover the ext superblock + label.
/// The superblock spans bytes 1024..2048, so 2048 captures the whole field.
const SUPERBLOCK_READ_BYTES: usize = 2048;

/// The located `COS_OEM` partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OemPartition {
    /// The partition's kernel name (and `/sys/block/<disk>/<kname>` subdir name),
    /// e.g. `nvme0n1p4` or `sda3`.
    pub kname: String,
    /// The partition's `major:minor`, read from `/sys/block/<disk>/<kname>/dev`
    /// at enumeration time (empty only if that attribute was unreadable). The
    /// deploy step MUST `open("/dev/<kname>")` and verify the opened node's
    /// `st_rdev` matches this before mounting — so the device mounted is provably
    /// the enumerated child partition of the target disk, not a `/dev` node
    /// repointed since enumeration (§9.1 5.3 parentage check).
    pub dev_number: String,
}

impl OemPartition {
    /// The `/dev` node to mount.
    pub fn dev_path(&self) -> String {
        format!("/dev/{}", self.kname)
    }
}

/// Why the `COS_OEM` partition could not be located. Both variants carry only the
/// non-secret target disk name (§9), so a logged `OemError` is safe.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OemError {
    /// The target disk exposes no partitions — the image write did not produce a
    /// partition table, or it has not been re-read into the kernel yet. The
    /// inspector MUST abort rather than search elsewhere (§9.1 5.3).
    #[error("target disk {disk:?} has no partitions after the image write")]
    NoPartitions {
        /// The target disk kernel name.
        disk: String,
    },
    /// The target disk has partitions, but none is labeled `COS_OEM`. The
    /// inspector MUST abort — it MUST NOT mount a `COS_OEM` on a different disk.
    #[error("target disk {disk:?} has no COS_OEM partition")]
    NotFound {
        /// The target disk kernel name.
        disk: String,
    },
}

/// Locate the `COS_OEM` partition on `target` against the live host (contract
/// §9.1 5.3). Reads each of the target disk's own partitions' ext labels.
pub fn find_oem_partition(target: &TargetDisk) -> Result<OemPartition, OemError> {
    find_oem_in(Path::new(SYSFS_BLOCK), &target.kname, |part| {
        read_ext_label_of_device(part)
    })
}

/// Pure locator over an injected `/sys/block`-shaped `block_dir` and a label
/// reader, so the target-scoping (finding H1) and the not-found/no-partition
/// aborts are unit-tested without real partitions. `label_of` maps a partition
/// kernel name to its filesystem label (`None` if unlabeled / not ext).
fn find_oem_in(
    block_dir: &Path,
    disk: &str,
    label_of: impl Fn(&str) -> Option<String>,
) -> Result<OemPartition, OemError> {
    let parts = target_partitions(block_dir, disk);
    if parts.is_empty() {
        return Err(OemError::NoPartitions {
            disk: disk.to_string(),
        });
    }
    for part in parts {
        if label_of(&part).as_deref() == Some(OEM_LABEL) {
            let dev_number =
                read_trimmed(&block_dir.join(disk).join(&part).join("dev")).unwrap_or_default();
            return Ok(OemPartition {
                kname: part,
                dev_number,
            });
        }
    }
    Err(OemError::NotFound {
        disk: disk.to_string(),
    })
}

/// The target disk's own partitions, in stable name order: the subdirectories of
/// `/sys/block/<disk>/` that carry a `partition` attribute (the kernel marks each
/// partition node with one; `queue`/`slaves`/`device`/… do not). This structural
/// enumeration is what keeps the `COS_OEM` search confined to the target disk
/// (finding H1) — there is no system-wide scan to go wrong.
fn target_partitions(block_dir: &Path, disk: &str) -> Vec<String> {
    let disk_dir = block_dir.join(disk);
    let Ok(entries) = fs::read_dir(&disk_dir) else {
        return Vec::new();
    };
    let mut parts: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| disk_dir.join(name).join("partition").exists())
        .collect();
    parts.sort();
    parts
}

/// Read the ext2/3/4 filesystem label from the leading bytes of a partition. The
/// superblock starts at [`EXT_SB_OFFSET`]; the magic ([`EXT_MAGIC`]) gates it, and
/// the 16-byte `s_volume_name` (NUL-padded) is the label. `None` if `buf` is too
/// short, the magic is absent (not ext / not formatted), or the label is empty.
fn ext_label(buf: &[u8]) -> Option<String> {
    if buf.len() < EXT_LABEL_OFFSET + EXT_LABEL_LEN {
        return None;
    }
    let magic = u16::from_le_bytes([buf[EXT_MAGIC_OFFSET], buf[EXT_MAGIC_OFFSET + 1]]);
    if magic != EXT_MAGIC {
        return None;
    }
    let raw = &buf[EXT_LABEL_OFFSET..EXT_LABEL_OFFSET + EXT_LABEL_LEN];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let label = std::str::from_utf8(&raw[..end]).ok()?.to_string();
    (!label.is_empty()).then_some(label)
}

/// Open `/dev/<part_kname>` and read its ext label, or `None` on any I/O error or
/// non-ext/unlabeled partition. Reads up to [`SUPERBLOCK_READ_BYTES`]; a partition
/// shorter than that (or unreadable) simply yields no label.
fn read_ext_label_of_device(part_kname: &str) -> Option<String> {
    let path = format!("/dev/{part_kname}");
    let mut file = File::open(&path).ok()?;
    let mut buf = vec![0u8; SUPERBLOCK_READ_BYTES];
    let n = read_up_to(&mut file, &mut buf).ok()?;
    ext_label(&buf[..n])
}

/// Fill `buf` from `reader`, returning how many bytes were read (which may be
/// fewer than `buf.len()` at EOF). Loops over short reads; a real superblock-
/// bearing partition always yields the full buffer.
fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::testutil::{write, Scratch};
    use std::collections::HashMap;

    /// Build a 2048-byte ext-superblock prefix with `magic` and `label`.
    fn ext_superblock(magic: u16, label: &str) -> Vec<u8> {
        let mut buf = vec![0u8; SUPERBLOCK_READ_BYTES];
        buf[EXT_MAGIC_OFFSET..EXT_MAGIC_OFFSET + 2].copy_from_slice(&magic.to_le_bytes());
        let bytes = label.as_bytes();
        let n = bytes.len().min(EXT_LABEL_LEN);
        buf[EXT_LABEL_OFFSET..EXT_LABEL_OFFSET + n].copy_from_slice(&bytes[..n]);
        buf
    }

    /// Create a partition subdir `/sys/block/<disk>/<part>/{partition,dev}` for
    /// each partition (numbered `259:<idx+1>`), plus some non-partition siblings
    /// the enumeration must ignore.
    fn write_disk_with_partitions(root: &Path, disk: &str, parts: &[&str]) {
        // Non-partition siblings that must be filtered out.
        write(root, &format!("{disk}/queue/rotational"), "0\n");
        write(root, &format!("{disk}/size"), "1000\n");
        write(root, &format!("{disk}/device/model"), "Disk\n");
        for (i, p) in parts.iter().enumerate() {
            write(root, &format!("{disk}/{p}/partition"), "1\n");
            write(
                root,
                &format!("{disk}/{p}/dev"),
                &format!("259:{}\n", i + 1),
            );
        }
    }

    #[test]
    fn ext_label_reads_cos_oem() {
        let sb = ext_superblock(EXT_MAGIC, "COS_OEM");
        assert_eq!(ext_label(&sb).as_deref(), Some("COS_OEM"));
    }

    #[test]
    fn ext_label_rejects_wrong_magic() {
        let sb = ext_superblock(0x1234, "COS_OEM");
        assert_eq!(ext_label(&sb), None);
    }

    #[test]
    fn ext_label_rejects_empty_label() {
        let sb = ext_superblock(EXT_MAGIC, "");
        assert_eq!(ext_label(&sb), None);
    }

    #[test]
    fn ext_label_reads_other_labels_verbatim() {
        let sb = ext_superblock(EXT_MAGIC, "COS_PERSISTENT");
        assert_eq!(ext_label(&sb).as_deref(), Some("COS_PERSISTENT"));
    }

    #[test]
    fn ext_label_handles_full_16_byte_label_without_nul() {
        // Exactly 16 chars, no NUL terminator: the whole field is the label.
        let sb = ext_superblock(EXT_MAGIC, "ABCDEFGHIJKLMNOP");
        assert_eq!(ext_label(&sb).as_deref(), Some("ABCDEFGHIJKLMNOP"));
    }

    #[test]
    fn ext_label_rejects_truncated_buffer() {
        let short = vec![0u8; EXT_LABEL_OFFSET]; // one byte short of the label
        assert_eq!(ext_label(&short), None);
    }

    #[test]
    fn target_partitions_lists_only_partitions_sorted() {
        let s = Scratch::new("oem-parts");
        write_disk_with_partitions(
            s.path(),
            "nvme0n1",
            &["nvme0n1p1", "nvme0n1p4", "nvme0n1p2"],
        );
        let parts = target_partitions(s.path(), "nvme0n1");
        assert_eq!(parts, vec!["nvme0n1p1", "nvme0n1p2", "nvme0n1p4"]);
    }

    #[test]
    fn find_oem_returns_the_labeled_partition() {
        let s = Scratch::new("oem-found");
        write_disk_with_partitions(s.path(), "sda", &["sda1", "sda2", "sda3"]);
        // sda1 = EFI (vfat, no ext label), sda2 = COS_STATE, sda3 = COS_OEM.
        let labels = HashMap::from([
            ("sda1", None),
            ("sda2", Some("COS_STATE".to_string())),
            ("sda3", Some("COS_OEM".to_string())),
        ]);
        let got = find_oem_in(s.path(), "sda", |p| labels.get(p).cloned().flatten()).unwrap();
        assert_eq!(got.kname, "sda3");
        assert_eq!(got.dev_path(), "/dev/sda3");
        // dev_number is carried for B3b-2b's st_rdev re-verify (sda3 is the 3rd partition).
        assert_eq!(got.dev_number, "259:3");
    }

    #[test]
    fn find_oem_returns_the_labeled_nvme_partition() {
        // A Kairos image on an NVMe namespace: partitions are nvme0n1p<N>, with
        // the `p` separator. The real /sys/block/nvme0n1/ also holds `mq`,
        // `holders`, `slaves` and `power` beside `queue`/`device`; none is a
        // partition, and the disk itself is never one of its own partitions.
        let s = Scratch::new("oem-nvme");
        write_disk_with_partitions(
            s.path(),
            "nvme0n1",
            &["nvme0n1p1", "nvme0n1p2", "nvme0n1p3", "nvme0n1p4"],
        );
        for sibling in [
            "mq/0/cpu_list",
            "holders/.keep",
            "slaves/.keep",
            "power/control",
        ] {
            write(s.path(), &format!("nvme0n1/{sibling}"), "\n");
        }
        assert_eq!(
            target_partitions(s.path(), "nvme0n1"),
            vec!["nvme0n1p1", "nvme0n1p2", "nvme0n1p3", "nvme0n1p4"]
        );

        // p1 = EFI (vfat), p2 = COS_OEM, p3 = COS_RECOVERY, p4 = COS_STATE.
        let labels = HashMap::from([
            ("nvme0n1p1", None),
            ("nvme0n1p2", Some("COS_OEM".to_string())),
            ("nvme0n1p3", Some("COS_RECOVERY".to_string())),
            ("nvme0n1p4", Some("COS_STATE".to_string())),
        ]);
        let got = find_oem_in(s.path(), "nvme0n1", |p| labels.get(p).cloned().flatten()).unwrap();
        assert_eq!(got.kname, "nvme0n1p2");
        assert_eq!(got.dev_path(), "/dev/nvme0n1p2");
        assert_eq!(got.dev_number, "259:2");
    }

    #[test]
    fn find_oem_on_a_bare_nvme_namespace_reports_no_partitions() {
        // A namespace whose partition table has not been re-read yet: only the
        // disk's own attributes, which must not be taken for partitions.
        let s = Scratch::new("oem-nvme-bare");
        write(s.path(), "nvme0n1/queue/rotational", "0\n");
        write(s.path(), "nvme0n1/size", "1000\n");
        write(s.path(), "nvme0n1/dev", "259:0\n");
        write(s.path(), "nvme0n1/device/model", "QEMU NVMe Ctrl\n");
        let err = find_oem_in(s.path(), "nvme0n1", |_| Some("COS_OEM".to_string())).unwrap_err();
        assert_eq!(
            err,
            OemError::NoPartitions {
                disk: "nvme0n1".into()
            }
        );
    }

    #[test]
    fn find_oem_aborts_when_no_partition_is_labeled_cos_oem() {
        let s = Scratch::new("oem-absent");
        write_disk_with_partitions(s.path(), "sda", &["sda1", "sda2"]);
        let labels = HashMap::from([
            ("sda1", Some("COS_GRUB".to_string())),
            ("sda2", Some("COS_STATE".to_string())),
        ]);
        let err = find_oem_in(s.path(), "sda", |p| labels.get(p).cloned().flatten()).unwrap_err();
        assert_eq!(err, OemError::NotFound { disk: "sda".into() });
    }

    #[test]
    fn find_oem_aborts_when_disk_has_no_partitions() {
        let s = Scratch::new("oem-nopart");
        // A disk dir with only non-partition siblings.
        write(s.path(), "sda/queue/rotational", "0\n");
        write(s.path(), "sda/size", "1000\n");
        let err = find_oem_in(s.path(), "sda", |_| None).unwrap_err();
        assert_eq!(err, OemError::NoPartitions { disk: "sda".into() });
    }

    #[test]
    fn find_oem_is_confined_to_the_target_disk() {
        // Finding H1: a COS_OEM on ANOTHER disk must not be matched. The locator
        // only enumerates /sys/block/<target>/, so an sdb/COS_OEM is invisible.
        let s = Scratch::new("oem-scoped");
        write_disk_with_partitions(s.path(), "sda", &["sda1"]); // target, no COS_OEM
        write_disk_with_partitions(s.path(), "sdb", &["sdb1"]); // decoy with COS_OEM
        let labels = HashMap::from([
            ("sda1", Some("COS_STATE".to_string())),
            ("sdb1", Some("COS_OEM".to_string())), // would be captured by a global scan
        ]);
        let err = find_oem_in(s.path(), "sda", |p| labels.get(p).cloned().flatten()).unwrap_err();
        assert_eq!(
            err,
            OemError::NotFound { disk: "sda".into() },
            "must NOT reach across to sdb's COS_OEM"
        );
    }

    #[test]
    fn find_oem_picks_first_cos_oem_in_name_order() {
        // Defensive: if two partitions somehow share the label, the lowest-numbered
        // (name-sorted) is chosen deterministically.
        let s = Scratch::new("oem-dup");
        write_disk_with_partitions(s.path(), "sda", &["sda5", "sda2"]);
        let got = find_oem_in(s.path(), "sda", |_| Some("COS_OEM".to_string())).unwrap();
        assert_eq!(got.kname, "sda2");
    }

    #[test]
    fn read_up_to_fills_from_a_slice_reader() {
        let data = vec![7u8; SUPERBLOCK_READ_BYTES];
        let mut buf = vec![0u8; SUPERBLOCK_READ_BYTES];
        let n = read_up_to(&mut data.as_slice(), &mut buf).unwrap();
        assert_eq!(n, SUPERBLOCK_READ_BYTES);
        assert_eq!(buf, data);
    }

    #[test]
    fn read_up_to_stops_at_short_eof() {
        let data = vec![1u8; 100];
        let mut buf = vec![0u8; SUPERBLOCK_READ_BYTES];
        let n = read_up_to(&mut data.as_slice(), &mut buf).unwrap();
        assert_eq!(n, 100);
    }
}
