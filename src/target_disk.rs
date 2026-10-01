//! Target-disk selection for provisioning (contract §9.1 step 2).
//!
//! Phase 2 writes a whole-disk OS image to **one** block device. Picking that
//! device wrong is destructive — it can clobber a disk the operator meant to
//! keep, or (after the image is written and `COS_OEM` is mounted, §9.1 step 5.3)
//! land the CAPI join secret on the wrong medium. This module is the single place
//! that decision is made, kept separate from [`crate::probe::disk`] (which builds
//! the *report's* `disks[]`): selection has its own eligibility predicates and a
//! pinned-override path the report collector does not.
//!
//! ## Policy (contract §5 `beskar7.disk`, §9.1 step 2)
//!   * **Pinned** (`beskar7.disk` set): resolve the operator's value — a
//!     `/dev/...` path (including a `by-id`/`by-path` symlink) or a bare kernel
//!     name — **once** to its canonical whole-disk kernel name, then use exactly
//!     that device. Abort (never silently fall back) if it is missing, a
//!     partition / non-physical node, removable, read-only, backs the running
//!     system, or is smaller than the floor. A wrong pin fails loudly.
//!   * **Auto** (`beskar7.disk` absent): the **smallest** eligible whole disk.
//!     "Smallest" keeps provisioning off an oversized data disk when a modest
//!     boot disk exists; ties break by kernel-name order for determinism.
//!
//! ## Eligibility ([`Ineligible`])
//! A candidate whole disk is eligible iff it is **physical** (has a backing
//! `device` link, excluding `loop`/`ram`/`zram`/`dm-*`/`md*`), **non-removable**,
//! **writable** (`ro` == 0), **not backing the running system**, and **larger
//! than the floor** (and non-empty — an empty card-reader slot reads size 0).
//!
//! The "backs the running system" predicate resolves each `/proc/mounts` source
//! to the physical whole disk(s) underneath it — including through
//! device-mapper (LVM/LUKS) and `md` RAID, by walking `/sys/block/<dev>/slaves/`
//! recursively (contract §9.1 step 2; for a PXE initramfs whose `/` is RAM-backed
//! this set is empty, but a disk-booted or LVM-rooted inspector must never
//! overwrite itself). The bias is deliberately to **over-exclude** on ambiguity:
//! a disk wrongly excluded merely shrinks the candidate set, whereas a system
//! disk wrongly *included* is a self-clobber.
//!
//! Note the policy is "any **unmounted** disk is fair game": a disk that is not
//! backing the running system is eligible even if it holds a valuable existing
//! filesystem or partition table — it will be overwritten. This matches the
//! Ironic/Metal³ "clean disk" posture; the operator pins `beskar7.disk` (or
//! removes the spare) to protect data they want to keep.
//!
//! ## Testability
//! Every decision is a pure function over an injected `/sys/block`-shaped tree
//! and parsed `/proc/mounts` text ([`select_core`], [`classify`], [`auto_select`],
//! [`backing_whole_disks`], [`strip_partition_suffix`]). The live entry point
//! [`select`] only resolves the real paths (and canonicalizes `/dev` symlinks)
//! and delegates. No real block device is touched here — this module *chooses*;
//! writing/mounting is the deploy orchestrator's job (§9.1 step 5).
//!
//! ## Secret hygiene (§9)
//! This module handles no secrets. `beskar7.disk` and device names are non-secret
//! (§5), so [`DiskError`] values — which echo the offending name to aid the
//! operator — are safe to log in full.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::probe::read_trimmed;

/// Kernel whole-block-device directory: one subdirectory per whole disk
/// (partitions are nested inside their parent and so never appear here).
const SYSFS_BLOCK: &str = "/sys/block";
/// Per-device class directory: lists whole disks *and* partitions, the latter
/// carrying a `partition` attribute. Used to tell a pinned partition apart from a
/// pinned whole disk for a precise error.
const SYSFS_CLASS_BLOCK: &str = "/sys/class/block";
/// The kernel's mount table; its block-device sources reveal which disks back the
/// running system and must be excluded from selection.
const PROC_MOUNTS: &str = "/proc/mounts";
/// Active swap areas. A swap *partition* of the system disk appears here, not in
/// `/proc/mounts`, so it is folded into the exclusion set too (a disk holding
/// live swap must not be overwritten).
const PROC_SWAPS: &str = "/proc/swaps";

/// `size` attribute unit: Linux reports block-device size in 512-byte sectors.
const BYTES_PER_SECTOR: u64 = 512;
/// Bound on `slaves/` recursion depth — generous for any real dm/md stack
/// (LUKS-on-LVM-on-md is depth 3), a backstop against a pathological cycle the
/// visited-set already guards.
const MAX_SLAVE_DEPTH: u32 = 16;

const REMOVABLE_TRUE: &str = "1";
const READ_ONLY_TRUE: &str = "1";

/// The selected deployment target: a whole block device by kernel name + size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetDisk {
    /// Kernel name and `/sys/block` directory name, e.g. `nvme0n1` or `sda`.
    pub kname: String,
    /// Capacity in bytes.
    pub size_bytes: u64,
    /// The device's `major:minor` number, read from `/sys/block/<kname>/dev` at
    /// selection time (empty only if that attribute was unreadable). The deploy
    /// step (§9.1 step 5.1) MUST `open("/dev/<kname>")` and verify the opened
    /// node's `st_rdev` matches this before writing, so a `/dev` node repointed
    /// between selection and open (udev re-enumeration, hot-plug) cannot redirect
    /// the write — the device validated here is provably the device written
    /// (contract §5 "no TOCTOU re-lookup").
    pub dev_number: String,
}

impl TargetDisk {
    /// The `/dev` node to open for the whole-disk write (§9.1 step 5.1).
    pub fn dev_path(&self) -> String {
        format!("/dev/{}", self.kname)
    }
}

/// Why a disk could not be used. All variants carry only non-secret device names
/// / sizes (§5), so logging a `DiskError` cannot leak anything sensitive.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DiskError {
    /// `beskar7.disk` named a path that does not exist or could not be resolved.
    #[error("pinned disk {pin:?} does not exist or could not be resolved")]
    PinNotFound {
        /// The operator's `beskar7.disk` value.
        pin: String,
    },
    /// The pin resolved to a name with no `/sys/block` entry and no `partition`
    /// marker — not a block device at all.
    #[error("pinned disk {kname:?} is not a block device")]
    PinNotBlockDevice {
        /// The resolved kernel name.
        kname: String,
    },
    /// The pin resolved to a partition (or other non-whole-disk node). The
    /// inspector writes whole-disk images, so a partition pin is rejected outright
    /// rather than promoted to its parent (contract §5 / §9.1 step 2).
    #[error("pinned disk {kname:?} is a partition, not a whole disk")]
    PinNotWholeDisk {
        /// The resolved kernel name.
        kname: String,
    },
    /// The pin resolved to a real whole disk that fails an eligibility predicate.
    #[error("pinned disk {kname:?} is ineligible: {reason}")]
    PinIneligible {
        /// The resolved kernel name.
        kname: String,
        /// The specific predicate that rejected it.
        reason: Ineligible,
    },
    /// Auto-selection found no eligible whole disk.
    #[error("no eligible target disk found")]
    NoEligibleDisk,
}

/// The specific reason a whole disk failed eligibility (contract §9.1 step 2).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Ineligible {
    /// No backing `device` link — a virtual device (`loop`/`ram`/`zram`/`dm`/`md`),
    /// not a physical disk to deploy onto.
    #[error("not a physical disk (no backing device)")]
    NotPhysical,
    /// Removable media (USB/optical) — not durable host storage.
    #[error("removable media")]
    Removable,
    /// Read-only (`ro` == 1) — cannot be written.
    #[error("read-only device")]
    ReadOnly,
    /// A partition of this disk is mounted by the running system (e.g. it backs
    /// `/`, directly or through LVM/md); writing it would clobber the live
    /// inspector.
    #[error("backs the running system")]
    SystemBacking,
    /// Reports size 0 — an empty slot (e.g. a card reader with no card).
    #[error("empty (zero-size) device")]
    Empty,
    /// Smaller than the required floor (the image cannot fit).
    #[error("too small: {size_bytes} bytes < required {min_bytes} bytes")]
    TooSmall {
        /// The device's capacity.
        size_bytes: u64,
        /// The floor it failed to meet.
        min_bytes: u64,
    },
}

/// One whole-disk candidate with the raw `/sys/block` attributes selection needs.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    kname: String,
    size_bytes: u64,
    dev_number: String,
    removable: bool,
    read_only: bool,
    /// Has a backing `device` link (distinguishes physical disks from virtual ones).
    physical: bool,
}

impl Candidate {
    fn target(&self) -> TargetDisk {
        TargetDisk {
            kname: self.kname.clone(),
            size_bytes: self.size_bytes,
            dev_number: self.dev_number.clone(),
        }
    }
}

/// Select the target disk against the live host (contract §9.1 step 2). `pin` is
/// the optional `beskar7.disk` value; `min_bytes` is the size floor (pass 0 when
/// the image size is not yet known — the deploy step additionally caps the write
/// at the disk's capacity, §8.1).
pub fn select(pin: Option<&str>, min_bytes: u64) -> Result<TargetDisk, DiskError> {
    let block = Path::new(SYSFS_BLOCK);
    let class_block = Path::new(SYSFS_CLASS_BLOCK);
    let resolved = match pin {
        Some(p) => Some(resolve_pin_to_kname(p)?),
        None => None,
    };
    let ramdisk = ramdisk_backing_knames(block);
    select_core(block, class_block, resolved.as_deref(), min_bytes, &ramdisk)
}

/// Pure selection over an injected `/sys/block`-shaped `block_dir` and
/// `/sys/class/block`-shaped `class_block_dir`. `pin` is an already-resolved
/// whole-disk kernel name (or `None` for auto-select). Separated from [`select`]
/// so the policy is unit-tested without a live host.
fn select_core(
    block_dir: &Path,
    class_block_dir: &Path,
    pin: Option<&str>,
    min_bytes: u64,
    ramdisk: &BTreeSet<String>,
) -> Result<TargetDisk, DiskError> {
    let candidates = enumerate(block_dir);
    match pin {
        Some(kname) => {
            if let Some(c) = candidates.iter().find(|c| c.kname == kname) {
                match classify(c, min_bytes, ramdisk) {
                    Ok(()) => Ok(c.target()),
                    Err(reason) => Err(DiskError::PinIneligible {
                        kname: kname.to_string(),
                        reason,
                    }),
                }
            } else if is_partition(class_block_dir, kname) {
                Err(DiskError::PinNotWholeDisk {
                    kname: kname.to_string(),
                })
            } else {
                Err(DiskError::PinNotBlockDevice {
                    kname: kname.to_string(),
                })
            }
        }
        None => auto_select(&candidates, min_bytes, ramdisk),
    }
}

/// Enumerate whole disks under `block_dir` in stable name order, reading the
/// attributes [`classify`] needs. Unreadable directories yield no candidates
/// (degenerate, not fatal).
fn enumerate(block_dir: &Path) -> Vec<Candidate> {
    let Ok(entries) = fs::read_dir(block_dir) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    names
        .iter()
        .map(|kname| {
            let dev = block_dir.join(kname);
            let size_bytes = read_trimmed(&dev.join("size"))
                .and_then(|s| s.parse::<u64>().ok())
                .map(|sectors| sectors * BYTES_PER_SECTOR)
                .unwrap_or(0);
            Candidate {
                kname: kname.clone(),
                size_bytes,
                dev_number: read_trimmed(&dev.join("dev")).unwrap_or_default(),
                removable: read_trimmed(&dev.join("removable")).as_deref() == Some(REMOVABLE_TRUE),
                read_only: read_trimmed(&dev.join("ro")).as_deref() == Some(READ_ONLY_TRUE),
                physical: dev.join("device").exists(),
            }
        })
        .collect()
}

/// Apply the eligibility predicates (contract §9.1 step 2) to one candidate.
/// Ordered most-categorical first so the reported reason is the most informative.
fn classify(c: &Candidate, min_bytes: u64, ramdisk: &BTreeSet<String>) -> Result<(), Ineligible> {
    if !c.physical {
        return Err(Ineligible::NotPhysical);
    }
    if c.removable {
        return Err(Ineligible::Removable);
    }
    if c.read_only {
        return Err(Ineligible::ReadOnly);
    }
    if ramdisk.contains(&c.kname) {
        return Err(Ineligible::SystemBacking);
    }
    if c.size_bytes == 0 {
        return Err(Ineligible::Empty);
    }
    if c.size_bytes < min_bytes {
        return Err(Ineligible::TooSmall {
            size_bytes: c.size_bytes,
            min_bytes,
        });
    }
    Ok(())
}

/// Smallest eligible whole disk, ties broken by name order (candidates are
/// pre-sorted, and `min_by_key` keeps the first minimum) for determinism.
fn auto_select(
    candidates: &[Candidate],
    min_bytes: u64,
    ramdisk: &BTreeSet<String>,
) -> Result<TargetDisk, DiskError> {
    candidates
        .iter()
        .filter(|c| classify(c, min_bytes, ramdisk).is_ok())
        .min_by_key(|c| c.size_bytes)
        .map(Candidate::target)
        .ok_or(DiskError::NoEligibleDisk)
}

/// Whether `kname` is a partition: it has no whole-disk `/sys/block` entry but
/// does carry a `partition` attribute under `/sys/class/block`.
fn is_partition(class_block_dir: &Path, kname: &str) -> bool {
    class_block_dir.join(kname).join("partition").exists()
}

/// Resolve an operator `beskar7.disk` value to a whole-disk kernel name. A value
/// containing `/` is treated as a path and canonicalized once (following any
/// `by-id`/`by-path` symlink), so the name validated is the name written — no
/// TOCTOU re-lookup (contract §5). A bare value is used as the kernel name
/// directly. Whole-disk-vs-partition adjudication happens in [`select_core`]
/// against `/sys`.
fn resolve_pin_to_kname(pin: &str) -> Result<String, DiskError> {
    let kname = if pin.contains('/') {
        let canonical = fs::canonicalize(pin).map_err(|_| DiskError::PinNotFound {
            pin: pin.to_string(),
        })?;
        kname_of_path(&canonical).ok_or(DiskError::PinNotFound {
            pin: pin.to_string(),
        })?
    } else {
        pin.to_string()
    };
    if kname.is_empty() {
        return Err(DiskError::PinNotFound {
            pin: pin.to_string(),
        });
    }
    Ok(kname)
}

/// The final path component of a resolved `/dev/<name>` device node.
fn kname_of_path(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
}

/// Kernel names of whole disks that back the running system, read best-effort
/// from `/proc/mounts` **and** `/proc/swaps`. Empty on any read error (and,
/// normally, for a PXE initramfs whose `/` is RAM-backed and which has no swap).
fn ramdisk_backing_knames(block_dir: &Path) -> BTreeSet<String> {
    let mut sources: Vec<String> = Vec::new();
    if let Ok(mounts) = fs::read_to_string(PROC_MOUNTS) {
        sources.extend(mount_sources(&mounts));
    }
    if let Ok(swaps) = fs::read_to_string(PROC_SWAPS) {
        sources.extend(swap_sources(&swaps));
    }
    let leaves = sources.iter().filter_map(|src| live_dev_leaf(src));
    backing_whole_disks(leaves, block_dir)
}

/// The `/dev/...` sources (first whitespace field) of each `/proc/mounts` line —
/// virtual sources (`tmpfs`, `proc`, `overlay`, …) are dropped.
fn mount_sources(mounts: &str) -> impl Iterator<Item = String> + '_ {
    mounts.lines().filter_map(|line| {
        let src = line.split_ascii_whitespace().next()?;
        src.starts_with("/dev/").then(|| src.to_string())
    })
}

/// The `/dev/...` swap devices from `/proc/swaps` (first field of each line
/// after the header). A swap *file* (a non-`/dev/` path) is skipped — it lives on
/// an already-mounted filesystem, so its disk is excluded via `/proc/mounts`.
fn swap_sources(swaps: &str) -> impl Iterator<Item = String> + '_ {
    swaps.lines().skip(1).filter_map(|line| {
        let src = line.split_ascii_whitespace().next()?;
        src.starts_with("/dev/").then(|| src.to_string())
    })
}

/// Canonicalize a `/dev` source to its `/sys/block` leaf kernel name, following
/// device-mapper (`/dev/mapper/<vg>-<lv>` → `/dev/dm-N`) and `by-id` symlinks.
/// Live (touches `/dev`). If canonicalization fails (a stale or synthesized
/// source such as `/dev/root`), it falls back to the source's own basename rather
/// than dropping it — preserving the over-exclude bias (a name that resolves to
/// nothing merely fails to shrink the candidate set).
fn live_dev_leaf(source: &str) -> Option<String> {
    let leaf = match fs::canonicalize(source) {
        Ok(canonical) => canonical.file_name()?.to_str()?.to_string(),
        Err(_) => Path::new(source).file_name()?.to_str()?.to_string(),
    };
    (!leaf.is_empty()).then_some(leaf)
}

/// Resolve each already-canonicalized mount-source leaf to the set of **physical
/// whole disks** backing it, recursing `slaves/` for dm/md stacks and stripping a
/// partition leaf to its parent disk. Pure over the injected `block_dir`, so the
/// security-critical self-clobber resolution is unit-tested without a live host.
fn backing_whole_disks(leaves: impl Iterator<Item = String>, block_dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for leaf in leaves {
        let mut visited = BTreeSet::new();
        collect_physical(&leaf, block_dir, MAX_SLAVE_DEPTH, &mut visited, &mut out);
    }
    out
}

/// Accumulate the physical whole disks backing `leaf` into `out`:
///   * a top-level `/sys/block/<leaf>` with **non-empty** `slaves/` is a dm/md
///     aggregate — recurse into each slave;
///   * a top-level entry with empty/absent `slaves/` is a physical whole disk —
///     add it;
///   * a name with **no** `/sys/block` entry is a partition (or a just-removed
///     device) — add its parent whole disk via [`strip_partition_suffix`].
///
/// `visited` guards against a `slaves/` cycle; `depth` is a hard backstop.
fn collect_physical(
    leaf: &str,
    block_dir: &Path,
    depth: u32,
    visited: &mut BTreeSet<String>,
    out: &mut BTreeSet<String>,
) {
    if depth == 0 || !visited.insert(leaf.to_string()) {
        return;
    }
    let dev = block_dir.join(leaf);
    if dev.exists() {
        let slaves = slave_names(&dev.join("slaves"));
        if slaves.is_empty() {
            out.insert(leaf.to_string());
        } else {
            for slave in slaves {
                collect_physical(&slave, block_dir, depth - 1, visited, out);
            }
        }
    } else if let Some(parent) = parent_whole_disk(block_dir, leaf) {
        // Authoritative: a partition is a subdirectory of its whole disk
        // (`/sys/block/<disk>/<leaf>`). This is the only reliable way to tell a
        // partition apart from a whole disk whose name ends in a digit
        // (`nvme0n1` vs `sda1`).
        out.insert(parent);
    } else {
        // Fallback (race / unknown topology): strip a partition suffix by string
        // shape, biased to over-exclude (a wrong name merely shrinks candidates).
        out.insert(strip_partition_suffix(leaf));
    }
}

/// The whole disk that owns partition `part`, found authoritatively: a partition
/// appears as a subdirectory `/sys/block/<disk>/<part>` of its parent disk. Scans
/// `block_dir` for the disk containing `part`. `None` if no such parent is
/// enumerable (the device was removed, or `part` is not actually a partition).
fn parent_whole_disk(block_dir: &Path, part: &str) -> Option<String> {
    let entries = fs::read_dir(block_dir).ok()?;
    for entry in entries.flatten() {
        if entry.path().join(part).is_dir() {
            return entry.file_name().into_string().ok();
        }
    }
    None
}

/// The entries of a `slaves/` directory (each a symlink to a backing device); the
/// file names are the backing devices' kernel names. Empty if the directory is
/// absent or unreadable.
fn slave_names(slaves_dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(slaves_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

/// Best-effort string fallback used only when [`parent_whole_disk`] cannot
/// authoritatively resolve a partition's owner (race, or unknown topology).
/// Strips a trailing partition number — and the `p` separator that
/// `nvme`/`mmc`/`md`/`loop` names use before it — to approximate the parent
/// (`nvme0n1p3` → `nvme0n1`, `sda2` → `sda`, `mmcblk0p1` → `mmcblk0`). It
/// **cannot** disambiguate a whole disk whose name ends in a digit (`nvme0n1`
/// would be mangled to `nvme0n`), which is exactly why the authoritative
/// subdirectory scan is tried first; reaching this fallback on a real whole disk
/// merely over-excludes a non-existent name (harmless).
fn strip_partition_suffix(name: &str) -> String {
    let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
    trimmed
        .strip_suffix('p')
        .filter(|base| base.chars().next_back().is_some_and(|c| c.is_ascii_digit()))
        .unwrap_or(trimmed)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::testutil::{write, Scratch};
    use std::os::unix::fs::symlink;

    /// 512-byte sectors for a whole-of-`gb`-decimal-GB disk.
    fn sectors_for_gb(gb: u64) -> u64 {
        gb * 1_000_000_000 / BYTES_PER_SECTOR
    }

    /// Write a whole-disk `/sys/block/<kname>` fixture with the given attributes.
    fn write_disk(root: &Path, kname: &str, gb: u64, removable: bool, read_only: bool) {
        write(
            root,
            &format!("{kname}/size"),
            &format!("{}\n", sectors_for_gb(gb)),
        );
        write(root, &format!("{kname}/dev"), "8:0\n");
        write(
            root,
            &format!("{kname}/removable"),
            if removable { "1\n" } else { "0\n" },
        );
        write(
            root,
            &format!("{kname}/ro"),
            if read_only { "1\n" } else { "0\n" },
        );
        // A backing `device` link marks it physical.
        write(root, &format!("{kname}/device/model"), "Test Disk\n");
    }

    /// Write a virtual device (no `device` link), e.g. a `dm`/`loop` node.
    fn write_virtual(root: &Path, kname: &str, gb: u64) {
        write(
            root,
            &format!("{kname}/size"),
            &format!("{}\n", sectors_for_gb(gb)),
        );
        write(root, &format!("{kname}/removable"), "0\n");
        write(root, &format!("{kname}/ro"), "0\n");
    }

    /// Mark a device a slave of `parent` (a `/sys/block/<parent>/slaves/<child>`
    /// entry); the kernel uses symlinks but a plain dir suffices for the read.
    fn write_slave(root: &Path, parent: &str, child: &str) {
        write(root, &format!("{parent}/slaves/{child}/_"), "");
    }

    /// Create a partition `part` under whole disk `disk`
    /// (`/sys/block/<disk>/<part>/`), as the kernel exposes it — this is what
    /// `parent_whole_disk` scans for to resolve a partition to its owner.
    fn write_partition(root: &Path, disk: &str, part: &str) {
        write(root, &format!("{disk}/{part}/partition"), "1\n");
    }

    fn no_ramdisk() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn auto_selects_smallest_eligible_disk() {
        let s = Scratch::new("auto-smallest");
        write_disk(s.path(), "sda", 2000, false, false);
        write_disk(s.path(), "nvme0n1", 480, false, false);
        write_disk(s.path(), "sdb", 1000, false, false);
        let class = Scratch::new("auto-smallest-class");

        let picked = select_core(s.path(), class.path(), None, 0, &no_ramdisk()).expect("a disk");
        assert_eq!(picked.kname, "nvme0n1");
        assert_eq!(picked.size_bytes, 480 * 1_000_000_000);
        assert_eq!(picked.dev_number, "8:0");
    }

    #[test]
    fn auto_excludes_removable_readonly_virtual_and_empty() {
        let s = Scratch::new("auto-exclude");
        write_disk(s.path(), "sda", 500, true, false); // removable
        write_disk(s.path(), "sdb", 500, false, true); // read-only
        write_virtual(s.path(), "dm-0", 100); // no device link
                                              // empty slot: physical, zero size.
        write(s.path(), "mmcblk0/size", "0\n");
        write(s.path(), "mmcblk0/removable", "0\n");
        write(s.path(), "mmcblk0/ro", "0\n");
        write(s.path(), "mmcblk0/device/model", "Reader\n");
        // the one good disk:
        write_disk(s.path(), "nvme0n1", 960, false, false);
        let class = Scratch::new("auto-exclude-class");

        let picked = select_core(s.path(), class.path(), None, 0, &no_ramdisk()).expect("a disk");
        assert_eq!(picked.kname, "nvme0n1");
    }

    #[test]
    fn auto_excludes_ramdisk_backing_device() {
        let s = Scratch::new("auto-ramdisk");
        write_disk(s.path(), "sda", 480, false, false); // smallest, but backs the system
        write_disk(s.path(), "nvme0n1", 960, false, false);
        let class = Scratch::new("auto-ramdisk-class");
        let mut ramdisk = BTreeSet::new();
        ramdisk.insert("sda".to_string());

        let picked = select_core(s.path(), class.path(), None, 0, &ramdisk).expect("a disk");
        assert_eq!(picked.kname, "nvme0n1", "must skip the smaller system disk");
    }

    #[test]
    fn auto_respects_the_size_floor() {
        let s = Scratch::new("auto-floor");
        write_disk(s.path(), "sda", 100, false, false);
        write_disk(s.path(), "sdb", 800, false, false);
        let class = Scratch::new("auto-floor-class");

        // Floor of 500 GB excludes sda; sdb is the smallest that still fits.
        let floor = 500 * 1_000_000_000;
        let picked = select_core(s.path(), class.path(), None, floor, &no_ramdisk()).expect("disk");
        assert_eq!(picked.kname, "sdb");
    }

    #[test]
    fn auto_with_no_eligible_disk_errors() {
        let s = Scratch::new("auto-none");
        write_disk(s.path(), "sda", 500, true, false); // removable
        write_virtual(s.path(), "loop0", 100);
        let class = Scratch::new("auto-none-class");

        let err = select_core(s.path(), class.path(), None, 0, &no_ramdisk()).unwrap_err();
        assert_eq!(err, DiskError::NoEligibleDisk);
    }

    #[test]
    fn pinned_eligible_disk_is_used_exactly() {
        let s = Scratch::new("pin-ok");
        write_disk(s.path(), "sda", 480, false, false); // smaller; auto would pick this
        write_disk(s.path(), "nvme0n1", 960, false, false);
        let class = Scratch::new("pin-ok-class");

        let picked =
            select_core(s.path(), class.path(), Some("nvme0n1"), 0, &no_ramdisk()).expect("disk");
        assert_eq!(picked.kname, "nvme0n1", "pin overrides smallest-eligible");
    }

    #[test]
    fn pinned_removable_disk_aborts_without_fallback() {
        let s = Scratch::new("pin-removable");
        write_disk(s.path(), "sdb", 500, true, false); // pinned but removable
        write_disk(s.path(), "nvme0n1", 960, false, false); // an eligible alternative exists
        let class = Scratch::new("pin-removable-class");

        let err = select_core(s.path(), class.path(), Some("sdb"), 0, &no_ramdisk()).unwrap_err();
        assert_eq!(
            err,
            DiskError::PinIneligible {
                kname: "sdb".to_string(),
                reason: Ineligible::Removable,
            },
            "a bad pin must fail loudly, never fall back to nvme0n1"
        );
    }

    #[test]
    fn pinned_too_small_disk_reports_sizes() {
        let s = Scratch::new("pin-small");
        write_disk(s.path(), "sda", 100, false, false);
        let class = Scratch::new("pin-small-class");
        let floor = 500 * 1_000_000_000;

        let err =
            select_core(s.path(), class.path(), Some("sda"), floor, &no_ramdisk()).unwrap_err();
        assert_eq!(
            err,
            DiskError::PinIneligible {
                kname: "sda".to_string(),
                reason: Ineligible::TooSmall {
                    size_bytes: 100 * 1_000_000_000,
                    min_bytes: floor,
                },
            }
        );
    }

    #[test]
    fn pinned_system_backing_disk_aborts() {
        let s = Scratch::new("pin-system");
        write_disk(s.path(), "sda", 960, false, false);
        let class = Scratch::new("pin-system-class");
        let mut ramdisk = BTreeSet::new();
        ramdisk.insert("sda".to_string());

        let err = select_core(s.path(), class.path(), Some("sda"), 0, &ramdisk).unwrap_err();
        assert_eq!(
            err,
            DiskError::PinIneligible {
                kname: "sda".to_string(),
                reason: Ineligible::SystemBacking,
            }
        );
    }

    #[test]
    fn pinned_partition_is_rejected_as_not_whole_disk() {
        let s = Scratch::new("pin-part");
        write_disk(s.path(), "sda", 960, false, false);
        // /sys/class/block/sda1 carries a `partition` attribute; no /sys/block/sda1.
        let class = Scratch::new("pin-part-class");
        write(class.path(), "sda1/partition", "1\n");

        let err = select_core(s.path(), class.path(), Some("sda1"), 0, &no_ramdisk()).unwrap_err();
        assert_eq!(
            err,
            DiskError::PinNotWholeDisk {
                kname: "sda1".to_string()
            }
        );
    }

    #[test]
    fn pinned_nonexistent_name_is_not_a_block_device() {
        let s = Scratch::new("pin-absent");
        write_disk(s.path(), "sda", 960, false, false);
        let class = Scratch::new("pin-absent-class");

        let err = select_core(s.path(), class.path(), Some("sdz"), 0, &no_ramdisk()).unwrap_err();
        assert_eq!(
            err,
            DiskError::PinNotBlockDevice {
                kname: "sdz".to_string()
            }
        );
    }

    #[test]
    fn pinned_virtual_device_is_ineligible_not_physical() {
        let s = Scratch::new("pin-virtual");
        write_virtual(s.path(), "dm-0", 500);
        let class = Scratch::new("pin-virtual-class");

        let err = select_core(s.path(), class.path(), Some("dm-0"), 0, &no_ramdisk()).unwrap_err();
        assert_eq!(
            err,
            DiskError::PinIneligible {
                kname: "dm-0".to_string(),
                reason: Ineligible::NotPhysical,
            }
        );
    }

    #[test]
    fn target_disk_dev_path() {
        let t = TargetDisk {
            kname: "nvme0n1".into(),
            size_bytes: 0,
            dev_number: "259:0".into(),
        };
        assert_eq!(t.dev_path(), "/dev/nvme0n1");
    }

    // --- self-clobber backing resolution (the H1 concern) -------------------

    #[test]
    fn backing_resolves_lvm_dm_to_physical_parent() {
        // `/` on LVM: /dev/mapper/vg-root -> dm-0, whose slave is the partition
        // nvme1n1p3, whose parent disk is nvme1n1.
        let s = Scratch::new("backing-lvm");
        write_virtual(s.path(), "dm-0", 500);
        write_slave(s.path(), "dm-0", "nvme1n1p3");
        // nvme1n1p3 is a partition under its whole disk, NOT a top-level entry.
        write_partition(s.path(), "nvme1n1", "nvme1n1p3");
        let set = backing_whole_disks(["dm-0".to_string()].into_iter(), s.path());
        assert!(set.contains("nvme1n1"), "set: {set:?}");
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn backing_resolves_md_raid_to_all_members() {
        // /dev/md0 striping sda1 + sdb1 -> both sda and sdb back the system.
        let s = Scratch::new("backing-md");
        write_virtual(s.path(), "md0", 1000);
        write_slave(s.path(), "md0", "sda1");
        write_slave(s.path(), "md0", "sdb1");
        write_partition(s.path(), "sda", "sda1");
        write_partition(s.path(), "sdb", "sdb1");
        let set = backing_whole_disks(["md0".to_string()].into_iter(), s.path());
        assert!(set.contains("sda"), "set: {set:?}");
        assert!(set.contains("sdb"), "set: {set:?}");
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn backing_resolves_stacked_dm_on_dm() {
        // LUKS-on-LVM: dm-1 -> dm-0 -> nvme0n1p3 -> nvme0n1.
        let s = Scratch::new("backing-stacked");
        write_virtual(s.path(), "dm-1", 500);
        write_virtual(s.path(), "dm-0", 500);
        write_slave(s.path(), "dm-1", "dm-0");
        write_slave(s.path(), "dm-0", "nvme0n1p3");
        write_partition(s.path(), "nvme0n1", "nvme0n1p3");
        let set = backing_whole_disks(["dm-1".to_string()].into_iter(), s.path());
        assert_eq!(set, BTreeSet::from(["nvme0n1".to_string()]));
    }

    #[test]
    fn backing_resolves_nvme_partition_authoritatively_not_by_string() {
        // The bug the authoritative scan fixes: nvme1n1p3's parent is nvme1n1,
        // and the *whole disk* nvme1n1 (name ends in a digit) must never be
        // mangled to "nvme1n". A bare /dev/nvme1n1p3 source resolves correctly.
        let s = Scratch::new("backing-nvme-auth");
        write_partition(s.path(), "nvme1n1", "nvme1n1p3");
        let set = backing_whole_disks(["nvme1n1p3".to_string()].into_iter(), s.path());
        assert_eq!(set, BTreeSet::from(["nvme1n1".to_string()]));
    }

    #[test]
    fn backing_slaves_cycle_is_bounded() {
        // A pathological dm-0 <-> dm-1 cycle must terminate, not recurse forever.
        let s = Scratch::new("backing-cycle");
        write_virtual(s.path(), "dm-0", 500);
        write_virtual(s.path(), "dm-1", 500);
        write_slave(s.path(), "dm-0", "dm-1");
        write_slave(s.path(), "dm-1", "dm-0");
        // Should return without hanging; no physical leaf exists in the cycle.
        let set = backing_whole_disks(["dm-0".to_string()].into_iter(), s.path());
        assert!(set.is_empty(), "set: {set:?}");
    }

    #[test]
    fn backing_unresolvable_partition_falls_back_to_string_strip() {
        // No enumerable parent (e.g. a just-removed device): the string fallback
        // approximates the parent, biased to over-exclude. nvme1n1p2 -> nvme1n1.
        let s = Scratch::new("backing-fallback");
        let set = backing_whole_disks(["nvme1n1p2".to_string()].into_iter(), s.path());
        assert_eq!(set, BTreeSet::from(["nvme1n1".to_string()]));
    }

    #[test]
    fn backing_plain_whole_disk_source_is_kept() {
        // A filesystem on a whole disk (no partition table): the source IS the
        // disk; /sys/block/sdb exists with empty slaves.
        let s = Scratch::new("backing-whole");
        write_disk(s.path(), "sdb", 1000, false, false);
        let set = backing_whole_disks(["sdb".to_string()].into_iter(), s.path());
        assert_eq!(set, BTreeSet::from(["sdb".to_string()]));
    }

    #[test]
    fn auto_select_excludes_lvm_backed_system_disk_end_to_end() {
        // The H1 regression: with `/` on LVM over the *smaller* disk, auto-select
        // must skip it even though smallest-eligible would otherwise pick it.
        let s = Scratch::new("h1-e2e");
        write_disk(s.path(), "nvme1n1", 480, false, false); // smaller; backs `/` via LVM
        write_disk(s.path(), "nvme0n1", 960, false, false); // the spare to deploy to
        write_virtual(s.path(), "dm-0", 480);
        write_slave(s.path(), "dm-0", "nvme1n1p3");
        write_partition(s.path(), "nvme1n1", "nvme1n1p3");
        let class = Scratch::new("h1-e2e-class");

        let ramdisk = backing_whole_disks(["dm-0".to_string()].into_iter(), s.path());
        assert!(ramdisk.contains("nvme1n1"));
        let picked = select_core(s.path(), class.path(), None, 0, &ramdisk).expect("a disk");
        assert_eq!(
            picked.kname, "nvme0n1",
            "must not deploy onto the LVM-backed system disk"
        );
    }

    // --- mount-source parsing -----------------------------------------------

    #[test]
    fn mount_sources_keeps_dev_and_drops_virtual() {
        let mounts = "\
rootfs / rootfs rw 0 0
/dev/mapper/vg-root / ext4 rw 0 0
/dev/nvme1n1p2 /boot/efi vfat rw 0 0
tmpfs /run tmpfs rw 0 0
proc /proc proc rw 0 0
overlay /var/lib/docker overlay rw 0 0
";
        let got: Vec<String> = mount_sources(mounts).collect();
        assert_eq!(got, vec!["/dev/mapper/vg-root", "/dev/nvme1n1p2"]);
    }

    #[test]
    fn swap_sources_skips_header_and_swapfiles() {
        let swaps = "\
Filename				Type		Size	Used	Priority
/dev/sda3                               partition	8388604	0	-2
/dev/mapper/vg-swap                     partition	4194300	0	-3
/swapfile                               file		2097148	0	-4
";
        let got: Vec<String> = swap_sources(swaps).collect();
        assert_eq!(got, vec!["/dev/sda3", "/dev/mapper/vg-swap"]);
    }

    #[test]
    fn strip_partition_suffix_handles_standard_partition_schemes() {
        // Fallback only — inputs here are partition names, the only case this is
        // called for (the authoritative scan handles whole disks).
        assert_eq!(strip_partition_suffix("sda2"), "sda");
        assert_eq!(strip_partition_suffix("nvme0n1p3"), "nvme0n1");
        assert_eq!(strip_partition_suffix("mmcblk0p1"), "mmcblk0");
        assert_eq!(strip_partition_suffix("md0p2"), "md0");
        // An sd*-style name with no trailing digit is returned unchanged.
        assert_eq!(strip_partition_suffix("sda"), "sda");
    }

    #[test]
    fn strip_partition_suffix_handles_multi_digit_nvme_names() {
        // Controller, namespace and partition numbers can all exceed 9; only the
        // trailing `p<N>` is stripped, never the namespace's `n<N>`.
        assert_eq!(strip_partition_suffix("nvme0n1p12"), "nvme0n1");
        assert_eq!(strip_partition_suffix("nvme10n2p1"), "nvme10n2");
        assert_eq!(strip_partition_suffix("nvme1n12p3"), "nvme1n12");
    }

    // --- NVMe end to end ------------------------------------------------------

    #[test]
    fn nvme_whole_disk_with_partitions_is_selected_not_a_partition() {
        // After a prior deploy the NVMe namespace carries partitions. They live
        // under /sys/block/nvme0n1/ (never top-level), so the candidate is the
        // whole disk nvme0n1 — which, ending in a digit, must not be read as a
        // partition of some "nvme0n" disk.
        let s = Scratch::new("nvme-whole");
        write_disk(s.path(), "nvme0n1", 480, false, false);
        for p in ["nvme0n1p1", "nvme0n1p2", "nvme0n1p3"] {
            write_partition(s.path(), "nvme0n1", p);
        }
        let class = Scratch::new("nvme-whole-class");
        for p in ["nvme0n1p1", "nvme0n1p2", "nvme0n1p3"] {
            write(class.path(), &format!("{p}/partition"), "1\n");
        }

        let names: Vec<String> = enumerate(s.path()).into_iter().map(|c| c.kname).collect();
        assert_eq!(names, vec!["nvme0n1"]);
        let auto = select_core(s.path(), class.path(), None, 0, &no_ramdisk()).expect("a disk");
        assert_eq!(auto.kname, "nvme0n1");
        assert_eq!(auto.dev_path(), "/dev/nvme0n1");
        let pinned =
            select_core(s.path(), class.path(), Some("nvme0n1"), 0, &no_ramdisk()).expect("disk");
        assert_eq!(pinned.kname, "nvme0n1");
    }

    #[test]
    fn pinned_nvme_partition_is_rejected_as_not_whole_disk() {
        let s = Scratch::new("pin-nvme-part");
        write_disk(s.path(), "nvme0n1", 960, false, false);
        write_partition(s.path(), "nvme0n1", "nvme0n1p3");
        let class = Scratch::new("pin-nvme-part-class");
        write(class.path(), "nvme0n1p3/partition", "1\n");

        let err =
            select_core(s.path(), class.path(), Some("nvme0n1p3"), 0, &no_ramdisk()).unwrap_err();
        assert_eq!(
            err,
            DiskError::PinNotWholeDisk {
                kname: "nvme0n1p3".to_string()
            }
        );
    }

    // --- pin resolution -----------------------------------------------------

    #[test]
    fn resolve_pin_follows_a_symlink_to_its_kname() {
        // Emulate /dev/disk/by-id/X -> ../../sdc. canonicalize() resolves the
        // symlink; kname_of_path takes the final component.
        let s = Scratch::new("resolve-symlink");
        let target = s.path().join("sdc");
        fs::write(&target, b"").unwrap();
        let link = s.path().join("by-id-link");
        symlink(&target, &link).unwrap();

        let kname = resolve_pin_to_kname(link.to_str().unwrap()).expect("resolved");
        assert_eq!(kname, "sdc");
    }

    #[test]
    fn resolve_pin_bare_name_is_passed_through() {
        assert_eq!(resolve_pin_to_kname("nvme0n1").unwrap(), "nvme0n1");
    }

    #[test]
    fn resolve_pin_nonexistent_path_errors() {
        let err = resolve_pin_to_kname("/dev/disk/by-id/does-not-exist-xyz").unwrap_err();
        assert_eq!(
            err,
            DiskError::PinNotFound {
                pin: "/dev/disk/by-id/does-not-exist-xyz".to_string()
            }
        );
    }
}
