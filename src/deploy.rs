//! Phase 2 deploy — write the digest-verified target image, inject the per-host
//! config, and reboot into the provisioned OS (contract §9.1 step 5).
//!
//! This is the **destructive** half of provisioning. It runs in five live steps,
//! each gated by the one before:
//!   1. [`write_image`] (§9.1 5.1–5.2) — stream the whole-disk OS image
//!      (`beskar7.target`) straight onto the block device chosen by
//!      [`crate::target_disk`], verifying it against `beskar7.target-digest`.
//!   2. [`reread_partition_table`] (§9.1 5.3) — `BLKRRPART` so the freshly-written
//!      image's partitions appear; the caller then locates the ESP
//!      ([`crate::esp`]) and `COS_OEM` ([`crate::oem`]).
//!   3. [`inject_startup_nsh`] — mount the ESP (`vfat`, `nodev,nosuid,noexec`),
//!      write the EFI Shell `startup.nsh` that chain-loads the disk's loader on
//!      the first boot (no NVRAM entry exists for the new disk yet), `fsync`, and
//!      unmount. Runs before step 4 so a failure here leaves no join secret on disk.
//!   4. [`inject_oem_config`] (§9.1 5.3–5.4) — mount the `COS_OEM` partition
//!      (`nodev,nosuid,noexec`), write the per-host Kairos cloud-config
//!      (`99_beskar7.yaml`, carrying the CAPI join secret) and the P2 provider-id
//!      artifact (`beskar7/provider-id`, `b7://<ns>/<host>` verbatim) — both
//!      `0600`/root — `fsync` files + directories, and unmount.
//!   5. [`reboot_now`] (§9.1 5.4) — `reboot(2)` into the provisioned OS.
//!
//! The image digest covers only the bytes streamed in step 1; the ESP and
//! `COS_OEM` writes happen after verification and do not affect it.
//!
//! ## Identity, never a re-resolvable path (TOCTOU guard, §5 / §9.1 5.3)
//! Neither destructive operation trusts a `/dev/<kname>` path it could re-resolve
//! to the wrong device:
//!   * The **whole-disk write** opens `/dev/<kname>` once (`O_EXCL`), then checks
//!     the *held fd's* `st_rdev` against [`TargetDisk::dev_number`] and that it is a
//!     block device — the check and the write share one fd, so nothing can repoint
//!     the device between them. `O_EXCL` also fails `EBUSY` on a mounted-but-not-
//!     system disk rather than clobbering it.
//!   * The **`COS_OEM` and ESP mounts** do not mount a `/dev` path at all: each
//!     `mknod`s a private block node from the partition's enumerated `major:minor`
//!     ([`crate::oem::OemPartition::dev_number`], [`crate::esp::EspPartition::dev_number`])
//!     and mounts that, so the mount is bound to the exact kernel device enumerated
//!     on the target disk — immune to a `/dev` node being repointed between
//!     enumeration and mount.
//!
//! ## Bounded, RAM-free, digest-gated write (§8.1)
//! The image is streamed by [`crate::image::ImageFetcher::fetch_to`], hashing
//! incrementally (never buffering the multi-GB body) and returning `Ok` **only**
//! on a full-length digest match, bounded by `min(build max, disk capacity)`. On
//! any mismatch/short-read/size-breach the caller MUST NOT proceed to
//! mount/inject/reboot; the unbootable disk is recovered on the next attempt.
//!
//! ## Mount lifetime & failure cleanup (§9.1 5.4–5.5, finding H2)
//! [`inject_startup_nsh`] and [`inject_oem_config`] share one mount lifecycle
//! (`with_private_mount`). [`inject_oem_config`] **always unmounts `COS_OEM` before returning**, on
//! success or failure (falling back to a lazy `MNT_DETACH` if the eager unmount is
//! busy) — so the partition is never left mounted across a reboot or a drop to a
//! debug shell. On an inject failure it first removes the partial `99_beskar7.yaml`
//! (which may hold the join secret) and the partial `beskar7/provider-id`, and
//! *then* unmounts (§9.1 step 8). (Unlinking the partial
//! frees but does not wipe its ext blocks on the target disk; that freed-block
//! remanence is accepted — the secret lives on this disk by design, and the disk
//! is unbootable until the next attempt overwrites the whole device.)
//!
//! ## Secret hygiene (§9)
//! The image and its digest are public. The **CAPI join secret** flows through
//! [`inject_oem_config`] as the `user_data` bytes: it is written **only** to the
//! `0600`/root `99_beskar7.yaml` on the verified `COS_OEM` partition, never
//! logged, and never placed in a [`DeployError`] (every variant carries only
//! device paths / `major:minor` / public digests, all non-secret). The caller
//! zeroes its `user_data` buffer after [`inject_oem_config`] returns.

use std::fmt;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use nix::errno::Errno;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sys::reboot::{reboot, RebootMode};
use nix::sys::stat::{makedev, mknod, Mode, SFlag};

use crate::esp::EspPartition;
use crate::image::{ImageError, ImageFetcher, Sha256Digest};
use crate::oem::OemPartition;
use crate::target_disk::TargetDisk;

/// The per-host Kairos cloud-config filename injected into `COS_OEM`. The `99_`
/// prefix orders it after the image's baked-in OEM configs so it wins (§9.1 5.3).
const OEM_CONFIG_FILENAME: &str = "99_beskar7.yaml";
/// Subdirectory of the `COS_OEM` mount root holding the P2 provider-id artifact
/// (contract §9.1 5.4). Together with [`OEM_PROVIDER_ID_FILENAME`] this is the
/// mount-relative path `beskar7/provider-id`, which is `/oem/beskar7/provider-id`
/// once Kairos mounts `COS_OEM` at `/oem` on the provisioned OS.
const OEM_PROVIDER_ID_SUBDIR: &str = "beskar7";
/// The P2 provider-id artifact filename (contract §9.1 5.4). Holds the
/// `beskar7.provider-id` value (`b7://<ns>/<host>`) verbatim, so a *shared*
/// bootstrap stage can read a *per-host* kubelet `--provider-id` (D-014 P2).
const OEM_PROVIDER_ID_FILENAME: &str = "provider-id";
/// Private mountpoint for the `COS_OEM` partition during injection. Created and
/// removed by [`inject_oem_config`]; on a fresh boot nothing else uses it.
const OEM_MOUNTPOINT: &str = "/run/beskar7-oem";
/// Private block-device node [`inject_oem_config`] creates from the enumerated
/// partition's `major:minor` and mounts — so the mount binds to the verified
/// device number, never a `/dev` path that could be repointed (§9.1 5.3).
const OEM_DEV_NODE: &str = "/run/beskar7-oem.dev";

/// The EFI Shell script [`inject_startup_nsh`] writes to the ESP root. On the first
/// boot after the write the firmware has no NVRAM entry for the disk and may drop
/// into the EFI Shell, which runs `startup.nsh` after its countdown. The script
/// scans the shell mappings `FS0:`–`FSF:` (the ESP is not necessarily `FS0:`) for
/// the Ubuntu-based Kairos ESP and starts its fallback loader; the OS then creates
/// its permanent boot entry. CRLF line endings, as the EFI Shell expects.
const STARTUP_NSH: &str = concat!(
    "@echo -off\r\n",
    "for %i in 0 1 2 3 4 5 6 7 8 9 A B C D E F\r\n",
    "  if exist FS%i:\\EFI\\ubuntu\\grub.cfg then\r\n",
    "    if exist FS%i:\\EFI\\BOOT\\BOOTX64.EFI then\r\n",
    "      FS%i:\r\n",
    "      \\EFI\\BOOT\\BOOTX64.EFI\r\n",
    "    endif\r\n",
    "  endif\r\n",
    "endfor\r\n",
);
/// The script's filename in the ESP root, where the EFI Shell looks for it. FAT is
/// case-insensitive, so this replaces a `STARTUP.NSH` already in the image.
const STARTUP_NSH_FILENAME: &str = "startup.nsh";

/// The partition a deploy-time mount writes to. Names it in errors, and lets the
/// provision-failed reason tell the two inject steps apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// The Kairos `COS_OEM` partition (per-host config + provider-id).
    Oem,
    /// The EFI System Partition (`startup.nsh`).
    Esp,
}

impl fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Part::Oem => "COS_OEM",
            Part::Esp => "ESP",
        })
    }
}

/// How [`with_private_mount`] mounts one partition: a private device node and
/// mountpoint under `/run`, the filesystem type, and its mount options.
struct PrivateMount {
    part: Part,
    node: &'static str,
    mountpoint: &'static str,
    fstype: &'static str,
    data: Option<&'static str>,
}

/// `COS_OEM` is ext2/3/4, which the ext4 driver mounts.
const OEM_MOUNT: PrivateMount = PrivateMount {
    part: Part::Oem,
    node: OEM_DEV_NODE,
    mountpoint: OEM_MOUNTPOINT,
    fstype: "ext4",
    data: None,
};

/// The ESP is FAT. The codepage and charset are explicit so the mount needs only
/// the `nls_cp437` and `nls_ascii` modules the initramfs ships, whatever the
/// kernel's `CONFIG_FAT_DEFAULT_*` defaults are (Alpine's iocharset is `utf8`).
const ESP_MOUNT: PrivateMount = PrivateMount {
    part: Part::Esp,
    node: "/run/beskar7-esp.dev",
    mountpoint: "/run/beskar7-esp",
    fstype: "vfat",
    data: Some("codepage=437,iocharset=ascii"),
};

// BLKRRPART = _IO(0x12, 95): re-read a block device's partition table.
nix::ioctl_none!(blkrrpart, 0x12, 95);

/// Errors from the deploy path. All variants carry only non-secret material
/// (device paths, `major:minor` numbers, public digests, syscall errnos) — never
/// the join secret or image bytes — so logging a `DeployError` in full is safe (§9).
#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    /// A `/dev` node could not be opened (e.g. held exclusively, or permission
    /// denied).
    #[error("opening device {path}")]
    OpenTarget {
        /// The `/dev/<kname>` path.
        path: String,
        /// The underlying open error.
        #[source]
        source: std::io::Error,
    },
    /// The opened node is not a block device — refuse to touch it.
    #[error("device {path} is not a block device — refusing")]
    NotABlockDevice {
        /// The `/dev/<kname>` path.
        path: String,
    },
    /// The node's metadata could not be read to verify its identity.
    #[error("reading device {path} metadata")]
    Stat {
        /// The `/dev/<kname>` path.
        path: String,
        /// The underlying stat error.
        #[source]
        source: std::io::Error,
    },
    /// The device carried no `major:minor` to verify against, so identity cannot
    /// be confirmed — refuse rather than risk the wrong device (§5).
    #[error("device {path} has no recorded device number; cannot verify identity — refusing")]
    NoDeviceNumber {
        /// The `/dev/<kname>` path.
        path: String,
    },
    /// The opened node's `st_rdev` does not match the device selected/enumerated —
    /// the `/dev` node was repointed since. Refuse (§5 / §9.1 5.3 TOCTOU guard).
    #[error("device {path} identity changed since selection (expected dev {expected}, found {found}) — refusing")]
    DeviceIdentityMismatch {
        /// The `/dev/<kname>` path.
        path: String,
        /// The `major:minor` recorded at selection/enumeration time.
        expected: String,
        /// The `major:minor` of the node actually opened.
        found: String,
    },
    /// Building the image fetcher, streaming, or the digest verification failed
    /// (see [`ImageError`]). A [`ImageError::DigestMismatch`] here means the bytes
    /// on disk did not match `beskar7.target-digest`: the caller MUST NOT mount,
    /// inject, or reboot.
    #[error(transparent)]
    Image(#[from] ImageError),
    /// Flushing the written image to stable storage failed.
    #[error("flushing target disk to stable storage")]
    Sync(#[source] std::io::Error),
    /// Re-reading the partition table (`BLKRRPART`) failed — the freshly-written
    /// image's partitions did not become visible.
    #[error("re-reading the partition table of {path}")]
    Reread {
        /// The whole-disk `/dev/<kname>` path.
        path: String,
        /// The ioctl errno.
        #[source]
        source: Errno,
    },
    /// A partition mountpoint could not be created.
    #[error("creating the {part} mountpoint {path}")]
    Mountpoint {
        /// The partition being mounted.
        part: Part,
        /// The mountpoint path.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The enumerated partition `major:minor` could not be parsed, so the mount
    /// cannot be bound to a verified device number — refuse (§9.1 5.3).
    #[error("partition {dev} has no parseable device number; cannot bind the mount — refusing")]
    BadDeviceNumber {
        /// The partition `/dev/<kname>` path.
        dev: String,
    },
    /// Creating a private partition block-device node (`mknod`) failed.
    #[error("creating the {part} device node for {dev}")]
    MakeNode {
        /// The partition being mounted.
        part: Part,
        /// The partition `/dev/<kname>` path the node represents.
        dev: String,
        /// The mknod errno.
        #[source]
        source: Errno,
    },
    /// Mounting a partition failed.
    #[error("mounting {part} device {dev}")]
    Mount {
        /// The partition being mounted.
        part: Part,
        /// The partition `/dev/<kname>` path.
        dev: String,
        /// The mount errno.
        #[source]
        source: Errno,
    },
    /// Writing or flushing the per-host `99_beskar7.yaml` failed. The source is an
    /// I/O error only — it never contains the config contents (the join secret).
    #[error("writing the per-host COS_OEM config")]
    ConfigWrite(#[source] std::io::Error),
    /// Writing or flushing the P2 `beskar7/provider-id` artifact failed (§9.1 5.4).
    /// The value is non-secret (`b7://<ns>/<host>`), but the source is kept to an
    /// I/O error for symmetry with [`ConfigWrite`](Self::ConfigWrite).
    #[error("writing the COS_OEM provider-id artifact")]
    ProviderIdWrite(#[source] std::io::Error),
    /// Writing or flushing `startup.nsh` on the ESP failed.
    #[error("writing startup.nsh to the ESP")]
    StartupNshWrite(#[source] std::io::Error),
    /// Unmounting a partition failed.
    #[error("unmounting {part} at {path}")]
    Unmount {
        /// The partition being unmounted.
        part: Part,
        /// The mountpoint path.
        path: String,
        /// The umount errno.
        #[source]
        source: Errno,
    },
    /// The `reboot(2)` syscall itself failed (it does not return on success).
    #[error("reboot syscall failed")]
    Reboot(#[source] Errno),
}

/// Stream `image_url` onto `target`, verifying it against `target_digest`, and
/// flush it to stable storage (contract §9.1 steps 5.1–5.2). `build_max_bytes` is
/// the §8.1 build-default ceiling; the effective cap is the smaller of it and the
/// disk's capacity. Returns the number of bytes written on a verified match.
///
/// On a verified-matching digest this leaves the whole-disk image on the device,
/// flushed; the caller may then proceed to step 5.3 (re-read partitions, mount
/// `COS_OEM`, inject). On **any** error — including a digest mismatch — the caller
/// MUST NOT proceed; the (unverified, non-secret) bytes on disk are never booted
/// and are overwritten on the next attempt (§8.1).
pub fn write_image(
    target: &TargetDisk,
    image_url: &str,
    target_digest: &str,
    build_max_bytes: u64,
) -> Result<u64, DeployError> {
    let digest = Sha256Digest::parse(target_digest)?;
    let cap = effective_max_bytes(build_max_bytes, target.size_bytes);
    let path = target.dev_path();

    // O_EXCL on a block device is the kernel's *exclusive* open: it fails with
    // EBUSY if the device is mounted or already held by another opener. Selection
    // already excludes system-backing disks, but this is defense-in-depth against
    // clobbering a mounted-but-not-system disk (an operator data disk) — a clean
    // unmounted spare opens fine.
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_EXCL)
        .open(&path)
        .map_err(|source| DeployError::OpenTarget {
            path: path.clone(),
            source,
        })?;
    verify_node_identity(&file, &path, &target.dev_number)?;

    let fetcher = ImageFetcher::new();
    let written = fetcher.fetch_to(image_url, &digest, cap, &mut file)?;
    file.sync_all().map_err(DeployError::Sync)?;
    Ok(written)
}

/// The effective write ceiling: the smaller of the build maximum and the disk's
/// capacity (§8.1 — a whole-disk image larger than the disk can never deploy). A
/// `0` capacity (unknown) falls back to the build maximum, leaving the image
/// fetcher's own backstop as the only bound.
fn effective_max_bytes(build_max: u64, disk_capacity: u64) -> u64 {
    if disk_capacity == 0 {
        build_max
    } else {
        build_max.min(disk_capacity)
    }
}

/// Confirm the opened `file` is the intended block device: it must be a block
/// device, and its `st_rdev` must equal `expected_dev` (the `major:minor` recorded
/// at selection/enumeration). Refuses on any mismatch or when no device number was
/// recorded (§5 / §9.1 5.3 TOCTOU guard). Shared by the whole-disk write and the
/// `COS_OEM` partition mount.
pub(crate) fn verify_node_identity(
    file: &File,
    path: &str,
    expected_dev: &str,
) -> Result<(), DeployError> {
    if expected_dev.is_empty() {
        return Err(DeployError::NoDeviceNumber {
            path: path.to_string(),
        });
    }
    let meta = file.metadata().map_err(|source| DeployError::Stat {
        path: path.to_string(),
        source,
    })?;
    if !meta.file_type().is_block_device() {
        return Err(DeployError::NotABlockDevice {
            path: path.to_string(),
        });
    }
    match rdev_matches(meta.rdev(), expected_dev) {
        Ok(()) => Ok(()),
        Err(found) => Err(DeployError::DeviceIdentityMismatch {
            path: path.to_string(),
            expected: expected_dev.to_string(),
            found,
        }),
    }
}

/// Compare a raw `st_rdev` against an expected `"major:minor"` string (as
/// `/sys/block/<kname>/dev` renders it). `Ok(())` on a match; `Err(found)` carries
/// the actual `"major:minor"` for the mismatch diagnostic.
fn rdev_matches(rdev: u64, expected: &str) -> Result<(), String> {
    let found = format!(
        "{}:{}",
        nix::sys::stat::major(rdev),
        nix::sys::stat::minor(rdev)
    );
    if found == expected {
        Ok(())
    } else {
        Err(found)
    }
}

/// Re-read `target`'s partition table (`BLKRRPART`) so the freshly-written image's
/// partitions appear in `/sys` and `/dev` (contract §9.1 5.3). Re-opens the
/// whole-disk node and re-verifies its identity (§5) before the ioctl.
pub fn reread_partition_table(target: &TargetDisk) -> Result<(), DeployError> {
    let path = target.dev_path();
    let file = OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|source| DeployError::OpenTarget {
            path: path.clone(),
            source,
        })?;
    verify_node_identity(&file, &path, &target.dev_number)?;
    // SAFETY: `file` is an open block-device fd; BLKRRPART takes no argument and
    // only asks the kernel to re-scan that device's partition table.
    unsafe { blkrrpart(file.as_raw_fd()) }.map_err(|source| DeployError::Reread {
        path: path.clone(),
        source,
    })?;
    Ok(())
}

/// Mount the located ESP, write [`STARTUP_NSH`] to its root, and unmount. The
/// first boot after the write has no NVRAM boot entry for the disk; the EFI Shell
/// runs this script to chain-load the disk's loader, and the provisioned OS then
/// creates its permanent entry.
///
/// The mount is bound to the ESP's enumerated `major:minor` exactly as for
/// `COS_OEM` (see [`inject_oem_config`]), and the ESP is **always unmounted before
/// returning**. The script is non-secret; a partial one left by a failure is
/// harmless, since the deploy aborts and the next attempt rewrites the disk.
pub fn inject_startup_nsh(esp: &EspPartition) -> Result<(), DeployError> {
    with_private_mount(&ESP_MOUNT, &esp.dev_path(), &esp.dev_number, |mnt| {
        write_and_sync_startup_nsh(mnt)
    })
}

/// Mount the located `COS_OEM` partition, write the per-host Kairos cloud-config
/// (`99_beskar7.yaml`, carrying `user_data` — the CAPI join secret) and the P2
/// provider-id artifact (`beskar7/provider-id`, `provider_id` verbatim) into it,
/// and unmount (contract §9.1 5.3–5.5).
///
/// The mount is bound to the partition's **enumerated `major:minor`** (finding
/// H1 / §9.1 5.3 parentage check): rather than mounting a `/dev/<kname>` path that
/// could be repointed between enumeration and mount, this `mknod`s a private block
/// node from `oem.dev_number` and mounts *that* — so the device mounted is provably
/// the partition [`crate::oem`] enumerated on the target disk. `COS_OEM` is
/// **always unmounted before returning** — on success or failure — with the partial
/// artifacts removed first on failure (finding H2 / §9.1 step 8).
///
/// `user_data` is the join secret: it is written only to the `0600`/root file and
/// is never logged. `provider_id` (`b7://<ns>/<host>`) is non-secret and written
/// `0600`/root in the same mount session — no extra mount or fetch (§9.1 5.4). The
/// caller zeroes its `user_data` buffer after this returns.
pub fn inject_oem_config(
    oem: &OemPartition,
    user_data: &[u8],
    provider_id: &str,
) -> Result<(), DeployError> {
    with_private_mount(&OEM_MOUNT, &oem.dev_path(), &oem.dev_number, |mnt| {
        // Write both artifacts in this one mount session: 99_beskar7.yaml (the join
        // secret) then beskar7/provider-id (v4.2, §9.1 5.4). On failure, remove both
        // partials — the config may hold the join secret — BEFORE unmounting (finding
        // H2 / §9.1 step 8); with_private_mount unmounts only after this returns.
        // remove_file on a never-created path is a harmless no-op.
        let inject = write_and_sync_config(mnt, user_data)
            .and_then(|()| write_and_sync_provider_id(mnt, provider_id));
        if inject.is_err() {
            let _ = fs::remove_file(mnt.join(OEM_CONFIG_FILENAME));
            let _ = fs::remove_file(
                mnt.join(OEM_PROVIDER_ID_SUBDIR)
                    .join(OEM_PROVIDER_ID_FILENAME),
            );
        }
        inject
    })
}

/// Mount the partition `dev` (enumerated as `dev_number`) per `spec`, run `write`
/// against the mount root, and unmount. Shared by [`inject_startup_nsh`] and
/// [`inject_oem_config`]; always removes the private device node afterward.
fn with_private_mount(
    spec: &PrivateMount,
    dev: &str,
    dev_number: &str,
    write: impl FnOnce(&Path) -> Result<(), DeployError>,
) -> Result<(), DeployError> {
    let devnum = parse_dev_number(dev_number).ok_or_else(|| DeployError::BadDeviceNumber {
        dev: dev.to_string(),
    })?;

    // Bind to the kernel partition by its verified major:minor: create a private
    // block node from the enumerated devnum and mount THAT — no /dev path to
    // repoint (§9.1 5.3). `/run` is a fresh tmpfs the PID-1 inspector solely owns;
    // the remove_file clears any stale node from a prior attempt, and mknod(2) does
    // NOT follow a symlink at the final component (it fails EEXIST), so a planted
    // symlink at this path cannot redirect the node — do not "harden" this into an
    // O_NOFOLLOW open, which has different semantics that don't apply to mknod.
    let node = Path::new(spec.node);
    let _ = fs::remove_file(node);
    mknod(
        node,
        SFlag::S_IFBLK,
        Mode::from_bits_truncate(0o600),
        devnum,
    )
    .map_err(|source| DeployError::MakeNode {
        part: spec.part,
        dev: dev.to_string(),
        source,
    })?;

    let result = mount_write_unmount(spec, node, dev, write);
    let _ = fs::remove_file(node); // remove the private node after the mount lifetime
    result
}

/// The mount → write → unmount core, factored out so [`with_private_mount`] always
/// removes the private device node afterward. Mounts `node` (`nodev,nosuid,noexec`),
/// runs `write`, and **always unmounts before returning** (finding H2).
fn mount_write_unmount(
    spec: &PrivateMount,
    node: &Path,
    dev: &str,
    write: impl FnOnce(&Path) -> Result<(), DeployError>,
) -> Result<(), DeployError> {
    let mnt = Path::new(spec.mountpoint);
    fs::create_dir_all(mnt).map_err(|source| DeployError::Mountpoint {
        part: spec.part,
        path: spec.mountpoint.to_string(),
        source,
    })?;

    // nodev,nosuid,noexec: COS_OEM and the ESP are only written with config and
    // scripts here, never device nodes, setuid binaries, or executables (§9.1 5.3).
    let flags = MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;
    if let Err(source) = mount(Some(node), mnt, Some(spec.fstype), flags, spec.data) {
        let _ = fs::remove_dir(mnt);
        return Err(DeployError::Mount {
            part: spec.part,
            dev: dev.to_string(),
            source,
        });
    }

    let written = write(mnt);

    // Always unmount before returning — the partition is never left mounted across
    // a reboot or a drop to a debug shell (§9.1 5.4, finding H2). If the eager
    // unmount fails (e.g. EBUSY), fall back to a lazy MNT_DETACH so the mount is
    // still torn down before we return — the "detached before return" invariant is
    // unconditional. The original (eager) error is still surfaced to the caller.
    let unmount = match umount2(mnt, MntFlags::empty()) {
        Ok(()) => Ok(()),
        Err(eager) => {
            let _ = umount2(mnt, MntFlags::MNT_DETACH);
            Err(DeployError::Unmount {
                part: spec.part,
                path: spec.mountpoint.to_string(),
                source: eager,
            })
        }
    };
    let _ = fs::remove_dir(mnt); // best-effort tidy of the (now-empty) mountpoint

    // Surface the write failure first (more informative), then any unmount failure.
    written?;
    unmount?;
    Ok(())
}

/// Parse a `"major:minor"` string (as `/sys/block/.../dev` renders it) into a
/// `dev_t`, so the mount can be bound to the enumerated device number. Both parts
/// must be decimal integers; `None` otherwise (including an empty string).
fn parse_dev_number(s: &str) -> Option<nix::libc::dev_t> {
    let (major, minor) = s.split_once(':')?;
    let major: u64 = major.parse().ok()?;
    let minor: u64 = minor.parse().ok()?;
    Some(makedev(major, minor))
}

/// Write `contents` to `<mount_dir>/99_beskar7.yaml`, force mode `0600`, and
/// `fsync` both the file and its directory so the config is durable before the
/// unmount/reboot (contract §9.1 5.3–5.4). The file content is `user_data`
/// verbatim — v2 *places* a Kairos-compatible cloud-config, it does not transcode
/// (§9.1 5.3). Pure file I/O over an injected directory, so it is unit-tested
/// against a scratch dir without a real mount.
fn write_and_sync_config(mount_dir: &Path, contents: &[u8]) -> Result<(), DeployError> {
    let path = mount_dir.join(OEM_CONFIG_FILENAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(DeployError::ConfigWrite)?;
    // Force exactly 0600 regardless of the inherited umask — the file holds the
    // join secret and must never be group/other-readable.
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(DeployError::ConfigWrite)?;
    file.write_all(contents).map_err(DeployError::ConfigWrite)?;
    file.sync_all().map_err(DeployError::ConfigWrite)?;
    // fsync the directory so the new dirent survives the unmount/reboot.
    let dir = File::open(mount_dir).map_err(DeployError::ConfigWrite)?;
    dir.sync_all().map_err(DeployError::ConfigWrite)?;
    Ok(())
}

/// Write `provider_id` verbatim — **no trailing newline** — to
/// `<mount_dir>/beskar7/provider-id`, force mode `0600`, and `fsync` the file, its
/// `beskar7/` directory, and the mount root (so the new subdirectory's dirent is
/// durable) before the unmount/reboot (contract §9.1 5.4). The value is the
/// `beskar7.provider-id` cmdline param (`b7://<ns>/<host>`): non-secret, but written
/// `0600`/root to mirror the config's hygiene. A *shared* bootstrap stage reads
/// exactly these bytes to set a *per-host* kubelet `--provider-id` (D-014 P2), so a
/// trailing newline or wrong mode would corrupt a downstream consumer — the byte
/// exactness is pinned against the shared golden artifact fixture. Pure file I/O
/// over an injected directory, so it is unit-tested against a scratch dir without a
/// real mount.
fn write_and_sync_provider_id(mount_dir: &Path, provider_id: &str) -> Result<(), DeployError> {
    let dir = mount_dir.join(OEM_PROVIDER_ID_SUBDIR);
    fs::create_dir_all(&dir).map_err(DeployError::ProviderIdWrite)?;
    let path = dir.join(OEM_PROVIDER_ID_FILENAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(DeployError::ProviderIdWrite)?;
    // Force exactly 0600 regardless of the inherited umask.
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(DeployError::ProviderIdWrite)?;
    // Verbatim: exactly the cmdline bytes, no trailing newline — a shared bootstrap
    // stage consumes this as the literal ProviderID (§9.1 5.4).
    file.write_all(provider_id.as_bytes())
        .map_err(DeployError::ProviderIdWrite)?;
    file.sync_all().map_err(DeployError::ProviderIdWrite)?;
    // fsync the beskar7/ directory, then the mount root, so both the file and the
    // freshly-created subdirectory's dirent survive the unmount/reboot.
    let dirf = File::open(&dir).map_err(DeployError::ProviderIdWrite)?;
    dirf.sync_all().map_err(DeployError::ProviderIdWrite)?;
    let rootf = File::open(mount_dir).map_err(DeployError::ProviderIdWrite)?;
    rootf.sync_all().map_err(DeployError::ProviderIdWrite)?;
    Ok(())
}

/// Write [`STARTUP_NSH`] to `<mount_dir>/startup.nsh`, replacing any existing one,
/// and `fsync` the file and its directory so the script is durable before the
/// unmount/reboot. Pure file I/O over an injected directory, so it is unit-tested
/// against a scratch dir without a real mount.
fn write_and_sync_startup_nsh(mount_dir: &Path) -> Result<(), DeployError> {
    let path = mount_dir.join(STARTUP_NSH_FILENAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(DeployError::StartupNshWrite)?;
    file.write_all(STARTUP_NSH.as_bytes())
        .map_err(DeployError::StartupNshWrite)?;
    file.sync_all().map_err(DeployError::StartupNshWrite)?;
    let dir = File::open(mount_dir).map_err(DeployError::StartupNshWrite)?;
    dir.sync_all().map_err(DeployError::StartupNshWrite)?;
    Ok(())
}

/// `sync(2)` then `reboot(2)` into the provisioned OS (contract §9.1 5.4). Does
/// **not** return on success (the host reboots); the returned [`DeployError`] is
/// reachable only if the syscall fails. The caller MUST have unmounted `COS_OEM`
/// (via [`inject_oem_config`]) and zeroed the `user_data` buffer first.
pub fn reboot_now() -> DeployError {
    // Belt-and-suspenders: the COS_OEM unmount and the image write's sync_all
    // already made everything durable, but a final sync costs nothing.
    nix::unistd::sync();
    match reboot(RebootMode::RB_AUTOBOOT) {
        // RB_AUTOBOOT diverges on success, so Ok is unreachable.
        Ok(infallible) => match infallible {},
        Err(source) => DeployError::Reboot(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn effective_max_is_capped_by_a_small_disk() {
        // A disk smaller than the build max caps the write to the disk size — a
        // whole-disk image larger than the disk can never deploy (§8.1).
        let disk = 8 * GIB; // < 16 GiB build max
        assert_eq!(effective_max_bytes(16 * GIB, disk), disk);
    }

    #[test]
    fn effective_max_is_the_build_max_when_disk_is_larger() {
        // A 480 GB disk dwarfs the 16 GiB build max, which stays in force.
        let disk = 480 * 1_000_000_000;
        assert_eq!(effective_max_bytes(16 * GIB, disk), 16 * GIB);
    }

    #[test]
    fn effective_max_falls_back_to_build_max_for_unknown_capacity() {
        assert_eq!(effective_max_bytes(16 * GIB, 0), 16 * GIB);
    }

    #[test]
    fn rdev_matches_accepts_the_recorded_major_minor() {
        // makedev encodes the same major:minor sysfs reports, so a round trip
        // through the kernel's dev_t must compare equal.
        let rdev = nix::sys::stat::makedev(259, 0);
        assert!(rdev_matches(rdev, "259:0").is_ok());
    }

    #[test]
    fn rdev_mismatch_reports_the_found_major_minor() {
        let rdev = nix::sys::stat::makedev(8, 0);
        // The device was selected as 8:0 but the opened node is now 8:16.
        let opened = nix::sys::stat::makedev(8, 16);
        match rdev_matches(opened, "8:0") {
            Err(found) => assert_eq!(found, "8:16"),
            Ok(()) => panic!("expected a mismatch"),
        }
        // Sanity: the matching case for the same recorded value still passes.
        assert!(rdev_matches(rdev, "8:0").is_ok());
    }

    #[test]
    fn no_device_number_refuses_identity() {
        // An empty dev_number means selection could not read /sys/block/<k>/dev;
        // verify_node_identity must refuse before any write. The empty-dev_number
        // guard fires before metadata is inspected, so the node's nature is
        // irrelevant — /dev/null is just a stand-in open File.
        let f = File::open("/dev/null").expect("/dev/null opens");
        let err = verify_node_identity(&f, "/dev/nvme0n1", "").unwrap_err();
        assert!(
            matches!(err, DeployError::NoDeviceNumber { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn non_block_device_is_refused() {
        // /dev/null is a *character* device (1:3): identity verification must
        // reject it as not-a-block-device rather than write to it.
        let f = File::open("/dev/null").expect("/dev/null opens");
        let err = verify_node_identity(&f, "/dev/null", "1:3").unwrap_err();
        assert!(
            matches!(err, DeployError::NotABlockDevice { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn invalid_digest_is_rejected_before_opening_anything() {
        // write_image parses the digest first, so a malformed digest fails fast
        // without touching the (here nonexistent) device.
        let target = TargetDisk {
            kname: "does-not-exist-zzz".into(),
            size_bytes: 1024,
            dev_number: "8:0".into(),
        };
        let err = write_image(&target, "http://example/img.raw", "not-a-digest", 1024).unwrap_err();
        assert!(
            matches!(err, DeployError::Image(ImageError::InvalidDigestFormat)),
            "got {err:?}"
        );
    }

    #[test]
    fn write_and_sync_config_writes_0600_with_exact_contents() {
        let s = crate::probe::testutil::Scratch::new("oem-cfg");
        let user_data = b"#cloud-config\nstages:\n  boot:\n    - name: join\n";
        write_and_sync_config(s.path(), user_data).expect("config written");

        let path = s.path().join(OEM_CONFIG_FILENAME);
        let meta = std::fs::metadata(&path).expect("file exists");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "the join-secret config must be 0600"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            user_data,
            "contents verbatim"
        );
    }

    #[test]
    fn write_and_sync_config_truncates_a_previous_file() {
        // A retry must not leave stale trailing bytes from a longer prior write.
        let s = crate::probe::testutil::Scratch::new("oem-cfg-trunc");
        write_and_sync_config(s.path(), b"a much longer previous config body").unwrap();
        write_and_sync_config(s.path(), b"short").unwrap();
        let path = s.path().join(OEM_CONFIG_FILENAME);
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
    }

    #[test]
    fn config_filename_is_the_contract_numbered_name() {
        // The 99_ prefix orders it after the image's baked-in OEM configs (§9.1 5.3).
        assert_eq!(OEM_CONFIG_FILENAME, "99_beskar7.yaml");
    }

    #[test]
    fn write_and_sync_provider_id_matches_golden_artifact() {
        // Byte-pin the P2 write against the shared golden fixture (§9.1 5.4):
        // content verbatim, NO trailing newline, mode 0600, at the mount-relative
        // path the fixture's absolute artifactPath implies.
        const GOLDEN: &str = include_str!("../test/contract/golden_provider_id_artifact.json");
        let g: serde_json::Value = serde_json::from_str(GOLDEN).expect("golden artifact decodes");

        let content = g["content"].as_str().expect("golden content");
        let artifact_path = g["artifactPath"].as_str().expect("golden artifactPath");
        assert_eq!(g["mode"].as_str(), Some("0600"), "golden mode is 0600");
        assert_eq!(g["owner"].as_str(), Some("root"), "golden owner is root");
        assert_eq!(
            g["contentHasTrailingNewline"].as_bool(),
            Some(false),
            "golden asserts no trailing newline"
        );

        // The fixture path is absolute (`/oem/<relpath>`) — the eventual mountpoint;
        // our write is relative to the COS_OEM mount root, so strip `/oem/` and
        // confirm the module composes exactly that relative path.
        let relpath = artifact_path
            .strip_prefix("/oem/")
            .expect("artifactPath is under /oem/");
        assert_eq!(
            relpath,
            format!("{OEM_PROVIDER_ID_SUBDIR}/{OEM_PROVIDER_ID_FILENAME}"),
            "the write path must match the golden artifactPath"
        );

        let s = crate::probe::testutil::Scratch::new("oem-pid");
        write_and_sync_provider_id(s.path(), content).expect("provider-id written");

        let path = s
            .path()
            .join(OEM_PROVIDER_ID_SUBDIR)
            .join(OEM_PROVIDER_ID_FILENAME);
        let meta = std::fs::metadata(&path).expect("file exists");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "the provider-id artifact must be 0600"
        );
        // Raw byte read (never a String compare that could normalize a newline).
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes, content.as_bytes(), "content byte-verbatim");
        assert_ne!(
            bytes.last(),
            Some(&b'\n'),
            "the provider-id artifact must have NO trailing newline"
        );
    }

    #[test]
    fn write_and_sync_provider_id_truncates_a_previous_file() {
        // A retry must not leave stale trailing bytes from a longer prior write.
        let s = crate::probe::testutil::Scratch::new("oem-pid-trunc");
        write_and_sync_provider_id(s.path(), "b7://ns/a-much-longer-host-name").unwrap();
        write_and_sync_provider_id(s.path(), "b7://n/h").unwrap();
        let path = s
            .path()
            .join(OEM_PROVIDER_ID_SUBDIR)
            .join(OEM_PROVIDER_ID_FILENAME);
        assert_eq!(std::fs::read(&path).unwrap(), b"b7://n/h");
    }

    #[test]
    fn startup_nsh_is_the_crlf_fs_scan_script() {
        // The EFI Shell expects CRLF line endings: every LF is preceded by a CR.
        assert!(STARTUP_NSH.ends_with("\r\n"));
        assert_eq!(
            STARTUP_NSH.matches('\n').count(),
            STARTUP_NSH.matches("\r\n").count(),
            "no bare LF line endings"
        );
        let lines: Vec<&str> = STARTUP_NSH.split("\r\n").collect();
        assert_eq!(
            lines,
            [
                "@echo -off",
                "for %i in 0 1 2 3 4 5 6 7 8 9 A B C D E F",
                "  if exist FS%i:\\EFI\\ubuntu\\grub.cfg then",
                "    if exist FS%i:\\EFI\\BOOT\\BOOTX64.EFI then",
                "      FS%i:",
                "      \\EFI\\BOOT\\BOOTX64.EFI",
                "    endif",
                "  endif",
                "endfor",
                "",
            ]
        );
    }

    #[test]
    fn write_and_sync_startup_nsh_replaces_an_existing_script() {
        let s = crate::probe::testutil::Scratch::new("esp-nsh");
        let path = s.path().join(STARTUP_NSH_FILENAME);
        std::fs::write(
            &path,
            "a much longer previous startup script body\r\n".repeat(20),
        )
        .unwrap();
        write_and_sync_startup_nsh(s.path()).expect("startup.nsh written");
        assert_eq!(std::fs::read(&path).unwrap(), STARTUP_NSH.as_bytes());
    }

    #[test]
    fn esp_mount_is_vfat_with_explicit_nls_tables() {
        // The initramfs ships nls_cp437 + nls_ascii (modules.list); the mount must
        // name exactly those rather than rely on the kernel's FAT defaults.
        assert_eq!(ESP_MOUNT.fstype, "vfat");
        assert_eq!(ESP_MOUNT.data, Some("codepage=437,iocharset=ascii"));
        assert_ne!(ESP_MOUNT.node, OEM_MOUNT.node);
        assert_ne!(ESP_MOUNT.mountpoint, OEM_MOUNT.mountpoint);
    }

    #[test]
    fn parse_dev_number_round_trips_through_makedev() {
        // The parsed major:minor must reconstruct the same dev_t the kernel uses,
        // so the mknod'd node binds to exactly the enumerated partition.
        assert_eq!(
            parse_dev_number("259:3"),
            Some(nix::sys::stat::makedev(259, 3))
        );
        assert_eq!(parse_dev_number("8:0"), Some(nix::sys::stat::makedev(8, 0)));
    }

    #[test]
    fn parse_dev_number_rejects_malformed_input() {
        for bad in ["", "259", "259:", ":3", "a:b", "259:3:1", "8 0"] {
            assert_eq!(parse_dev_number(bad), None, "{bad:?} should not parse");
        }
    }
}
