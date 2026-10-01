//! Load the kernel modules the inspector needs, before it probes hardware or
//! provisions (decision D-012).
//!
//! The shipped kernel is the distro `linux-lts`, which builds storage/network/
//! filesystem drivers as **modules** — so the binary-only initramfs is otherwise
//! hardware-blind (no disk to write, no NIC to report over, no `ext4` to mount
//! `COS_OEM`). Rather than own a custom built-in kernel, the image ships a
//! **curated** `/lib/modules/<kver>/` subtree plus an ordered load-list
//! (`beskar7.load`) whose dependencies and order were resolved **at build time**
//! (`depmod` / `modprobe --show-depends`). This module just inserts that list.
//!
//! What the inspector owns here is small and deliberate: an `insmod` loop over a
//! precomputed list, plus a bounded `/sys` settle wait. It does **not**
//! reimplement modprobe's dependency resolver (precomputed at build) or udev (the
//! inspector runs once on a static machine, then reboots — there is no hotplug
//! window). The list is the whole curated set — virtio, the common bare-metal
//! storage (AHCI/SATA, NVMe, SAS/RAID HBAs) and NIC families, and `ext4` — loaded
//! unconditionally: a driver whose hardware is absent binds nothing. The firmware
//! those drivers request ships under `/lib/firmware`, where the kernel's direct
//! loader reads it with no helper. Loading only the drivers whose PCI `modalias`
//! matches present hardware (coldplug) is a possible later optimisation, not a
//! requirement.
//!
//! Best-effort by design: a missing module directory (e.g. a future built-in
//! kernel) or a single failed insert must **not** abort the run before the report
//! is even sent — failures are logged (module path + errno, both non-secret) and
//! the run continues.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::errno::Errno;

/// Root of the kernel module tree shipped in the initramfs.
const MODULES_ROOT: &str = "/lib/modules";
/// The build-time-resolved, dependency-ordered load-list, under
/// `/lib/modules/<kver>/`. One absolute `.ko` path per line; `#` comments and
/// blank lines are ignored.
const LOAD_LIST_NAME: &str = "beskar7.load";

/// `/sys` directories whose population signals that driver probing has bound
/// devices; the settle wait blocks until their entry counts stabilize (and the
/// network interface NIC selection needs exists).
const SYS_BLOCK: &str = "/sys/block";
const SYS_NET: &str = "/sys/class/net";

/// Upper bound on the post-load `/sys` settle wait. Device probing can outlast
/// `finit_module`, and some NIC drivers bring the hardware up before they
/// register a netdev — ice loads its DDP package, mlx5 and bnxt wait on device
/// firmware — which can take seconds; a cap of a few seconds returns before that
/// and NIC selection then fails. The full 30 s is only spent on a host where no
/// interface appears at all, or the `BOOTIF` one never does (either fails NIC
/// selection next anyway); a host whose NIC is up proceeds as soon as the counts
/// hold steady.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Poll interval during the settle wait.
const SETTLE_POLL: Duration = Duration::from_millis(100);
/// Consecutive unchanged polls that count as "settled".
const SETTLE_STABLE_POLLS: u32 = 2;

/// Load the curated kernel modules, then wait for `/sys` to settle — including,
/// when `bootif` (the cmdline's `BOOTIF`) pins the provisioning NIC, for that
/// NIC to register. Best-effort: logs a summary and any per-module failure
/// (non-secret), never aborts the run. A no-op (with a log line) if no module
/// tree / load-list is present.
pub fn load_drivers(bootif: Option<&str>) {
    let Some(list_path) = find_load_list() else {
        eprintln!(
            "beskar7-inspector: no kernel-module load-list under {MODULES_ROOT} \
             (built-in drivers?); skipping module load"
        );
        return;
    };
    let content = match std::fs::read_to_string(&list_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("beskar7-inspector: cannot read module load-list: {e}; skipping");
            return;
        }
    };

    let (mut loaded, mut skipped, mut failed) = (0u32, 0u32, 0u32);
    for module in parse_load_list(&content) {
        match insmod(Path::new(module)) {
            Ok(()) => loaded += 1,
            // EEXIST: already loaded, or built into the kernel. ENODEV/ENXIO: the
            // module loaded but its init found no matching device/CPU feature
            // (e.g. crc32c-intel on a CPU without the instruction — the generic
            // variant covers it). All are expected for a "load the whole curated
            // set, let devices bind" approach, not failures.
            Err(Errno::EEXIST) | Err(Errno::ENODEV) | Err(Errno::ENXIO) => skipped += 1,
            Err(e) => {
                failed += 1;
                eprintln!("beskar7-inspector: module {module} failed to load: {e}");
            }
        }
    }
    eprintln!(
        "beskar7-inspector: kernel modules: {loaded} loaded, {skipped} already-present/no-device, {failed} failed"
    );

    settle(bootif);
}

/// The path to `/lib/modules/<kver>/beskar7.load`, or `None` if no module tree
/// (or no load-list) is present. `<kver>` is the single kernel-version directory
/// the initramfs ships; if several exist, the first in sorted order is used.
fn find_load_list() -> Option<PathBuf> {
    let mut versions: Vec<_> = std::fs::read_dir(MODULES_ROOT)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    versions.sort();
    versions
        .into_iter()
        .map(|v| v.join(LOAD_LIST_NAME))
        .find(|p| p.is_file())
}

/// Parse the load-list: trimmed non-empty lines that are not `#` comments, in
/// order. Pure, so the format handling is unit-tested.
fn parse_load_list(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// Insert one module via `finit_module(2)`. The build ships modules uncompressed
/// and dependency-ordered, so this is a plain in-order load with no decompression
/// or dependency resolution.
fn insmod(path: &Path) -> Result<(), Errno> {
    let file = File::open(path)
        .map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(Errno::EINVAL as i32)))?;
    // An empty NUL-terminated module-parameter string. (A `c""` literal would
    // raise the MSRV to 1.77; a byte string keeps it at 1.74.)
    let params = b"\0";
    // SAFETY: finit_module(2) loads a kernel module from `fd`, reading the file's
    // contents; `params` is a valid NUL-terminated empty string and `flags` is 0.
    // No process memory is shared with the kernel beyond the read of the fd.
    let ret = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_finit_module,
            file.as_raw_fd(),
            params.as_ptr() as *const nix::libc::c_char,
            0 as nix::libc::c_int,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// One `/sys` observation the settle wait decides on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeviceCounts {
    /// Entries in `/sys/block`.
    block: usize,
    /// Non-loopback entries in `/sys/class/net` — the interfaces NIC selection
    /// ([`crate::net::candidate_interfaces`]) chooses from.
    nics: usize,
    /// Whether the interface NIC selection needs exists: the one whose MAC is
    /// `BOOTIF` when the cmdline pins one, otherwise any of them.
    selectable: bool,
}

/// How the settle wait ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SettleOutcome {
    /// The counts held for [`SETTLE_STABLE_POLLS`] polls and the interface NIC
    /// selection needs exists.
    Settled,
    /// [`SETTLE_TIMEOUT`] elapsed first; the run proceeds with what is present.
    TimedOut,
}

/// The settle wait's decision state. Free of I/O and clocks (the caller passes
/// each observation and the elapsed time), so the policy is unit-tested.
struct Settle {
    prev: DeviceCounts,
    stable: u32,
}

impl Settle {
    fn new(initial: DeviceCounts) -> Self {
        Self {
            prev: initial,
            stable: 0,
        }
    }

    /// Fold in `cur`, observed `elapsed` after the wait began. `None` means keep
    /// polling.
    fn observe(&mut self, cur: DeviceCounts, elapsed: Duration) -> Option<SettleOutcome> {
        if cur == self.prev {
            self.stable += 1;
        } else {
            self.stable = 0;
            self.prev = cur;
        }
        // Stable counts alone are not enough: until the interface NIC selection
        // needs exists, selection fails outright, while a slow NIC driver (or
        // the BOOTIF NIC's, behind a faster onboard port) may still be
        // registering it.
        if self.stable >= SETTLE_STABLE_POLLS && cur.selectable {
            Some(SettleOutcome::Settled)
        } else if elapsed >= SETTLE_TIMEOUT {
            Some(SettleOutcome::TimedOut)
        } else {
            None
        }
    }
}

/// Wait for `/sys` device population to stabilize after the load pass (the
/// kernel's device probe is asynchronous — this is what `udevadm settle` does,
/// in ~20 lines). Returns once [`Settle`] decides, then logs the counts it saw.
/// This is the only wait for a NIC to *appear*: NIC selection
/// ([`crate::net`]) reads `/sys/class/net` once, and its later waits are for
/// link carrier and a DHCP lease, not for the interface.
fn settle(bootif: Option<&str>) {
    let start = Instant::now();
    let mut state = Settle::new(device_counts(bootif));
    let (outcome, counts) = loop {
        std::thread::sleep(SETTLE_POLL);
        let cur = device_counts(bootif);
        if let Some(outcome) = state.observe(cur, start.elapsed()) {
            break (outcome, cur);
        }
    };
    let ms = start.elapsed().as_millis();
    let DeviceCounts { block, nics, .. } = counts;
    match outcome {
        SettleOutcome::Settled => eprintln!(
            "beskar7-inspector: devices settled after {ms} ms: \
             {block} block devices, {nics} network interfaces"
        ),
        SettleOutcome::TimedOut => eprintln!(
            "beskar7-inspector: device settle wait timed out after {ms} ms: \
             {block} block devices, {nics} network interfaces; continuing{}",
            timeout_hint(counts, bootif.is_some())
        ),
    }
}

/// What a timed-out settle wait adds to its log line: why NIC selection, which
/// runs next, is about to fail — if it is.
fn timeout_hint(counts: DeviceCounts, bootif: bool) -> &'static str {
    if counts.nics == 0 {
        " (no NIC driver bound — is this NIC's driver shipped?)"
    } else if bootif && !counts.selectable {
        " (the BOOTIF NIC never registered)"
    } else {
        ""
    }
}

/// The live [`DeviceCounts`].
fn device_counts(bootif: Option<&str>) -> DeviceCounts {
    device_counts_in(Path::new(SYS_BLOCK), Path::new(SYS_NET), bootif)
}

/// [`DeviceCounts`] for a `/sys/block`-shaped and a `/sys/class/net`-shaped
/// directory.
fn device_counts_in(block_dir: &Path, net_dir: &Path, bootif: Option<&str>) -> DeviceCounts {
    DeviceCounts {
        block: count_dir(block_dir),
        nics: crate::net::candidate_interfaces(net_dir).len(),
        selectable: crate::net::nic_selectable(net_dir, bootif),
    }
}

/// Number of entries in a directory, or 0 if it cannot be read.
fn count_dir(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .map(|rd| rd.flatten().count())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::testutil::{write, Scratch};

    #[test]
    fn parse_load_list_skips_comments_and_blanks_keeps_order() {
        let content = "\
# curated modules (D-012)
/lib/modules/6.6.1-lts/virtio_pci.ko

  /lib/modules/6.6.1-lts/virtio_blk.ko
# ext4 for COS_OEM
/lib/modules/6.6.1-lts/ext4.ko
";
        let got: Vec<&str> = parse_load_list(content).collect();
        assert_eq!(
            got,
            vec![
                "/lib/modules/6.6.1-lts/virtio_pci.ko",
                "/lib/modules/6.6.1-lts/virtio_blk.ko",
                "/lib/modules/6.6.1-lts/ext4.ko",
            ]
        );
    }

    #[test]
    fn parse_load_list_empty_is_empty() {
        assert_eq!(parse_load_list("\n\n# only comments\n").count(), 0);
    }

    /// `modules.list` uses the load-list's line format (trimmed lines, `#`
    /// comments, blanks ignored), so the same parser reads it.
    fn shipped_modules() -> Vec<&'static str> {
        parse_load_list(include_str!("../modules.list")).collect()
    }

    #[test]
    fn modules_list_ships_the_bare_metal_storage_and_nic_drivers() {
        // Issue #54: the list was the QEMU slice, so on bare metal no NIC driver
        // bound ("no network interface found") and no SATA/SAS/NVMe disk
        // appeared. Without these the commonest server disks and NICs are
        // invisible; dropping one must fail here, not on a host.
        let shipped = shipped_modules();
        for required in [
            "ext4",
            "ahci",
            "nvme",
            "sd_mod",
            "megaraid_sas",
            "mpt3sas",
            "e1000e",
            "igb",
            "ixgbe",
            "i40e",
            "ice",
            "tg3",
            "bnxt_en",
            "mlx5_core",
        ] {
            assert!(
                shipped.contains(&required),
                "modules.list is missing {required}"
            );
        }
    }

    const NO_NIC: DeviceCounts = DeviceCounts {
        block: 2,
        nics: 0,
        selectable: false,
    };
    const ONE_NIC: DeviceCounts = DeviceCounts {
        block: 2,
        nics: 1,
        selectable: true,
    };
    /// BOOTIF pins a NIC that has not registered; another NIC has.
    const OTHER_NIC_ONLY: DeviceCounts = DeviceCounts {
        block: 2,
        nics: 1,
        selectable: false,
    };
    /// The BOOTIF NIC has registered beside the other one.
    const BOOTIF_NIC_TOO: DeviceCounts = DeviceCounts {
        block: 2,
        nics: 2,
        selectable: true,
    };
    const SOON: Duration = Duration::from_millis(300);

    #[test]
    fn settle_done_once_counts_are_stable_and_a_nic_exists() {
        let mut s = Settle::new(ONE_NIC);
        assert_eq!(
            s.observe(ONE_NIC, SOON),
            None,
            "one stable poll is not enough"
        );
        assert_eq!(s.observe(ONE_NIC, SOON), Some(SettleOutcome::Settled));
    }

    #[test]
    fn settle_keeps_waiting_while_only_loopback_exists() {
        // Stable counts with no NIC: a slow NIC driver (ice, mlx5, bnxt) may still
        // be bringing its netdev up, and NIC selection would fail outright.
        let mut s = Settle::new(NO_NIC);
        for _ in 0..50 {
            assert_eq!(s.observe(NO_NIC, SOON), None);
        }
        // The NIC registers; once it holds steady the wait ends.
        assert_eq!(s.observe(ONE_NIC, SOON), None);
        assert_eq!(s.observe(ONE_NIC, SOON), None);
        assert_eq!(s.observe(ONE_NIC, SOON), Some(SettleOutcome::Settled));
    }

    #[test]
    fn settle_keeps_waiting_while_counts_grow() {
        let mut s = Settle::new(ONE_NIC);
        for n in 2..10 {
            let growing = DeviceCounts {
                block: n,
                nics: n,
                selectable: true,
            };
            assert_eq!(s.observe(growing, SOON), None, "counts changed at {n}");
        }
    }

    #[test]
    fn settle_proceeds_at_the_timeout_without_a_nic() {
        let mut s = Settle::new(NO_NIC);
        let just_before = SETTLE_TIMEOUT - Duration::from_millis(1);
        assert_eq!(s.observe(NO_NIC, just_before), None);
        assert_eq!(
            s.observe(NO_NIC, SETTLE_TIMEOUT),
            Some(SettleOutcome::TimedOut)
        );
    }

    #[test]
    fn settle_proceeds_at_the_timeout_while_counts_still_change() {
        let mut s = Settle::new(ONE_NIC);
        let changed = DeviceCounts {
            block: 3,
            ..ONE_NIC
        };
        assert_eq!(
            s.observe(changed, SETTLE_TIMEOUT),
            Some(SettleOutcome::TimedOut)
        );
    }

    #[test]
    fn settle_still_waits_for_a_slow_nic_well_past_the_old_cap() {
        // The old 3 s cap returned before ice/mlx5/bnxt had registered a netdev.
        let mut s = Settle::new(NO_NIC);
        assert_eq!(s.observe(NO_NIC, Duration::from_secs(3)), None);
        assert_eq!(s.observe(NO_NIC, Duration::from_secs(20)), None);
    }

    #[test]
    fn settle_with_bootif_keeps_waiting_while_only_another_nic_exists() {
        // An onboard 1G port (igb) often registers seconds before the 25G port
        // that PXE-booted (ice, mlx5); settling on the first would make NIC
        // selection fail with BootifNoMatch.
        let mut s = Settle::new(OTHER_NIC_ONLY);
        for _ in 0..50 {
            assert_eq!(s.observe(OTHER_NIC_ONLY, SOON), None);
        }
        assert_eq!(s.observe(BOOTIF_NIC_TOO, SOON), None);
        assert_eq!(s.observe(BOOTIF_NIC_TOO, SOON), None);
        assert_eq!(
            s.observe(BOOTIF_NIC_TOO, SOON),
            Some(SettleOutcome::Settled)
        );
    }

    #[test]
    fn settle_with_bootif_proceeds_at_the_timeout_if_its_nic_never_registers() {
        let mut s = Settle::new(OTHER_NIC_ONLY);
        assert_eq!(s.observe(OTHER_NIC_ONLY, Duration::from_secs(20)), None);
        assert_eq!(
            s.observe(OTHER_NIC_ONLY, SETTLE_TIMEOUT),
            Some(SettleOutcome::TimedOut)
        );
    }

    #[test]
    fn timeout_hint_names_what_never_appeared() {
        assert_eq!(
            timeout_hint(NO_NIC, false),
            " (no NIC driver bound — is this NIC's driver shipped?)"
        );
        assert_eq!(
            timeout_hint(NO_NIC, true),
            " (no NIC driver bound — is this NIC's driver shipped?)"
        );
        assert_eq!(
            timeout_hint(OTHER_NIC_ONLY, true),
            " (the BOOTIF NIC never registered)"
        );
        assert_eq!(timeout_hint(ONE_NIC, false), "");
        assert_eq!(timeout_hint(BOOTIF_NIC_TOO, true), "");
    }

    #[test]
    fn device_counts_exclude_loopback() {
        let block = Scratch::new("settle-block");
        write(block.path(), "nvme0n1/size", "1\n");
        let net = Scratch::new("settle-net");
        write(net.path(), "lo/address", "00:00:00:00:00:00\n");
        assert_eq!(
            device_counts_in(block.path(), net.path(), None),
            DeviceCounts {
                block: 1,
                nics: 0,
                selectable: false,
            }
        );
        write(net.path(), "eth0/address", "52:54:00:12:34:56\n");
        assert_eq!(
            device_counts_in(block.path(), net.path(), None),
            DeviceCounts {
                block: 1,
                nics: 1,
                selectable: true,
            }
        );
    }

    #[test]
    fn device_counts_with_bootif_need_that_nic() {
        let block = Scratch::new("settle-bootif-block");
        let net = Scratch::new("settle-bootif-net");
        write(net.path(), "lo/address", "00:00:00:00:00:00\n");
        write(net.path(), "eth0/address", "52:54:00:00:00:01\n");
        let bootif = Some("01-52-54-00-00-00-02");
        let only_other = device_counts_in(block.path(), net.path(), bootif);
        assert_eq!((only_other.nics, only_other.selectable), (1, false));
        // Without BOOTIF, the same lone NIC is selectable.
        assert!(device_counts_in(block.path(), net.path(), None).selectable);

        write(net.path(), "eth1/address", "52:54:00:00:00:02\n");
        let both = device_counts_in(block.path(), net.path(), bootif);
        assert_eq!((both.nics, both.selectable), (2, true));
    }

    #[test]
    fn count_dir_counts_entries_and_is_zero_for_missing() {
        let s = Scratch::new("modcount");
        write(s.path(), "sda/x", "");
        write(s.path(), "nvme0n1/x", "");
        assert_eq!(count_dir(s.path()), 2);
        assert_eq!(count_dir(Path::new("/nonexistent/sys/block/zzz")), 0);
    }

    #[test]
    fn find_load_list_picks_the_version_dir_with_the_list() {
        // A modules root with a version dir containing beskar7.load resolves to it.
        let s = Scratch::new("modroot");
        write(
            s.path(),
            "6.6.1-lts/beskar7.load",
            "/lib/modules/6.6.1-lts/ext4.ko\n",
        );
        // find_load_list reads the real MODULES_ROOT, so exercise the inner logic
        // shape via the same sort+join+is_file path against the scratch tree.
        let mut versions: Vec<_> = std::fs::read_dir(s.path())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        versions.sort();
        let found = versions
            .into_iter()
            .map(|v| v.join(LOAD_LIST_NAME))
            .find(|p| p.is_file());
        assert_eq!(found, Some(s.path().join("6.6.1-lts").join("beskar7.load")));
    }
}
