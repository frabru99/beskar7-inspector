//! PID 1 orchestration — the two-phase enroll/provision pipeline (contract §9).
//!
//! [`run`] is the whole inspector run, composed from the already-tested modules:
//!
//! ```text
//! mount pseudo-filesystems (/proc /sys /dev /run /tmp)   [skipped in --dry-run]
//! parse /proc/cmdline (beskar7.*)                        cmdline::BootParams
//! ── Phase 1: enroll & inspect (always) ───────────────────────────────────────
//! probe hardware → InspectionReport                     probe::collect
//! select the target disk                                target_disk::select
//! POST the report (202 = success, retried)              client::submit_report
//! ── --dry-run stops here ─────────────────────────────────────────────────────
//! ── Phase 2: provision (when bootstrap is ready) ─────────────────────────────
//! poll GET /bootstrap (404/5xx = not ready)             client::fetch_bootstrap
//! write the digest-pinned image to the disk             deploy::write_image
//! re-read the partition table                           deploy::reread_partition_table
//! locate COS_OEM on the target disk                     oem::find_oem_partition
//! mount COS_OEM, inject 99_beskar7.yaml + provider-id   deploy::inject_oem_config
//! zero the user-data buffer                             drop(user_data)
//! POST the provisioned-complete callback (202)          client::provisioned
//! reboot(2)                                             deploy::reboot_now
//! ```
//!
//! ## Secret hygiene (§9)
//! The bearer token lives in a [`Secret`](crate::secret::Secret) (redacted in
//! `Debug`, zeroed on drop). The fetched bootstrap **user-data is the join
//! secret**: it is held in a [`Zeroizing`] buffer, passed only to
//! [`deploy::inject_oem_config`] (which writes it to the `0600` `COS_OEM` file),
//! and explicitly dropped — zeroing it — before the reboot. Nothing here logs the
//! token, the user-data, or the full cmdline; [`RunError`] carries only
//! non-secret module errors. At PID-1 start (non-dry-run) `mlockall` pins all
//! pages so these secrets never reach swap.
//!
//! The zeroing happens on every *return* path (success and `?`-propagated error)
//! because the [`Zeroizing`]/[`Secret`](crate::secret::Secret) destructors run as
//! the `run` frame unwinds. The crate builds with `panic = "abort"`, so a *panic*
//! between fetch and drop would skip those destructors — bounded by the swapless /
//! `mlockall` guarantee (the secret stays in RAM, never swap, and the aborting
//! PID 1 runs nothing further).

use std::time::Duration;

use zeroize::Zeroizing;

use crate::client::{CallbackClient, ClientError};
use crate::cmdline::{BootParams, CmdlineError};
use crate::deploy::{self, DeployError};
use crate::image::DEFAULT_MAX_IMAGE_BYTES;
use crate::net::{self, NetError};
use crate::oem::{self, OemError};
use crate::probe;
use crate::target_disk::{self, DiskError};

/// How often Phase 2 re-polls `GET /bootstrap` while the bootstrap provider is
/// still producing the user-data (§9.2).
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Default Phase 2 poll budget when `beskar7.timeout` is unset — 30 minutes,
/// matching the bearer token's order-of-magnitude lifetime; on expiry the host is
/// re-driven by the controller (fresh nonce/token, §9.2).
const DEFAULT_POLL_BUDGET: Duration = Duration::from_secs(30 * 60);

/// Errors from a full inspector run. Variants carry only non-secret module errors
/// and fixed strings — never the token, user-data, or cmdline (§9).
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// Mounting a pseudo-filesystem the init needs (`/proc`, `/sys`, …) failed.
    #[error("mounting {target}")]
    Mount {
        /// The mountpoint.
        target: String,
        /// The mount errno.
        #[source]
        source: nix::errno::Errno,
    },
    /// Parsing the kernel cmdline failed (missing/invalid `beskar7.*`).
    #[error(transparent)]
    Cmdline(#[from] CmdlineError),
    /// Bringing up the provisioning network (NIC select / DHCP / netlink) failed.
    #[error(transparent)]
    Net(#[from] NetError),
    /// Selecting the target disk failed (none eligible, or a bad `beskar7.disk`).
    #[error(transparent)]
    Disk(#[from] DiskError),
    /// Building the callback client or submitting the report failed.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// Phase 2 gave up waiting for the bootstrap user-data within the poll budget.
    #[error("timed out waiting for bootstrap data")]
    BootstrapTimeout,
    /// Phase 2 aborted the bootstrap fetch on a non-retryable error (e.g. an
    /// expired/invalid bearer token — `401`/`403`). The host is re-driven by the
    /// controller with a fresh token (§9.2).
    #[error("bootstrap fetch aborted (not retryable): {0}")]
    BootstrapAborted(#[source] ClientError),
    /// Locating the `COS_OEM` partition on the target disk failed.
    #[error(transparent)]
    Oem(#[from] OemError),
    /// A deploy step (write/re-read/mount/inject/reboot) failed.
    #[error(transparent)]
    Deploy(#[from] DeployError),
}

/// Run the inspector. With `dry_run`, performs **Phase 1 only** (mounts are
/// skipped, the report is submitted, and it returns `Ok` without fetching
/// bootstrap data, writing any disk, or rebooting) — the CI / report-only mode
/// (§9.0). Otherwise it runs both phases and, on success, **does not return** (the
/// host reboots in [`deploy::reboot_now`]).
pub fn run(dry_run: bool) -> Result<(), RunError> {
    if !dry_run {
        mount_pseudo_filesystems()?;
        // Pin all current and future pages so the in-RAM secrets (token,
        // user-data) can never be paged to swap — making §9's swapless guarantee
        // a runtime invariant rather than a deployment assumption. Before the
        // cmdline parse, so the token is never held in unlocked memory.
        // Best-effort: a host without CAP_IPC_LOCK falls back to the
        // swapless-ramdisk assumption.
        lock_memory();
    }

    let params = BootParams::from_proc_cmdline()?;

    if !dry_run {
        // Load the curated storage/network/fs drivers so /sys/block and
        // /sys/class/net are populated before probing, and ext4 is available for
        // the COS_OEM mount (D-012). Best-effort; must run after /proc,/sys,/dev
        // are mounted and before the probe reads /sys. It takes BOOTIF so its
        // settle wait holds out for the NIC that PXE-booted, not just any NIC.
        crate::modules::load_drivers(params.bootif.as_deref());
        // Bring up the provisioning NIC (DHCP) so the callback is reachable — the
        // NIC driver was loaded above, but the link is down and unaddressed, and
        // kernel ip=dhcp can't help with a module loaded post-boot (D-013). Needs
        // the cmdline (for BOOTIF), so it runs after the parse and before probe.
        let net = net::bring_up_provisioning_network(&params)?;
        eprintln!(
            "beskar7-inspector: network up on {} ({}/{})",
            net.iface, net.ip, net.prefix_len
        );
        // Write DHCP-provided DNS (option 6) so a hostname beskar7.api resolves.
        // Best-effort: an IP-literal beskar7.api (the recommended form, §8.2) needs
        // no resolver, so a write failure must not abort provisioning.
        if let Err(e) = net::write_resolv_conf(&net.dns) {
            eprintln!("beskar7-inspector: could not write /etc/resolv.conf: {e}");
        }
    }

    // ── Phase 1: enroll & inspect (always) ──────────────────────────────────
    let report = probe::collect();
    // Select the target disk now so the choice (or its absence) is logged during
    // enrollment; it is only *required* for Phase 2. min_bytes is 0 here — the
    // image size is unknown until the stream, and deploy caps the write at the
    // disk's capacity (§8.1).
    let target = target_disk::select(params.disk.as_deref(), 0);
    match &target {
        Ok(t) => eprintln!(
            "beskar7-inspector: target disk {} ({} bytes)",
            t.dev_path(),
            t.size_bytes
        ),
        Err(e) => eprintln!("beskar7-inspector: no target disk yet: {e}"),
    }

    let client = CallbackClient::new(&params)?;
    client.submit_report(&report)?;
    eprintln!("beskar7-inspector: inspection report accepted");

    if dry_run {
        eprintln!("beskar7-inspector: --dry-run, stopping after Phase 1");
        return Ok(());
    }

    // ── Phase 2: provision (when bootstrap data is ready) ───────────────────
    // A missing target disk is fatal for provisioning. It is reported before the
    // bootstrap poll: no disk appears later (there is no hotplug window), and the
    // controller, which has the report, would otherwise wait out its deployment
    // timeout.
    let target = require_target(target, |reason| client.provision_failed(reason))?;
    let max_polls = poll_budget_iterations(params.timeout);
    let user_data = Zeroizing::new(poll_bootstrap(max_polls, sleep, || {
        client.fetch_bootstrap()
    })?);
    eprintln!("beskar7-inspector: bootstrap data received, provisioning");

    // The destructive deploy steps. A failure is reported to the controller
    // before the existing abort/halt, like a missing disk above.
    if let Err(e) = run_deploy_steps(&target, &params, &user_data) {
        return Err(report_provision_failure(e, |reason| {
            client.provision_failed(reason)
        }));
    }

    // Zero the join secret before handing control to the firmware (§9.1 step 6).
    // The provisioned callback below carries no secret, so it is safe to fire
    // after the secret is gone.
    drop(user_data);

    // Tell the controller the deploy succeeded BEFORE rebooting (D-015): the host
    // is about to reboot into the target OS and never runs the inspector again, so
    // a silent reboot would leave the controller unable to confirm provisioning.
    // As critical as the inspection POST — a retries-exhausted failure propagates
    // (as RunError::Client) rather than rebooting silently, so the controller can
    // re-drive the host.
    client.provisioned()?;
    eprintln!("beskar7-inspector: provisioned-complete callback accepted");

    eprintln!("beskar7-inspector: provisioned, rebooting into the target OS");
    Err(RunError::Deploy(deploy::reboot_now()))
}

/// The target disk Phase 2 deploys to, or — when selection failed — the failure,
/// after reporting it through `provision_failed` ([`report_provision_failure`]).
fn require_target(
    target: Result<crate::target_disk::TargetDisk, DiskError>,
    provision_failed: impl FnOnce(&'static str) -> Result<(), ClientError>,
) -> Result<crate::target_disk::TargetDisk, RunError> {
    target.map_err(|e| report_provision_failure(e.into(), provision_failed))
}

/// Report a Phase 2 failure through the provision-failed callback (D-015 v4.1),
/// then hand the failure back to propagate. The inspection report was accepted,
/// so the controller is waiting on this host; the callback lets it fail the
/// machine now instead of at its deployment timeout. Best-effort: a callback that
/// does not land (after its own retries, or a v4 controller's `404`) must NOT loop
/// or mask the failure — it is logged (non-secret) and the original error is
/// returned, which parks PID 1 so the controller still times the host out.
fn report_provision_failure(
    e: RunError,
    provision_failed: impl FnOnce(&'static str) -> Result<(), ClientError>,
) -> RunError {
    let reason = provision_failure_reason(&e);
    match provision_failed(reason) {
        Ok(()) => eprintln!("beskar7-inspector: provision-failed callback accepted ({reason})"),
        Err(cb) => eprintln!("beskar7-inspector: provision-failed callback did not land: {cb}"),
    }
    e
}

/// Run the destructive deploy steps in order — write the digest-pinned image,
/// re-read the partition table, locate `COS_OEM`, inject the per-host config — each
/// gated by the one before (§9.1 step 5). Returns the first failing step's
/// [`RunError`]; the caller reports it through [`report_provision_failure`].
fn run_deploy_steps(
    target: &crate::target_disk::TargetDisk,
    params: &BootParams,
    user_data: &[u8],
) -> Result<(), RunError> {
    deploy::write_image(
        target,
        &params.target,
        &params.target_digest,
        DEFAULT_MAX_IMAGE_BYTES,
    )?;
    deploy::reread_partition_table(target)?;
    let oem_partition = oem::find_oem_partition(target)?;
    deploy::inject_oem_config(&oem_partition, user_data, &params.provider_id)?;
    Ok(())
}

/// A short, secret-free reason string for the provision-failed callback, derived
/// from which Phase 2 step failed. The strings name the failing step only — never
/// the image bytes, the join secret, device names or paths, or status codes — so
/// they are safe to put on the wire and in a log (§9); the console line carries
/// the detail. `&'static str` because the controller uses the reason for
/// operator-facing diagnosis, not machine parsing.
fn provision_failure_reason(e: &RunError) -> &'static str {
    match e {
        RunError::Disk(d) => disk_error_reason(d),
        RunError::Deploy(d) => deploy_error_reason(d),
        // find_oem_partition failed — the freshly-written image had no locatable
        // COS_OEM partition to inject into.
        RunError::Oem(_) => "COS_OEM partition not found",
        // Only Disk/Deploy/Oem errors are reported, but keep the match total so a
        // future step cannot silently fall through without a reason.
        _ => "deploy failed",
    }
}

/// Map a [`DiskError`] (target-disk selection, §9.1 step 2) to its callback reason.
fn disk_error_reason(e: &DiskError) -> &'static str {
    match e {
        DiskError::NoEligibleDisk => "no eligible target disk",
        DiskError::PinNotFound { .. } => "pinned target disk not found",
        DiskError::PinNotBlockDevice { .. } => "pinned target disk is not a block device",
        DiskError::PinNotWholeDisk { .. } => "pinned target disk is a partition",
        DiskError::PinIneligible { .. } => "pinned target disk is ineligible",
    }
}

/// Map a [`DeployError`] to its short, secret-free callback reason (§9). Groups the
/// step's variants: image fetch/digest, whole-disk write/identity, partition
/// re-read, and `COS_OEM` mount/inject.
fn deploy_error_reason(e: &DeployError) -> &'static str {
    use crate::image::ImageError;
    match e {
        DeployError::Image(ImageError::DigestMismatch { .. }) => "image digest mismatch",
        DeployError::Image(ImageError::InvalidDigestFormat) => "invalid image digest",
        DeployError::Image(ImageError::UnsupportedScheme) => "unsupported image URL scheme",
        DeployError::Image(ImageError::TooLarge { .. }) => "image too large",
        DeployError::Image(
            ImageError::Http(_) | ImageError::Transport(_) | ImageError::Read(_),
        ) => "image fetch failed",
        DeployError::Image(ImageError::Write(_)) | DeployError::Sync(_) => {
            "whole-disk write failed"
        }
        DeployError::OpenTarget { .. }
        | DeployError::NotABlockDevice { .. }
        | DeployError::Stat { .. }
        | DeployError::NoDeviceNumber { .. }
        | DeployError::DeviceIdentityMismatch { .. }
        | DeployError::BadDeviceNumber { .. } => "target disk error",
        DeployError::Reread { .. } => "partition re-read failed",
        DeployError::Mountpoint { .. }
        | DeployError::MakeNode { .. }
        | DeployError::Mount { .. }
        | DeployError::ConfigWrite(_)
        | DeployError::ProviderIdWrite(_)
        | DeployError::Unmount { .. } => "COS_OEM inject failed",
        // reboot_now's error never flows through run_deploy_steps (it runs after a
        // successful deploy), but keep the match total.
        DeployError::Reboot(_) => "deploy failed",
    }
}

/// `mlockall(MCL_CURRENT|MCL_FUTURE)` so no page — including the heap holding the
/// bearer token and the join secret — is ever swapped out (§9). Best-effort: on
/// failure (e.g. no `CAP_IPC_LOCK`) it warns and relies on the swapless-ramdisk
/// assumption, rather than aborting provisioning.
fn lock_memory() {
    use nix::sys::mman::{mlockall, MlockAllFlags};
    if let Err(e) = mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE) {
        eprintln!(
            "beskar7-inspector: warning: mlockall failed ({e}); secret pages rely \
             on the ramdisk being swapless (§9)"
        );
    }
}

/// The pseudo-filesystems the init mounts, with their flags. `/dev` (devtmpfs) and
/// `/run` (tmpfs) must allow device nodes — `/dev` for the kernel's device nodes,
/// `/run` for the private `COS_OEM` block node `deploy` `mknod`s — so they omit
/// `MS_NODEV`; the rest get `nodev,nosuid,noexec`. (`/run` keeping device nodes is
/// load-bearing for the deploy mount design — see the regression test.)
fn mount_specs() -> [(
    &'static str,
    &'static str,
    &'static str,
    nix::mount::MsFlags,
); 5] {
    use nix::mount::MsFlags;
    let hardened = MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;
    let dev_ok = MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;
    [
        ("proc", "/proc", "proc", hardened),
        ("sysfs", "/sys", "sysfs", hardened),
        ("devtmpfs", "/dev", "devtmpfs", dev_ok),
        ("tmpfs", "/run", "tmpfs", dev_ok),
        ("tmpfs", "/tmp", "tmpfs", hardened),
    ]
}

/// Mount the pseudo-filesystems ([`mount_specs`]). An already-mounted filesystem
/// (`EBUSY`, e.g. a kernel-auto-mounted devtmpfs) is tolerated.
fn mount_pseudo_filesystems() -> Result<(), RunError> {
    for (src, target, fstype, flags) in mount_specs() {
        mount_one(src, target, fstype, flags)?;
    }
    Ok(())
}

/// Mount one pseudo-filesystem, creating the mountpoint and tolerating `EBUSY`
/// (already mounted).
fn mount_one(
    src: &str,
    target: &str,
    fstype: &str,
    flags: nix::mount::MsFlags,
) -> Result<(), RunError> {
    let _ = std::fs::create_dir_all(target);
    match nix::mount::mount(Some(src), target, Some(fstype), flags, None::<&str>) {
        Ok(()) | Err(nix::errno::Errno::EBUSY) => Ok(()),
        Err(source) => Err(RunError::Mount {
            target: target.to_string(),
            source,
        }),
    }
}

/// The production sleeper (isolated so [`poll_bootstrap`] tests inject a no-op).
fn sleep(d: Duration) {
    std::thread::sleep(d);
}

/// Number of `GET /bootstrap` poll attempts for a given `beskar7.timeout`: the
/// budget divided by [`POLL_INTERVAL`], at least one. An unset timeout uses
/// [`DEFAULT_POLL_BUDGET`].
fn poll_budget_iterations(timeout: Option<Duration>) -> u32 {
    let budget = timeout.unwrap_or(DEFAULT_POLL_BUDGET);
    let polls = budget.as_secs() / POLL_INTERVAL.as_secs().max(1);
    polls.clamp(1, u32::MAX as u64) as u32
}

/// Poll `fetch` (a `GET /bootstrap`) until it returns the user-data, a
/// non-retryable error aborts, or `max_polls` attempts elapse (§9.2). A not-ready
/// result (`404`/`5xx`/transient) sleeps [`POLL_INTERVAL`] and retries; an auth or
/// otherwise-fatal result aborts immediately. Pure over the injected `fetch` and
/// `sleep`, so the poll policy is unit-tested without a network.
fn poll_bootstrap(
    max_polls: u32,
    mut sleep: impl FnMut(Duration),
    mut fetch: impl FnMut() -> Result<Vec<u8>, ClientError>,
) -> Result<Vec<u8>, RunError> {
    for attempt in 0..max_polls {
        match fetch() {
            Ok(data) => return Ok(data),
            Err(e) => match classify_poll(&e) {
                PollVerdict::Abort => return Err(RunError::BootstrapAborted(e)),
                PollVerdict::NotReady => {
                    if attempt + 1 < max_polls {
                        sleep(POLL_INTERVAL);
                    }
                }
            },
        }
    }
    Err(RunError::BootstrapTimeout)
}

/// Whether a failed `GET /bootstrap` means "not ready yet, keep polling" or "stop".
#[derive(Debug, PartialEq, Eq)]
enum PollVerdict {
    /// The bootstrap data is not available yet (or a transient error) — retry.
    NotReady,
    /// A non-retryable failure (expired token, protocol/config error) — abort.
    Abort,
}

/// Classify a [`ClientError`] from the bootstrap poll. `404` and `5xx` are
/// "not ready" (the opaque 404 covers both not-ready and resolution failures,
/// §4.3); `401`/`403` and a too-large body are fatal; transient network errors
/// keep polling; configuration errors (CA/TLS/serialize) abort.
fn classify_poll(e: &ClientError) -> PollVerdict {
    match e {
        ClientError::Http(401) | ClientError::Http(403) => PollVerdict::Abort,
        ClientError::Http(404) => PollVerdict::NotReady,
        ClientError::Http(code) if (500..600).contains(code) => PollVerdict::NotReady,
        ClientError::Http(_) => PollVerdict::Abort,
        ClientError::BootstrapTooLarge => PollVerdict::Abort,
        // The client already retried transient failures internally; if one still
        // surfaced, keep polling — the controller may still be minting the secret.
        ClientError::RetriesExhausted(_) | ClientError::Transport(_) | ClientError::Body => {
            PollVerdict::NotReady
        }
        // CA decode/invalid/empty, TLS setup, serialize: deterministic config
        // errors that retrying cannot fix.
        _ => PollVerdict::Abort,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn poll_budget_divides_timeout_by_interval() {
        // 10 min / 5 s = 120 polls.
        assert_eq!(poll_budget_iterations(Some(Duration::from_secs(600))), 120);
        // Unset uses the 30-min default: 1800 / 5 = 360.
        assert_eq!(poll_budget_iterations(None), 360);
        // A tiny timeout still yields at least one poll.
        assert_eq!(poll_budget_iterations(Some(Duration::from_secs(1))), 1);
        assert_eq!(poll_budget_iterations(Some(Duration::from_secs(0))), 1);
    }

    #[test]
    fn classify_poll_retries_404_and_5xx() {
        assert_eq!(
            classify_poll(&ClientError::Http(404)),
            PollVerdict::NotReady
        );
        for code in [500, 502, 503, 504] {
            assert_eq!(
                classify_poll(&ClientError::Http(code)),
                PollVerdict::NotReady
            );
        }
        assert_eq!(
            classify_poll(&ClientError::Transport("reset".into())),
            PollVerdict::NotReady
        );
        assert_eq!(
            classify_poll(&ClientError::RetriesExhausted(Box::new(ClientError::Http(
                503
            )))),
            PollVerdict::NotReady
        );
    }

    #[test]
    fn classify_poll_aborts_on_auth_and_config_errors() {
        assert_eq!(classify_poll(&ClientError::Http(401)), PollVerdict::Abort);
        assert_eq!(classify_poll(&ClientError::Http(403)), PollVerdict::Abort);
        assert_eq!(classify_poll(&ClientError::Http(400)), PollVerdict::Abort);
        assert_eq!(
            classify_poll(&ClientError::BootstrapTooLarge),
            PollVerdict::Abort
        );
        assert_eq!(classify_poll(&ClientError::CaDecode), PollVerdict::Abort);
        assert_eq!(classify_poll(&ClientError::CaEmpty), PollVerdict::Abort);
    }

    #[test]
    fn poll_returns_data_once_ready() {
        let calls = Cell::new(0u32);
        let sleeps = Cell::new(0u32);
        let out = poll_bootstrap(
            10,
            |_| sleeps.set(sleeps.get() + 1),
            || {
                let n = calls.get();
                calls.set(n + 1);
                if n < 3 {
                    Err(ClientError::Http(404)) // not ready
                } else {
                    Ok(b"#cloud-config\n".to_vec())
                }
            },
        )
        .expect("eventually ready");
        assert_eq!(out, b"#cloud-config\n");
        assert_eq!(calls.get(), 4); // 3 not-ready + 1 ready
        assert_eq!(sleeps.get(), 3); // one sleep before each retry
    }

    #[test]
    fn poll_aborts_immediately_on_auth_failure() {
        let calls = Cell::new(0u32);
        let out = poll_bootstrap(
            10,
            |_| {},
            || {
                calls.set(calls.get() + 1);
                Err(ClientError::Http(401))
            },
        );
        assert!(matches!(out, Err(RunError::BootstrapAborted(_))));
        assert_eq!(calls.get(), 1, "auth failure must not be retried");
    }

    #[test]
    fn run_mount_allows_device_nodes_but_proc_does_not() {
        use nix::mount::MsFlags;
        let specs = mount_specs();
        let flags_of = |mp: &str| specs.iter().find(|(_, t, _, _)| *t == mp).unwrap().3;

        // /run MUST keep device nodes — deploy mknod's the private COS_OEM block
        // node there and mounts it; adding MS_NODEV would silently break injection.
        assert!(
            !flags_of("/run").contains(MsFlags::MS_NODEV),
            "/run must NOT be MS_NODEV (deploy mknod's a block node there)"
        );
        assert!(
            !flags_of("/dev").contains(MsFlags::MS_NODEV),
            "/dev needs nodes"
        );
        // The rest are fully hardened.
        for mp in ["/proc", "/sys", "/tmp"] {
            assert!(
                flags_of(mp).contains(MsFlags::MS_NODEV),
                "{mp} should be MS_NODEV"
            );
        }
        // nosuid,noexec everywhere.
        for (_, mp, _, flags) in specs {
            assert!(flags.contains(MsFlags::MS_NOSUID), "{mp} should be nosuid");
            assert!(flags.contains(MsFlags::MS_NOEXEC), "{mp} should be noexec");
        }
    }

    #[test]
    fn deploy_reason_names_the_failing_step_without_secrets() {
        use crate::image::ImageError;

        // Image-stage failures map to image-specific reasons.
        assert_eq!(
            deploy_error_reason(&DeployError::Image(ImageError::DigestMismatch {
                expected: "sha256:aa".into(),
                computed: "sha256:bb".into(),
            })),
            "image digest mismatch"
        );
        assert_eq!(
            deploy_error_reason(&DeployError::Image(ImageError::TooLarge { max_bytes: 1 })),
            "image too large"
        );
        assert_eq!(
            deploy_error_reason(&DeployError::Image(ImageError::Http(500))),
            "image fetch failed"
        );
        // The whole-disk write (image write to the sink, or the flush).
        assert_eq!(
            deploy_error_reason(&DeployError::Sync(std::io::Error::other("x"))),
            "whole-disk write failed"
        );
        // Partition re-read.
        assert_eq!(
            deploy_error_reason(&DeployError::Reread {
                path: "/dev/sda".into(),
                source: nix::errno::Errno::EIO,
            }),
            "partition re-read failed"
        );
        // COS_OEM inject — the ConfigWrite source is an IO error only, never the
        // join secret, and the reason names the step, not the contents.
        assert_eq!(
            deploy_error_reason(&DeployError::ConfigWrite(std::io::Error::other("x"))),
            "COS_OEM inject failed"
        );

        // The Oem (find-partition) error path has its own reason.
        assert_eq!(
            provision_failure_reason(&RunError::Oem(crate::oem::OemError::NotFound {
                disk: "nvme0n1".into(),
            })),
            "COS_OEM partition not found"
        );

        // Every reason is short and contains no obvious secret marker. (A static
        // smoke check — the real guarantee is that the strings are fixed literals.)
        for r in [
            deploy_error_reason(&DeployError::Sync(std::io::Error::other("x"))),
            provision_failure_reason(&RunError::Oem(crate::oem::OemError::NotFound {
                disk: "nvme0n1".into(),
            })),
        ] {
            assert!(r.len() < 64, "reason {r:?} should be short");
            assert!(!r.contains("Bearer"), "reason {r:?} must not name a token");
        }
    }

    // --- a missing target disk is reported, not left to time out -------------

    fn some_disk() -> crate::target_disk::TargetDisk {
        crate::target_disk::TargetDisk {
            kname: "nvme0n1".into(),
            size_bytes: 1 << 30,
            dev_number: "259:0".into(),
        }
    }

    #[test]
    fn a_missing_target_disk_is_reported_then_returned() {
        // The inspection report was accepted, so the controller is waiting on this
        // host: without the callback the machine only fails at its deployment
        // timeout (20 minutes by default).
        let reported = std::cell::RefCell::new(Vec::new());
        let out = require_target(Err(DiskError::NoEligibleDisk), |reason| {
            reported.borrow_mut().push(reason);
            Ok(())
        });
        assert!(matches!(
            out,
            Err(RunError::Disk(DiskError::NoEligibleDisk))
        ));
        assert_eq!(*reported.borrow(), vec!["no eligible target disk"]);
    }

    #[test]
    fn an_unusable_pinned_disk_is_reported_too() {
        let reported = std::cell::RefCell::new(Vec::new());
        let out = require_target(
            Err(DiskError::PinNotWholeDisk {
                kname: "sda1".into(),
            }),
            |reason| {
                reported.borrow_mut().push(reason);
                Ok(())
            },
        );
        assert!(matches!(
            out,
            Err(RunError::Disk(DiskError::PinNotWholeDisk { .. }))
        ));
        assert_eq!(
            *reported.borrow(),
            vec!["pinned target disk is a partition"]
        );
    }

    #[test]
    fn a_selected_target_disk_reports_nothing() {
        let out = require_target(Ok(some_disk()), |reason| {
            panic!("reported {reason:?} for a usable disk")
        });
        assert_eq!(out.expect("the disk").kname, "nvme0n1");
    }

    #[test]
    fn a_failed_callback_does_not_mask_the_missing_disk() {
        // Best-effort, like the deploy-step funnel: a callback that does not land
        // (a v4 controller's 404, retries exhausted) leaves the original error.
        let calls = Cell::new(0u32);
        let out = require_target(Err(DiskError::NoEligibleDisk), |_| {
            calls.set(calls.get() + 1);
            Err(ClientError::Http(404))
        });
        assert!(matches!(
            out,
            Err(RunError::Disk(DiskError::NoEligibleDisk))
        ));
        assert_eq!(calls.get(), 1, "reported once, not retried here");
    }

    #[test]
    fn disk_reasons_name_the_cause_without_device_names() {
        use crate::target_disk::Ineligible;
        let cases = [
            (DiskError::NoEligibleDisk, "no eligible target disk"),
            (
                DiskError::PinNotFound {
                    pin: "/dev/disk/by-id/wwn-0x5000c500a1b2c3d4".into(),
                },
                "pinned target disk not found",
            ),
            (
                DiskError::PinNotBlockDevice {
                    kname: "ttyS0".into(),
                },
                "pinned target disk is not a block device",
            ),
            (
                DiskError::PinNotWholeDisk {
                    kname: "sda1".into(),
                },
                "pinned target disk is a partition",
            ),
            (
                DiskError::PinIneligible {
                    kname: "sdb".into(),
                    reason: Ineligible::Removable,
                },
                "pinned target disk is ineligible",
            ),
        ];
        for (err, want) in cases {
            let got = provision_failure_reason(&RunError::Disk(err));
            assert_eq!(got, want);
            for name in ["wwn-0x5000c500a1b2c3d4", "ttyS0", "sda1", "sdb", "/dev/"] {
                assert!(!got.contains(name), "reason {got:?} names a device");
            }
        }
    }

    #[test]
    fn poll_times_out_after_max_polls() {
        let calls = Cell::new(0u32);
        let sleeps = Cell::new(0u32);
        let out = poll_bootstrap(
            3,
            |_| sleeps.set(sleeps.get() + 1),
            || {
                calls.set(calls.get() + 1);
                Err(ClientError::Http(404))
            },
        );
        assert!(matches!(out, Err(RunError::BootstrapTimeout)));
        assert_eq!(calls.get(), 3); // exactly max_polls attempts
        assert_eq!(sleeps.get(), 2); // no sleep after the final attempt
    }
}
