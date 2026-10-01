# beskar7-inspector

The hardware-inspection and provisioning ramdisk for
[Beskar7](https://github.com/projectbeskar/beskar7), a Cluster API infrastructure
provider for bare-metal hosts.

The inspector is a single **static Rust binary** (`x86_64-unknown-linux-musl`)
used directly as the initramfs `/init`. It PXE-boots on a target machine, probes
its hardware natively, reports to the Beskar7 controller, then writes the target
OS image to disk and reboots into it. There is no shell, no busybox, and no
external tools — every probe and provisioning syscall is performed in-process.

## Install (operators)

**You do not need to build this.** Each release publishes the two boot files your
boot server serves, plus their checksums:

```bash
REL=https://github.com/projectbeskar/beskar7-inspector/releases/latest/download
curl -fsSLO $REL/vmlinuz
curl -fsSLO $REL/initrd.img
curl -fsSLO $REL/sha256sums.txt
sha256sum -c sha256sums.txt --ignore-missing
```

These artifacts boot your hardware, so verify them before serving. Releases are
signed with [cosign](https://docs.sigstore.dev/) keyless signing (no long-lived key):

```bash
IDENTITY='^https://github.com/projectbeskar/beskar7-inspector/\.github/workflows/release\.yml@refs/tags/.*$'
ISSUER=https://token.actions.githubusercontent.com

curl -fsSLO $REL/sha256sums.txt.cosign.bundle
cosign verify-blob --bundle sha256sums.txt.cosign.bundle \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
  sha256sums.txt
```

A failed verification means the artifacts were not produced by this project's
release workflow — do not boot them.

Serve both files from one directory and point `Beskar7Machine.spec.inspectionImageURL`
at that directory — the controller appends `/vmlinuz` and `/initrd.img` when it
renders the per-host iPXE script.

### Matching the inspector to your controller

The controller and inspector share a **versioned wire contract**. A controller
speaking contract `vN` requires an inspector implementing `vN`. Every release
states its contract version, ships it as `contract-version.txt`, and tags its
container image accordingly — so you can pull the right one without guessing:

```bash
# the contract version your controller speaks: test/contract/VERSION in the beskar7 repo
docker pull ghcr.io/projectbeskar/beskar7-inspector:contract-v4.2
```

The image carries both files at `/vmlinuz` and `/initrd.img` (convenient for
air-gapped mirrors):

```bash
cid=$(docker create ghcr.io/projectbeskar/beskar7-inspector:contract-v4.2)
docker cp $cid:/vmlinuz . && docker cp $cid:/initrd.img . && docker rm $cid
```

Building from source is still supported — see [Build, test, lint](#build-test-lint).

## How it works (contract v4.2)

Beskar7 renders a per-host iPXE script that boots this image with the `beskar7.*`
parameters on the kernel cmdline. The inspector then runs two phases:

1. **Enroll & inspect** (always) — parse the cmdline, probe hardware from
   firmware truth (SMBIOS/DMI via `/sys/firmware/dmi/tables`, plus `/sys` and
   `/proc`), select a target disk, and `POST` the report to the controller over
   verified TLS (success is `202 Accepted`). `--dry-run` stops here.
2. **Provision** (when bootstrap data is ready) — `GET` the CAPI bootstrap
   user-data, stream the digest-pinned whole-disk OS image (a Kairos raw image)
   onto the selected disk while verifying its SHA-256, inject a per-host
   cloud-config (carrying the join secret) into the image's `COS_OEM` partition,
   and `reboot(2)` into the provisioned OS.

```
power on → PXE → controller-rendered iPXE → inspector
              Phase 1: probe → POST report (202)
              Phase 2: GET bootstrap → write image (digest-verified)
                       → inject COS_OEM config → reboot → target OS
```

The wire contract — endpoints, cmdline parameters, the report schema, the
digest-pinning trust model, and the disk/`COS_OEM` behavior — is specified in
[`docs/inspector-contract.md`](https://github.com/projectbeskar/beskar7/blob/main/docs/inspector-contract.md)
in the beskar7 repo (the **source of truth**). This repo implements contract
**v4.2** (`CONTRACT_VERSION` in `src/lib.rs`).

## Hardware support

The image boots Alpine's `linux-lts` kernel, which builds its storage and network
drivers as modules. The initramfs ships a curated set of them
([`modules.list`](modules.list)) and loads all of them at startup. A driver whose
hardware is absent binds nothing.

| Kind | Families | Drivers |
|---|---|---|
| Storage | SATA (AHCI; legacy Intel PIIX/ICH) | `ahci`, `ata_piix` |
| | NVMe | `nvme` |
| | SAS HBAs and RAID: Broadcom/LSI MegaRAID, SAS2/SAS3 HBAs, SAS4 Tri-Mode; Microchip SmartPQI (HPE Smart Array Gen10+); HPE Smart Array before Gen10; Adaptec | `megaraid_sas`, `mpt3sas`, `mpi3mr`, `smartpqi`, `hpsa`, `aacraid` |
| | SCSI disks (SATA, SAS and RAID volumes appear as `/dev/sdX`) | `sd_mod` |
| | Virtual: virtio, VMware PVSCSI | `virtio_blk`, `virtio_scsi`, `vmw_pvscsi` |
| Network | Intel 1/2.5/10/25/40/100GbE | `e1000`, `e1000e`, `igb`, `igc`, `ixgbe`, `i40e`, `ice` |
| | Broadcom NetXtreme, NetXtreme II, NetXtreme-C/E | `tg3`, `bnx2`, `bnx2x`, `bnxt_en` |
| | NVIDIA/Mellanox ConnectX-3 and ConnectX-4+ | `mlx4_en`, `mlx5_core` |
| | Realtek | `r8169` |
| | Marvell/QLogic FastLinQ, Emulex OneConnect, Marvell/Aquantia AQtion, AMD/Solarflare, Chelsio T4–T6, Cisco UCS VIC | `qede`, `be2net`, `atlantic`, `sfc`, `cxgb4`, `enic` |
| | Virtual: virtio, VMware vmxnet3 | `virtio_net`, `vmxnet3` |
| Filesystem | ext4 (for the image's `COS_OEM` partition) | `ext4` |

Drivers that need device firmware get it from the image. At build time, every
firmware file the shipped modules declare is copied into `/lib/firmware`, where
the kernel loads it directly.

So far the image has been boot-tested only on QEMU's emulated NVMe, AHCI, PIIX
and PVSCSI controllers and its igb, e1000e, e1000, vmxnet3 and virtio NICs. The
other drivers are the kernel's upstream drivers and have not been tested on real
hardware by this project.

**If your NIC or storage controller is missing,** the console shows
`no network interface found` or `no eligible target disk found`. Please
[open an issue](https://github.com/projectbeskar/beskar7-inspector/issues) and
include the output of `lspci -nn` from that host. Boot any Linux live image to
get it.

### Firmware licensing

The firmware in `initrd.img` is not covered by this project's Apache-2.0
license. It comes unmodified (only decompressed) from Alpine's `linux-firmware-*`
packages, which repackage the upstream
[linux-firmware](https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git)
repository. Each file is redistributed under the terms its vendor set.

Those license texts ship with the firmware. They are vendored in
[`firmware-licenses/`](firmware-licenses/): the `LICENCE.*`/`LICENSE.*` files,
plus the `WHENCE` entries that map each shipped file to its license. Their
upstream source and tag are recorded in that directory's README. The texts are
copied:

- into `initrd.img` at `/lib/firmware/LICENSES/`, beside the firmware;
- into the container image at `/firmware-licenses/`.

The image build fails if it would ship a firmware file that those `WHENCE`
entries do not cover.

## Security posture

- **Verified TLS** to the callback (rustls, CA delivered on the cmdline); no
  insecure-skip-verify on the report/bootstrap path.
- The **target image is integrity-checked by content digest**, not TLS — it may
  be served over plain HTTP and is gated by `beskar7.target-digest`; the inspector
  never boots a non-matching image.
- The **join secret** is written only to a `0600`/root file on the verified
  `COS_OEM` partition, held in zeroizing buffers, and pinned out of swap with
  `mlockall`. The bearer token, boot nonce, full cmdline, and user-data are never
  logged.
- Device identity is re-verified (`st_rdev`) before every destructive write, so a
  repointed `/dev` node cannot redirect the image or the join secret.

## Build, test, lint

```bash
cargo test --all-targets                       # unit + contract tests
cargo fmt --all -- --check                     # formatting (CI-enforced)
cargo clippy --all-targets -- -D warnings      # lint (CI-enforced)
make check                                     # all three of the above
make image                                     # build build/vmlinuz + build/initrd.img
make test-vm                                   # boot the image in QEMU (Phase 1 smoke)
```

`make image` produces the two boot files (`build/vmlinuz`, `build/initrd.img`)
from the multi-stage `Dockerfile`: it builds the static binary, assembles a
minimal initramfs (the binary as `/init`, the curated kernel modules and the
firmware they declare, and the mountpoints it needs), and
takes the kernel from Alpine's `linux-lts`. An operator serves these two files to
the boot infrastructure the controller's iPXE script points at.

> **Status:** the inspector is feature-complete against contract v4.2 (incl. the
> provisioning-complete and provision-failed callbacks) and fully unit- and
> contract-tested. `make test-vm` smoke-boots the image in QEMU (Phase 1 only —
> without a live callback the run stops after cmdline parsing).
> End-to-end boot (PXE → inspect → provision
> → reboot) is validated as part of Beskar7's integration/e2e work, not in this
> repo's CI (which runs fmt, clippy, and tests).

## Layout

```
src/cmdline.rs      parse /proc/cmdline into the beskar7.* params
src/probe/          native hardware probing (SMBIOS/DMI + /sys + /proc)
src/report.rs       serde structs that serialize to the contract report schema
src/client.rs       rustls callback client: POST report (202), GET bootstrap
src/image.rs        digest-pinned streaming target-image fetch
src/target_disk.rs  target-disk selection
src/oem.rs          locate the COS_OEM partition on the target disk
src/deploy.rs       whole-disk write + COS_OEM mount/inject + reboot
src/run.rs          the PID-1 two-phase pipeline
src/main.rs         thin PID-1 entrypoint over run::run
tests/contract.rs   golden-fixture report round-trip (shared with beskar7)
modules.list        the curated kernel modules the image ships
firmware-licenses/  licence texts + WHENCE mapping for the shipped firmware
```
