# syntax=docker/dockerfile:1
#
# Build beskar7-inspector as a self-contained initramfs: one static
# x86_64-musl binary used directly as /init, the curated kernel modules under
# /lib/modules/<kver>/ and the firmware they request (with its licence texts)
# under /lib/firmware/, plus the empty mountpoints it needs and a console device
# node. No shell, no busybox, no external tools — the binary probes hardware and
# performs every provisioning syscall natively. The output is
# the two artifacts an operator serves to iPXE: /vmlinuz and /initrd.img.

# ---- Stage 1: build the static musl binary --------------------------------
# Bases are pinned tag@digest so a rebuilt tag cannot change the artifact
# silently. Dependabot rewrites both halves together when a tag moves; for a tag
# rebuilt in place it is unreliable, so a base-image security rebuild can need a
# manual digest bump (see .github/dependabot.yml). The tag was `rust:alpine`,
# which floats across Rust releases as well as Alpine ones — naming the version
# keeps a toolchain bump a reviewable change rather than a digest bump.
FROM rust:1.98-alpine3.24@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS build
# ring (pulled in by rustls) builds its asm with a C toolchain + make/perl.
RUN apk add --no-cache musl-dev gcc make perl
WORKDIR /src
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl \
 && strip target/x86_64-unknown-linux-musl/release/beskar7-inspector

# ---- Stage 2: assemble the initramfs and take the kernel ------------------
# kmod + zstd are build-time only (they resolve module deps and decompress the
# .ko files) — they are NOT copied into the initramfs, which stays binary-only.
# The linux-firmware-* subpackages are build-time too: the initramfs takes only
# the files the shipped drivers declare (see the firmware step below), never a
# whole package. They are the subpackages that carry firmware for drivers in
# modules.list (tg3 → tigon, r8169 → rtl_nic, ice's DDP package → intel, qede →
# qed, …); a driver added there that needs firmware may need its subpackage here.
# The digest pins the base, NOT the kernel or the firmware: `apk add` resolves
# against the live 3.24 repository at build time, so either can still move
# without a change here. That is why the kernel version is recorded in the image
# below and named in the release notes.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS assemble
RUN apk add --no-cache linux-lts cpio kmod zstd \
        linux-firmware-bnx2 linux-firmware-bnx2x linux-firmware-cxgb4 \
        linux-firmware-intel linux-firmware-qed linux-firmware-rtl_nic \
        linux-firmware-tigon
WORKDIR /irfs
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/beskar7-inspector ./init
COPY modules.list /tmp/modules.list
COPY firmware-licenses /tmp/firmware-licenses
# Only the mountpoints the init mounts itself, plus a console node for its
# pre-mount stderr (the kernel wires init's stdio to /dev/console if it exists)
# and /dev/null. devtmpfs (mounted by the init) supplies the rest.
RUN chmod 0755 init \
 && mkdir -p proc sys dev run tmp \
 && mknod -m 0600 dev/console c 5 1 \
 && mknod -m 0666 dev/null c 1 3
# Curate the kernel modules (D-012): resolve transitive deps + load order at
# build time, ship the .ko files uncompressed under /lib/modules/<kver>/, and
# write an ordered load-list (beskar7.load) the inspector finit_module's at
# startup. Built-in drivers are skipped: modprobe reports them as "builtin" and
# exits 0, because the driver is already in the kernel image.
#
# An entry that does not resolve at all FAILS THE BUILD. modprobe exits non-zero
# only when the kernel ships nothing under that name, which is what happens when
# a kernel bump renames a driver. Previously that error was swallowed, so the
# initramfs shipped without the driver and the first sign of trouble was a NIC
# or disk that never appeared on real hardware.
RUN set -eu; \
    KVER=$(ls /lib/modules | head -1); \
    DST="/irfs/lib/modules/$KVER"; \
    mkdir -p "$DST"; \
    depmod "$KVER" 2>/dev/null || true; \
    : > "$DST/beskar7.load"; \
    : > /tmp/unresolved; \
    grep -vE '^[[:space:]]*(#|$)' /tmp/modules.list | while read -r mod; do \
        modprobe --show-depends --set-version "$KVER" "$mod" 2>/dev/null \
            || echo "$mod" >> /tmp/unresolved; \
    done > /tmp/depends; \
    if [ -s /tmp/unresolved ]; then \
        echo "ERROR: modules.list entries do not resolve against kernel $KVER:" >&2; \
        sed 's/^/  - /' /tmp/unresolved >&2; \
        echo "A kernel bump can rename a driver or fold it into the image." >&2; \
        echo "Update modules.list. Do not ship an initramfs missing a driver." >&2; \
        exit 1; \
    fi; \
    awk '$1=="insmod"{print $2}' /tmp/depends | awk '!seen[$0]++' | while read -r ko; do \
        base=$(basename "$ko"); unc="${base%.gz}"; unc="${unc%.zst}"; \
        case "$ko" in \
            *.gz)  gunzip -c "$ko" > "$DST/$unc" ;; \
            *.zst) zstd -dqc "$ko" > "$DST/$unc" ;; \
            *)     cp "$ko" "$DST/$unc" ;; \
        esac; \
        echo "/lib/modules/$KVER/$unc" >> "$DST/beskar7.load"; \
    done; \
    builtins=$(awk '$1=="builtin"{print $2}' /tmp/depends | sort -u | wc -l); \
    echo "=== beskar7.load ($(wc -l < "$DST/beskar7.load") modules, $builtins already in the kernel) ==="; \
    cat "$DST/beskar7.load"
# Ship the firmware the loaded drivers request. Several of the NIC drivers need
# it for some or all of their parts (bnx2/bnx2x and qede always; tg3, r8169 and
# cxgb4 for many chips; ice drops to a reduced "safe mode" without its DDP
# package), and the initramfs has no udev or helper to fetch it: the kernel's direct
# loader reads /lib/firmware/<name> straight from the rootfs. So for every
# module in beskar7.load, take the names it declares (`modinfo -F firmware`) and
# copy just those files, at the same relative path.
#
# Alpine packages firmware zstd-compressed (sometimes via a versioned symlink:
# cxgb4/t4fw.bin.zst -> t4fw-1.27.5.0.bin.zst). Each file is resolved through
# its symlinks and written decompressed, so loading it does not depend on the
# kernel's CONFIG_FW_LOADER_COMPRESS_* options; the initramfs gzip compresses it
# again. A declared name with no file is expected, not an error — drivers list
# optional variants and firmware for chips the packages here do not cover — so
# it is counted, not fatal.
#
# modinfo runs outside a pipeline so a failure stops the build instead of
# silently shipping no firmware.
RUN set -eu; \
    KVER=$(ls /lib/modules | head -1); \
    : > /tmp/fw-shipped; \
    : > /tmp/fw-absent; \
    sed 's|^|/irfs|' "/irfs/lib/modules/$KVER/beskar7.load" > /tmp/loaded-kos; \
    xargs modinfo -F firmware < /tmp/loaded-kos > /tmp/fw-declared-raw; \
    sort -u /tmp/fw-declared-raw > /tmp/fw-declared; \
    while read -r name; do \
        src=""; \
        for cand in "/lib/firmware/$name" "/lib/firmware/$name.zst" "/lib/firmware/$name.xz"; do \
            if [ -e "$cand" ]; then src=$(readlink -f "$cand"); break; fi; \
        done; \
        if [ -z "$src" ]; then echo "$name" >> /tmp/fw-absent; continue; fi; \
        dst="/irfs/lib/firmware/$name"; \
        mkdir -p "$(dirname "$dst")"; \
        case "$src" in \
            *.zst) zstd -dqc "$src" > "$dst" ;; \
            *.xz)  xzcat "$src" > "$dst" ;; \
            *)     cp "$src" "$dst" ;; \
        esac; \
        echo "/lib/firmware/$name" >> /tmp/fw-shipped; \
    done < /tmp/fw-declared; \
    echo "=== firmware ($(wc -l < /tmp/fw-shipped) files shipped, $(wc -l < /tmp/fw-absent) declared names not in the shipped packages) ==="; \
    cat /tmp/fw-shipped; \
    if [ -s /tmp/fw-absent ]; then \
        echo "--- declared but not shipped:"; \
        cat /tmp/fw-absent; \
    fi
# Ship the licence texts with the firmware. Several linux-firmware licences
# require their text to accompany redistribution, and Alpine's split firmware
# packages carry none, so they are vendored in firmware-licenses/ (see its
# README). They go to /lib/firmware/LICENSES/, beside the files they cover: the
# kernel only opens the names drivers request, so the directory is inert there.
#
# Every shipped firmware file must be listed in the vendored WHENCE excerpt (as
# File:, RawFile: or Link: — a Link's target sits in the same stanza), and every
# licence text it cites must be vendored. Otherwise the BUILD FAILS: a kernel
# or firmware bump that makes a driver declare a new file must not ship it
# without its licence.
RUN set -eu; \
    LIC=/tmp/firmware-licenses; \
    sed -nE 's/^(File|RawFile|Link):[[:space:]]*"?([^"[:space:]]+)"?.*/\2/p' "$LIC/WHENCE" \
        | sort -u > /tmp/fw-licensed; \
    (cd /irfs/lib/firmware && find . -type f | sed 's|^\./||' | sort) > /tmp/fw-files; \
    comm -23 /tmp/fw-files /tmp/fw-licensed > /tmp/fw-unlicensed; \
    if [ -s /tmp/fw-unlicensed ]; then \
        echo "ERROR: shipped firmware not covered by firmware-licenses/WHENCE:" >&2; \
        sed 's/^/  - /' /tmp/fw-unlicensed >&2; \
        echo "Update the vendored licences: add each file's linux-firmware WHENCE" >&2; \
        echo "stanza and the licence texts it cites (see firmware-licenses/README.md)." >&2; \
        exit 1; \
    fi; \
    grep -oE 'LICEN[CS]E\.[A-Za-z0-9_+-]+(\.[A-Za-z0-9_+-]+)*' "$LIC/WHENCE" | sort -u > /tmp/fw-cited; \
    : > /tmp/fw-text-missing; \
    while read -r text; do \
        [ -s "$LIC/$text" ] || echo "$text" >> /tmp/fw-text-missing; \
    done < /tmp/fw-cited; \
    if [ -s /tmp/fw-text-missing ]; then \
        echo "ERROR: firmware-licenses/WHENCE cites licence texts that are not vendored:" >&2; \
        sed 's/^/  - /' /tmp/fw-text-missing >&2; \
        exit 1; \
    fi; \
    mkdir -p /irfs/lib/firmware/LICENSES; \
    cp "$LIC"/* /irfs/lib/firmware/LICENSES/; \
    echo "=== firmware licences: $(wc -l < /tmp/fw-files) shipped files covered, $(wc -l < /tmp/fw-cited) licence texts shipped ==="; \
    ls /irfs/lib/firmware/LICENSES
RUN find . | cpio --quiet -H newc -o | gzip -9 > /initrd.img \
 && cp /boot/vmlinuz-lts /vmlinuz \
 && ls /lib/modules | head -1 > /kernel-version.txt

# ---- Stage 3: carrier image holding the two artifacts ---------------------
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=assemble /vmlinuz /vmlinuz
COPY --from=assemble /initrd.img /initrd.img
# The kernel these artifacts carry. An operator booting unfamiliar hardware
# needs to know this, and the base-image tag alone does not say it.
COPY --from=assemble /kernel-version.txt /kernel-version.txt
# The licence texts for the firmware inside initrd.img (also shipped in it, at
# /lib/firmware/LICENSES/), so a mirror of this image redistributes them too.
COPY --from=assemble /irfs/lib/firmware/LICENSES/ /firmware-licenses/
LABEL org.opencontainers.image.title="beskar7-inspector" \
      org.opencontainers.image.description="Carrier image for the Beskar7 hardware-inspection initramfs (vmlinuz + initrd.img)" \
      org.opencontainers.image.source="https://github.com/projectbeskar/beskar7-inspector"
# `make build` does `docker create` + `docker cp` to extract /vmlinuz + /initrd.img.
CMD ["/bin/sh"]
