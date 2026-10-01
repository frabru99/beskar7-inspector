# Firmware licences

The firmware in `initrd.img` is copied from Alpine's `linux-firmware-*`
packages (version `20260519-r0`). Those packages carry no licence files, but
several firmware licences require their text to accompany redistribution. This
directory vendors those texts. The image ships them in the initramfs at
`/lib/firmware/LICENSES/`, next to the files they cover. The carrier image also
has a copy at `/firmware-licenses/`.

## Source

Upstream [linux-firmware](https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git),
tag **`20260519`** (the upstream release Alpine's `20260519-r0` packages).
Each file was fetched once from:

```
https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/<file>?h=20260519
```

- **`LICENCE.*` / `LICENSE.*`**: the upstream files, unmodified.
- **`WHENCE`**: an **excerpt** of upstream `WHENCE`. It is the file's header
  plus the stanzas (cxgb4, tg3, bnx2x, bnx2, qed, r8169, ice) that list at least
  one shipped firmware file. Each kept stanza is copied whole and verbatim; the
  others are left out. The full upstream file at this tag is 440,678 bytes,
  sha256 `93a059ebbd333245a587778663c17d3df09421da30ae6b3e2d18ac2741f506c0`.

The excerpt is deliberate: it is the mapping the image build checks against.
Every shipped firmware file must appear in this `WHENCE` (as a `File:`,
`RawFile:` or `Link:` entry), otherwise **the build fails**. A firmware file
from a driver whose stanza and licence text are not vendored here therefore
cannot ship unnoticed, even though the full upstream `WHENCE` would list it.
`tests/firmware_licenses.rs` (run by `cargo test`) checks that every licence
text the excerpt cites is vendored and that nothing uncited is.

## Updating

When the firmware build check fails, or when the Alpine firmware packages move
to a new upstream tag:

1. Find the new tag (the version of Alpine's `linux-firmware-*` packages).
2. For each shipped file the check names, copy its whole stanza from that tag's
   `WHENCE` into `WHENCE` here, verbatim. Refresh the stanzas already here from
   the same tag.
3. Fetch every `LICENCE.*` / `LICENSE.*` those stanzas cite, from the same tag.
4. Update the tag, URL and sha256 above, then run `cargo test` and `make image`.
