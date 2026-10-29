# HyperHEN Y2JB bundle (download0.dat)

This repository builds a `download0.dat` for the YouTube (Y2JB) entry point that
boots **HyperHEN** directly instead of the **Payload Manager**.

Nothing from the HyperHEN source tree lives here. The repository contains only:

| Path | Role |
| :--- | :--- |
| `download0/` | original Y2JB `download0` tree (splash-screen loader, exploit JS, elfldr, kexp, kexp.bin) |
| `HyperHEN.elf` | the payload to boot |
| `tools/y2jb_bundle.py` | rewires the loader and stages the patched tree |
| `.github/workflows/build.yml` | builds the UFS2 image in a FreeBSD VM and publishes it |

## How the chain is rewired

`Relapse.js` runs the kernel exploit, `kexp.bin` starts `elfldr` on `:9021`, and
the splash-screen JavaScript streams its bundled ELF to that loader. With no
`autoload.txt`, `ps5-unified-autoloader.elf` then starts the Payload Manager
(a ~10 KB encrypted blob, `pldmgr_v0.6.3.elf`, plus the web UI embedded in the
autoloader itself).

The patch keeps the exploit chain untouched and points the **first** stage at
HyperHEN:

1. copies `HyperHEN.elf` into
   `cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/`,
2. repoints the loader (`AUTOLOAD_ELF` in `main.js`, `payload_name` in the newer
   split `autoload.js`),
3. drops the now unreachable `ps5-unified-autoloader.elf` / `pldmgr_v*.elf`,
4. silences Y2JB's per-boot comfort toasts (`FW : …`, "Successfully loaded
   unified autoloader"), so the only toast left is HyperHEN's own verdict.

## Build

`.github/workflows/build.yml` runs on every push to `main` (or manually):

1. stages `download0/` + `HyperHEN.elf` into `build/download0/`,
2. inside a FreeBSD 14.2 VM, creates a 336 789 504-byte image with
   `newfs -O 2 -b 32768 -f 4096`, mounts it, copies the staged tree, sets the
   permissions the app expects and checks that the embedded ELF hashes to the
   committed one,
3. zips the result and publishes it on the `latest` release.

Locally:

```bash
python3 tools/y2jb_bundle.py --download0 download0 --elf HyperHEN.elf --out build/download0
```

## Install

1. Download `download0-HyperHEN.zip` from the `latest` release and unzip it.
2. With FTP, replace `download0.dat` in `/user/download/PPSA0165*/` (the YouTube
   app: `PPSA01650` / `PPSA01651` / `PPSA01652`).
3. Launch YouTube: the exploit runs, HyperHEN boots, and exactly one toast
   appears — "Welcome to HYL92" on success, "Retry to load HYL92" on failure.

Payloads sent later can still be pushed to `elfldr` on `:9021`; the Payload
Manager web UI is intentionally not part of this image.
