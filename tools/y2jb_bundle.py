#!/usr/bin/env python3
# Copyright (C) 2026 OnionHEN / LightningMods
"""Boot HyperHEN straight from the Y2JB payload (download0) bundle.

The itsPLK Y2JB chain is:

    Relapse/Lapse (kernel exploit) -> kexp -> elfldr on :9021
      -> the splash-screen JS streams its bundled ELF to elfldr
        -> ps5-unified-autoloader.elf: reads autoload.txt, else starts Payload Manager

Nothing in that chain knows about HyperHEN, so the stock bundle always lands in
the Payload Manager web UI. This script rewires the first stage instead of
fighting the second one:

  * copies HyperHEN.elf into the splash_screen cache directory,
  * points the JS at it (`AUTOLOAD_ELF` in older bundles, `payload_name` in the
    v1.1+ split autoload.js), so elfldr receives HyperHEN directly,
  * drops the now unreachable ps5-unified-autoloader.elf / pldmgr_v*.elf,
  * drops Y2JB's comfort toasts (per-boot "FW : ..." banner and the misleading
    "Successfully loaded unified autoloader"), because HyperHEN now reports the
    only verdict that matters: its own success or failure toast.

Errors from the exploit/loader are left untouched.

Usage:
    scripts/y2jb_bundle.py --download0 <dir> --elf HyperHEN.elf [--out <dir>]
"""

import argparse
import pathlib
import re
import shutil
import sys

# Older main.js refuses anything larger: `size > 0x1000000n` throws.
AUTOLOAD_SIZE_LIMIT = 0x1000000
SPLASH_SUFFIX = ("cache", "splash_screen")
BUNDLED_ELF = "HyperHEN.elf"
# Payload selection moved between releases; accept both spellings.
AUTOLOAD_PATTERNS = (
    re.compile(r'(const\s+AUTOLOAD_ELF\s*=\s*")([^"]*)(")'),
    re.compile(r'(const\s+payload_name\s*=\s*")([^"]*)(")'),
)
SCRIPT_ORDER = ("autoload.js", "main.js")
# Stage-one artefacts that only exist to reach the Payload Manager.
REPLACED_FILES = ("ps5-unified-autoloader.elf",)
TOAST_GUARD_MARK = "/* hyperhen: verdict only */"
TOAST_GUARD = (
    "    " + TOAST_GUARD_MARK + "\n"
    "    // HyperHEN boots after this loader and reports the real verdict, so\n"
    "    // drop Y2JB's per-boot chatter instead of stacking toasts on top of it.\n"
    '    if (/^FW : /.test(text) ||\n'
    '        /Successfully loaded unified autoloader/.test(text)) {\n'
    "        return;\n"
    "    }\n"
)


def fail(message):
    print("error: " + message, file=sys.stderr)
    raise SystemExit(1)


def find_splash_dir(download0):
    """Return the single cache/splash_screen/<base64 url>/ directory."""
    root = download0.joinpath(*SPLASH_SUFFIX)
    if not root.is_dir():
        fail("%s has no %s/" % (download0, "/".join(SPLASH_SUFFIX)))

    candidates = [d for d in root.iterdir() if d.is_dir() and (d / "main.js").is_file()]
    if len(candidates) != 1:
        fail(
            "expected exactly one splash_screen cache directory with main.js, found %d"
            % len(candidates)
        )
    return candidates[0]


def read_text(path):
    return path.read_text(encoding="utf-8", errors="surrogateescape")


def write_text(path, text):
    path.write_text(text, encoding="utf-8", errors="surrogateescape")


def patch_payload_name(splash):
    """Point the loader at HyperHEN.elf. Returns (file, previous, patched)."""
    ordered = [splash / name for name in SCRIPT_ORDER]
    ordered += [p for p in sorted(splash.glob("*.js")) if p not in ordered]

    for script in ordered:
        if not script.is_file():
            continue
        text = read_text(script)
        for pattern in AUTOLOAD_PATTERNS:
            match = pattern.search(text)
            if not match:
                continue
            previous = match.group(2)
            if previous == BUNDLED_ELF:
                return script.name, previous, False
            write_text(
                script,
                text[: match.start()]
                + match.group(1)
                + BUNDLED_ELF
                + match.group(3)
                + text[match.end() :],
            )
            return script.name, previous, True

    fail(
        "no payload constant found in %s (looked for AUTOLOAD_ELF / payload_name)"
        % splash
    )


def patch_toast_filter(splash):
    """Silence Y2JB's per-boot comfort toasts, keep real errors."""
    misc = splash / "misc.js"
    if not misc.is_file():
        return None
    text = read_text(misc)
    if TOAST_GUARD_MARK in text:
        return "already filtered"

    decl = "function send_notification(text) {\n"
    index = text.find(decl)
    if index < 0:
        return "send_notification() not found, skipped"

    insert_at = index + len(decl)
    write_text(misc, text[:insert_at] + TOAST_GUARD + text[insert_at:])
    return "boot chatter filtered"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--download0",
        required=True,
        type=pathlib.Path,
        help="Y2JB tree root (the directory copied to /mnt when building download0.dat)",
    )
    parser.add_argument(
        "--elf", required=True, type=pathlib.Path, help="HyperHEN.elf to embed"
    )
    parser.add_argument(
        "--out",
        type=pathlib.Path,
        help="write the patched tree here instead of modifying --download0 in place",
    )
    parser.add_argument(
        "--keep-toasts",
        action="store_true",
        help="keep Y2JB's own boot toasts (do not filter them)",
    )
    args = parser.parse_args()

    source_tree = args.download0.resolve()
    if not source_tree.is_dir():
        fail("%s is not a directory" % source_tree)

    elf = args.elf.resolve()
    if not elf.is_file():
        fail("%s does not exist" % elf)

    payload = elf.read_bytes()
    if payload[:4] != b"\x7fELF":
        fail("%s is not an ELF file" % elf)
    if not 4 <= len(payload) <= AUTOLOAD_SIZE_LIMIT:
        fail(
            "%s is %d bytes; the loader only accepts 4..%d bytes (0x1000000)"
            % (elf, len(payload), AUTOLOAD_SIZE_LIMIT)
        )

    if args.out:
        target = args.out.resolve()
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source_tree, target, symlinks=True)
        print("copied %s -> %s" % (source_tree, target))
    else:
        target = source_tree

    splash = find_splash_dir(target)
    script, previous_elf, patched = patch_payload_name(splash)
    (splash / BUNDLED_ELF).write_bytes(payload)

    removed = []
    for name in REPLACED_FILES:
        stale = splash / name
        if stale.exists():
            stale.unlink()
            removed.append(name)
    for stale in sorted(splash.glob("pldmgr_v*.elf")):
        stale.unlink()
        removed.append(stale.name)

    toasts = "kept" if args.keep_toasts else patch_toast_filter(splash)

    print("splash dir   : %s" % splash.relative_to(target))
    print(
        "payload hook : %s %s -> %s%s"
        % (script, previous_elf, BUNDLED_ELF, "" if patched else " (already set)")
    )
    print(
        "embedded     : %s (%d bytes, %.2f MiB)"
        % (BUNDLED_ELF, len(payload), len(payload) / 1048576)
    )
    print("removed      : %s" % (", ".join(removed) if removed else "nothing"))
    print("boot toasts  : %s" % toasts)
    total = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
    print("tree size    : %d bytes (%.1f MiB)" % (total, total / 1048576))
    print()
    print("Next: build the 336789504-byte UFS2 image with")
    print(
        "  newfs -O 2 -b 32768 -f 4096 /dev/<md>  then  cp -R %s/. /mnt/" % target.name
    )


if __name__ == "__main__":
    main()
