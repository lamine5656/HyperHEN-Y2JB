#!/usr/bin/env python3
"""Read-only UFS2 extractor for a PS5 `download0.dat` image.

The image is a plain UFS2 filesystem built by `newfs` on FreeBSD. Windows has no
UFS driver and 7-Zip refuses these images, so this script walks the on-disk
structures directly:

  * superblock at byte 65536 (`fs_magic` 0x19540119) gives block size, fragment
    size, inodes per group (0x0B8) and fragments per group (0x0BC),
  * inode `n` lives in cylinder group `n / ipg` at block
    `iblkno + fpg * cg / frags_per_block + (index % ipg) / inopb`,
  * the root directory is inode 2 and its entries are `ufs2_dirent`,
  * file data comes from the 12 direct pointers plus single/double/triple
    indirect blocks, all counted in fragments.

The output is a normal directory tree, ready to be patched and repacked.

Usage:
    tools/ufs2_extract.py --image download0.dat --out extracted/
"""

import argparse
import os
import pathlib
import struct
import sys

SBLOCK_UFS2 = 65536
FS_MAGIC = 0x19540119
OFF_BSIZE = 0x030
OFF_FSIZE = 0x034
OFF_IPG = 0x0B8
OFF_FPG = 0x0BC
INODE_SIZE = 256
DINODE_SIZE_OFF = 16
DINODE_DB = 0x70          # di_db[12]
DINODE_IB = 0xD0          # di_ib[3]

DT_DIR = 4


class Image:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.f.seek(SBLOCK_UFS2)
        sb = self.f.read(0x600)
        if len(sb) < 0x600 or struct.unpack_from("<I", sb, 0x55C)[0] != FS_MAGIC:
            raise SystemExit("not a UFS2 image (magic mismatch at 0x10000+0x55C)")
        self.bsize = struct.unpack_from("<i", sb, OFF_BSIZE)[0]
        self.fsize = struct.unpack_from("<i", sb, OFF_FSIZE)[0]
        self.ipg = struct.unpack_from("<i", sb, OFF_IPG)[0]
        self.fpg = struct.unpack_from("<i", sb, OFF_FPG)[0]
        if min(self.bsize, self.fsize, self.ipg, self.fpg) <= 0:
            raise SystemExit("unexpected geometry in the superblock")
        self.frags_per_block = self.bsize // self.fsize
        self.inopb = self.bsize // INODE_SIZE
        self.nindir = self.bsize // 8
        self.iblkno = self._find_inode_area()

    def _find_inode_area(self):
        """Locate cg0's inode table by finding the root directory inode (#2)."""
        self.f.seek(0)
        window = self.f.read(64 << 20)
        for off in range(0, len(window) - 3 * INODE_SIZE, INODE_SIZE):
            root = off + 2 * INODE_SIZE
            mode, nlink = struct.unpack_from("<Hh", window, root)
            if mode & 0xF000 != 0x4000 or nlink < 2:
                continue
            size = struct.unpack_from("<q", window, root + DINODE_SIZE_OFF)[0]
            if not 0 < size <= 1 << 20:
                continue
            if struct.unpack_from("<q", window, root + DINODE_DB)[0] <= 0:
                continue
            return off // self.bsize
        raise SystemExit("could not locate the inode table (root inode #2)")

    def _inode_offset(self, ino):
        cg = ino // self.ipg
        idx = ino % self.ipg
        blk = self.iblkno + (self.fpg * cg) // self.frags_per_block + idx // self.inopb
        return blk * self.bsize + (idx % self.inopb) * INODE_SIZE

    def inode(self, ino):
        self.f.seek(self._inode_offset(ino))
        raw = self.f.read(INODE_SIZE)
        return {
            "mode": struct.unpack_from("<H", raw, 0)[0],
            "size": struct.unpack_from("<q", raw, DINODE_SIZE_OFF)[0],
            "db": list(struct.unpack_from("<12q", raw, DINODE_DB)),
            "ib": list(struct.unpack_from("<3q", raw, DINODE_IB)),
        }

    def _block(self, frag_no):
        self.f.seek(frag_no * self.fsize)
        return self.f.read(self.bsize)

    def read_file(self, inode):
        size = inode["size"]
        if size <= 0:
            return b""
        out = bytearray()

        for frag_no in inode["db"]:
            if len(out) >= size:
                break
            out += self._block(frag_no) if frag_no else bytes(self.bsize)

        def walk(frag_no, depth):
            if len(out) >= size or not frag_no:
                return
            data = self._block(frag_no)
            for ptr in struct.unpack_from("<%dq" % self.nindir, data, 0):
                if len(out) >= size:
                    return
                if not ptr:
                    continue
                if depth == 1:
                    out.extend(self._block(ptr))
                else:
                    walk(ptr, depth - 1)

        for depth, frag_no in enumerate(inode["ib"], start=1):
            if frag_no:
                walk(frag_no, depth)

        return bytes(out[:size])

    def is_dir(self, inode):
        return inode["mode"] & 0xF000 == 0x4000

    def listdir(self, inode):
        data = self.read_file(inode)
        off = 0
        while off + 8 <= len(data):
            ino, reclen, _dtype, namlen = struct.unpack_from("<IHBB", data, off)
            if reclen < 8 or off + reclen > len(data):
                break
            if ino:
                yield data[off + 8 : off + 8 + namlen].decode("utf-8", "surrogateescape"), ino
            off += reclen


def extract(image, out_dir, ino=2, prefix=""):
    total = 0
    for name, child in image.listdir(image.inode(ino)):
        if name in (".", ".."):
            continue
        node = image.inode(child)
        rel = os.path.join(prefix, name)
        path = out_dir / rel
        if image.is_dir(node):
            path.mkdir(parents=True, exist_ok=True)
            total += extract(image, out_dir, child, rel)
        else:
            payload = image.read_file(node)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            total += len(payload)
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args()

    image = Image(args.image)
    args.out.mkdir(parents=True, exist_ok=True)
    print(
        "geometry: bsize=%d fsize=%d ipg=%d fpg=%d inode_area_blk=%d"
        % (image.bsize, image.fsize, image.ipg, image.fpg, image.iblkno)
    )
    total = extract(image, args.out)
    files = sum(1 for p in args.out.rglob("*") if p.is_file())
    print("extracted %d bytes in %d files -> %s" % (total, files, args.out))


if __name__ == "__main__":
    main()
