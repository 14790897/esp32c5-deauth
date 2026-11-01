#!/usr/bin/env python3
"""Patch the ESP32-C5 libnet80211.a in YOUR local ESP-IDF installation so
esp_wifi_80211_tx() accepts deauth/disassoc frames.

IDF 6.1 ships a sanity check (`ieee80211_raw_frame_sanity_check`) that rejects
these frame types with "wifi:unsupport frame type: 0c0/0a0". This script finds
that function's section in `ieee80211_output.o` and replaces its first four
bytes with `li a0,0; ret` (RISC-V compressed encoding 01 45 82 80).

The original archive is kept as libnet80211.a.orig. No vendor binary is
distributed by this repository; this only edits the copy on your machine.
Re-run after upgrading or reinstalling ESP-IDF. Use --restore to undo.

Authorized testing only. You are responsible for complying with local law and
with Espressif's license terms.
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

SECTION = ".text.ieee80211_raw_frame_sanity_check"
MEMBER = "ieee80211_output.o"
PATCH = bytes.fromhex("01458280")   # c.li a0,0 ; c.jr ra
STOCK_PROLOGUE = bytes.fromhex("797106d6")  # addi sp,sp,-48 ; sw ra,44(sp)


def default_lib():
    idf = os.environ.get("IDF_PATH")
    if not idf:
        sys.exit("IDF_PATH is not set. Run from an ESP-IDF terminal or pass --lib.")
    return Path(idf) / "components" / "esp_wifi" / "lib" / "esp32c5" / "libnet80211.a"


def find_ar(explicit=None):
    if explicit:
        return explicit
    for name in ("riscv32-esp-elf-ar.exe", "riscv32-esp-elf-ar"):
        found = shutil.which(name)
        if found:
            return found
    sys.exit("riscv32-esp-elf-ar not found on PATH. Run from an ESP-IDF "
             "terminal or pass --ar.")


def section_offset(data: bytes, wanted: str):
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        sys.exit("ieee80211_output.o is not a little-endian ELF32 object")
    e_shoff, = struct.unpack_from("<I", data, 0x20)
    e_shentsize, = struct.unpack_from("<H", data, 0x2E)
    e_shnum, = struct.unpack_from("<H", data, 0x30)
    e_shstrndx, = struct.unpack_from("<H", data, 0x32)

    def header(index):
        off = e_shoff + index * e_shentsize
        return struct.unpack_from("<IIIIIIIIII", data, off)

    shstr = header(e_shstrndx)
    names_off, names_size = shstr[4], shstr[5]
    names = data[names_off:names_off + names_size]

    for index in range(e_shnum):
        sh = header(index)
        name_off = sh[0]
        end = names.find(b"\0", name_off)
        name = names[name_off:end].decode(errors="replace")
        if name == wanted:
            return sh[4], sh[5]  # sh_offset, sh_size
    sys.exit(f"Section {wanted} not found. This script targets the IDF 6.1 "
             f"ESP32-C5 library; check your IDF version.")


def extract(ar, archive: Path, member: str, work: Path) -> Path:
    subprocess.run([ar, "x", str(archive), member], cwd=work, check=True)
    path = work / member
    if not path.exists():
        sys.exit(f"{member} was not extracted from {archive}")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", help="path to libnet80211.a (default: $IDF_PATH/.../esp32c5/libnet80211.a)")
    parser.add_argument("--ar", help="path to riscv32-esp-elf-ar")
    parser.add_argument("--restore", action="store_true", help="restore libnet80211.a from .orig")
    args = parser.parse_args()

    lib = Path(args.lib).resolve() if args.lib else default_lib().resolve()
    backup = lib.with_name(lib.name + ".orig")

    if args.restore:
        if not backup.exists():
            sys.exit(f"No backup at {backup}")
        shutil.copy2(backup, lib)
        print(f"restored {lib} from {backup}")
        return

    ar = find_ar(args.ar)

    if not lib.exists():
        sys.exit(f"Library not found: {lib}")
    if not backup.exists():
        shutil.copy2(lib, backup)
        print(f"backup: {backup}")

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        obj = extract(ar, lib, MEMBER, work)
        data = bytearray(obj.read_bytes())
        offset, size = section_offset(data, SECTION)
        current = bytes(data[offset:offset + 4])

        if current == PATCH:
            print(f"{lib} is already patched ({SECTION} @ 0x{offset:x})")
            return
        if current != STOCK_PROLOGUE:
            print(f"warning: unexpected prologue {current.hex()} at 0x{offset:x}; "
                  f"patching anyway")
        data[offset:offset + 4] = PATCH
        obj.write_bytes(data)

        subprocess.run([ar, "r", str(lib), MEMBER], cwd=work, check=True)

        # Verify round-trip.
        verify = extract(ar, lib, MEMBER, work)
        check = verify.read_bytes()[offset:offset + 4]
        if check != PATCH:
            sys.exit("verification failed: archive was not updated")

    print(f"patched {lib}")
    print(f"section {SECTION} at 0x{offset:x}, size 0x{size:x}")
    print("restore with: python tools/patch_libnet80211.py --restore")


if __name__ == "__main__":
    main()
