#!/usr/bin/env python3
"""Create a small directory containing a plain `as` that forwards to the
RISC-V assembler launcher and its xesp variant siblings.

On Windows the ESP-IDF RISC-V toolchain ships `riscv32-esp-elf-as.exe` as a
launcher that expects `riscv32-esp-elf-as-xespv2p1.exe` / `...p2.exe` next to
it. GCC, however, resolves a plain `as` through PATH. This script copies the
launcher and its siblings into `toolchain_shim/`; build_c5.bat prepends that
directory to PATH.

Run it from an ESP-IDF terminal (so the toolchain is on PATH), or pass --bin.
No vendor file is committed to the repository; .gitignore excludes the shim.
"""

import argparse
import shutil
import sys
from pathlib import Path


def find_bin():
    roots = []
    if shutil.which("riscv32-esp-elf-as") or shutil.which("riscv32-esp-elf-as.exe"):
        found = shutil.which("riscv32-esp-elf-as") or shutil.which("riscv32-esp-elf-as.exe")
        return Path(found).resolve().parent
    for env_name in ("IDF_TOOLS_PATH", "IDF_PATH"):
        value = __import__("os").environ.get(env_name)
        if value:
            roots.append(Path(value))
    roots += [Path(r"C:\Espressif"), Path.home() / "esp", Path.home() / ".espressif"]
    for root in roots:
        for pattern in ("tools/riscv32-esp-elf/*/riscv32-esp-elf/bin",
                        "tools/riscv32-esp-elf/*/bin"):
            for candidate in sorted(root.glob(pattern), reverse=True):
                if (candidate / "riscv32-esp-elf-as.exe").exists() or \
                   (candidate / "riscv32-esp-elf-as").exists():
                    return candidate
    return None


def main():
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", help="path to the riscv32-esp-elf/bin directory")
    parser.add_argument("--out", default=str(repo / "toolchain_shim"),
                        help="output directory (default: <repo>/toolchain_shim)")
    args = parser.parse_args()

    src = Path(args.bin) if args.bin else find_bin()
    if src is None or not src.exists():
        sys.exit("Could not find the RISC-V toolchain. Run from an ESP-IDF "
                 "terminal or pass --bin <.../riscv32-esp-elf/bin>.")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    exe = ".exe" if (src / "riscv32-esp-elf-as.exe").exists() else ""
    mapping = {
        f"riscv32-esp-elf-as{exe}": f"as{exe}",
        f"riscv32-esp-elf-as-xespv2p1{exe}": f"as-xespv2p1{exe}",
        f"riscv32-esp-elf-as-xespv2p2{exe}": f"as-xespv2p2{exe}",
    }
    for src_name, dst_name in mapping.items():
        source = src / src_name
        if source.exists():
            shutil.copy2(source, out / dst_name)
            print(f"copied {source} -> {out / dst_name}")
        else:
            print(f"optional file not found: {source}")
    print(f"\nShim ready: {out}")


if __name__ == "__main__":
    main()
