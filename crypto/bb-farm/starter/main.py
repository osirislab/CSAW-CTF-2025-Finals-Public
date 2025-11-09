from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import os
import subprocess
from pathlib import Path
import sys

from pwn import context, remote

ROOT = Path(__file__).resolve().parents[0]
PROOF_TARGET = ROOT / "../artifacts"
PROGRAM_PATH = ROOT / "../program.so"
CHUNK_SIZE = 64

context.log_level = os.environ.get("PWN_LOG", "info")

def _extension_path() -> Path:
    target_dir = ROOT / "target" / "release"
    suffixes = importlib.machinery.EXTENSION_SUFFIXES
    candidates: list[Path] = []
    for suffix in suffixes:
        candidates.append(target_dir / f"bb_farm_starter{suffix}")
        candidates.append(target_dir / f"libbb_farm_starter{suffix}")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "compiled bb_farm_starter extension not found in target/release"
    )


def ensure_rust_extension() -> Path:
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
        ],
        cwd=ROOT,
        check=True,
    )
    return _extension_path()


def load_rust_module():
    dest = ensure_rust_extension()
    module_name = "bb_farm_starter"
    spec = importlib.util.spec_from_file_location(module_name, dest)
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load spec for {module_name} from {dest}")
    module = importlib.util.module_from_spec(spec)
    loader = spec.loader
    assert loader is not None
    loader.exec_module(module)
    sys.modules[module_name] = module
    return module


RUST_MODULE = load_rust_module()


def _recv_menu(io) -> str:
    raw = io.recvuntil(b"> ")
    text = raw.decode(errors="replace")
    for line in text.splitlines():
        if line.startswith("state:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError(f"missing state line in menu: {text!r}")


def allocate_slot(io, slot_idx: int, name_bytes: bytes, label_bytes: bytes) -> int:
    state_hex = _recv_menu(io)
    alloc_hex, alloc_proof = RUST_MODULE.generate_alloc_proof(
        state_hex,
        CHUNK_SIZE,
        str(PROOF_TARGET),
        str(PROGRAM_PATH),
    )

    io.sendline(b"1")
    io.recvuntil(b"idx: ")
    io.sendline(str(slot_idx).encode())

    io.recvuntil(b"proof (base64): ")
    io.sendline(alloc_proof.encode())

    io.recvuntil(b"result (hex: state+ptr): ")
    io.sendline(alloc_hex.encode())

    io.recvuntil(b"name: ")
    io.sendline(name_bytes.decode())

    io.recvuntil(b"send label (8 bytes)\n")
    io.send(label_bytes)

    confirmation = io.recvline().decode(errors="replace").rstrip("\r\n")
    if "@" not in confirmation:
        raise RuntimeError(f"allocation confirmation unexpected: {confirmation!r}")
    ptr_hex = confirmation.split("@", 1)[1].strip()
    return int(ptr_hex, 16)


def show_slot(io, slot_idx: int) -> tuple[str, bytes]:
    io.sendline(b"2")
    io.recvuntil(b"idx: ")
    io.sendline(str(slot_idx).encode())
    data_line = io.recvline().decode(errors="replace").rstrip("\r\n")
    if ": " not in data_line:
        raise RuntimeError(f"show output unexpected: {data_line!r}")
    name, digest_hex = data_line.split(": ", 1)
    return name, bytes.fromhex(digest_hex)


def free_slot(io, slot_idx: int, ptr: int) -> None:
    state_hex = _recv_menu(io)
    free_hex, free_proof = RUST_MODULE.generate_free_proof(
        state_hex,
        ptr,
        str(PROOF_TARGET),
        str(PROGRAM_PATH),
    )

    io.sendline(b"3")
    io.recvuntil(b"idx: ")
    io.sendline(str(slot_idx).encode())

    io.recvuntil(b"proof (base64): ")
    io.sendline(free_proof.encode())

    io.recvuntil(b"result (hex: state+ptr): ")
    io.sendline(free_hex.encode())


def test_allocate_and_show_roundtrip() -> None:
    io = remote("localhost", 5000)

    slot_idx = 0
    first_name = b"A" * 8
    first_label = bytes(range(8))
    second_name = b"B" * 8
    second_label = bytes(range(8, 16))

    ptr = allocate_slot(io, slot_idx, first_name, first_label)
    shown_name, shown_label = show_slot(io, slot_idx)
    assert shown_name == first_name.decode(), shown_name
    assert shown_label == first_label, shown_label

    free_slot(io, slot_idx, ptr)

    ptr = allocate_slot(io, slot_idx, second_name, second_label)
    shown_name, shown_label = show_slot(io, slot_idx)
    assert shown_name == second_name.decode(), shown_name
    assert shown_label == second_label, shown_label

    io.interactive()

if __name__ == "__main__":
    test_allocate_and_show_roundtrip()
