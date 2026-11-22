# SPDX-License-Identifier: MIT
"""Audits of the compiled payload `inpsnap2` that a disassembly cannot make (docs/SP11-PAYLOAD-INPSNAP2.md): where every store of the code goes, from the LLVM IR of the payload built with
the Makefile's own flags, and how deep its frames reach into the stack the runner leaves it. The audits are the ones of the payload `inputsnap` (tools/sp11_payload_inputsnap_audit.py, whose
parser and pointer-root walk are the xhci audit's): the same rules hold here (no integer is ever turned into a pointer, the root of every store, memset, memcpy or memmove destination is an
`alloca` of the function or a pointer parameter whose callers are held to the same rule, no pointer is kept in memory, no writable global, no atomic, no libcall), and nothing of it is
copied. The payload's allow-list entry is POLICIES['inpsnap2'] of tools/sp11_payload_testlib.py (after gpusnap2's), which is what the generic payload suites iterate; this module registers the same dict at import (setdefault) so
that its own tools work on a tree without the shared entry, and tools/test-q1n1-sp11-payload-inpsnap2.py holds the two equal. Neither audit checks the OFFSET of a store, only its base (docs/SP11-PAYLOAD-INPSNAP2.md, 4.1).
Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_inputsnap_audit as base  # noqa: E402

ROOT = base.ROOT
ENTRY = base.ENTRY
STACK_USABLE = base.STACK_USABLE
provenance = base.provenance
build_ir = base.build_ir
frame_sizes = base.frame_sizes
stack_depth = base.stack_depth

# The allow-list entry of the payload (the same dict as the shared table's): MRS of CurrentEL and nothing else (no counter, no wait), no SMC, no barrier at all, and `read_only`, which
# tools/sp11_payload_memcheck.py checks from the disassembly (the IR audit checks the base of every store again from the compiler's own view; neither checks an offset). `bytes` is the one
# range the runner is told about, whatever the size.
POLICY = {'registers': {'currentel'}, 'smc': 0, 'bytes': 8192, 'forbid': {'isb', 'dsb', 'dmb', 'sb', 'sev', 'sevl'}, 'read_only': True}
lib.POLICIES.setdefault('inpsnap2', POLICY)
