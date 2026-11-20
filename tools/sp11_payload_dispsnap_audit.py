# SPDX-License-Identifier: MIT
"""Audits of the compiled payload `dispsnap` that a disassembly cannot make (docs/SP11-PAYLOAD-DISPSNAP.md): where every store of the code goes, from the
LLVM IR of the payload built with the Makefile's own flags, and how deep its frames reach into the stack the runner leaves it. Each audit is a function
of text with faulty texts it must reject (tools/test-q1n1-sp11-payload-dispsnap.py). Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only).

The store audit holds the document's sentence "the payload stores only to its own stack" to the compiled code without counting stores (how many there are
depends on the compiler). It uses the parser and the pointer-root walk of the audit of the payload `xhci` (tools/sp11_payload_xhci_audit.py) and applies
the rules below; they are restated here so that this module stands alone (the same rules hold the sibling read-only snapshot payloads):
  * no integer is ever turned into a pointer (no `inttoptr` in any function): a store to a device, to the framebuffer or to RAM needs one;
  * the root of every store, of every memset, memcpy or memmove destination is an `alloca` of the function (S) or a pointer parameter of a function other
    than the entry (P), whose callers are held to the same rule through the arguments they hand over;
  * a pointer handed to a direct call is rooted in S, P, a constant global (read-only tables and strings) or null, and a pointer handed to an indirect
    call (the runner's ops) in S or P only: the ops store through the pointers they are given;
  * no pointer is kept in memory and read back (a loaded pointer has root L, and none is allowed as a store root or a call argument), so that the roots
    above are the whole story; the four ops are loaded function pointers, which are only called;
  * no writable global, no atomic, no fence, and no call to a function the module does not define (a libcall to memset or memcpy) but the intrinsics.
It proves the BASE of every store and not its offset: the offsets are bounded by the host test's address sanitizer on every run."""
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_xhci_audit as xa  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENTRY = 'payload_entry'
STORE_ROOTS = {'S', 'P'}
DIRECT_ARGUMENT_ROOTS = {'S', 'P', 'G', 'K'}
INDIRECT_ARGUMENT_ROOTS = {'S', 'P'}
# What the ABI keeps free of the payload's stack for q1n1's own ops and a fault frame (platform/uefi/sp11-payload-abi.h): 16 KiB of 64.
STACK_USABLE = 48 * 1024


def cflags(root=ROOT):
    return lib.payload_cflags(Path(root) / 'platform' / 'uefi' / 'Makefile')


def compile_command(root, source, output, *extra):
    root = Path(root)
    return ['clang'] + cflags(root) + ['-Ipayloads'] + list(extra) + [str(source), '-o', str(output)]


def build_ir(source, out_dir, root=ROOT, extra=()):
    """The IR text of `source` (a path), built from `root` with the Makefile's flags (and `extra` after them: a seeded bug may be sloppy enough for -Werror)."""
    root, out_dir = Path(root).resolve(), Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / (Path(source).stem + '.ll')
    done = lib.run(compile_command(root, source, output, '-S', '-emit-llvm', *extra), cwd=root)
    if done.returncode:
        raise RuntimeError(f'{source} did not compile to IR: {done.stderr[-800:]}')
    return output.read_text(encoding='utf-8')


def provenance(ir):
    """(problems, counts) of the IR of the payload: empty problems mean that every store, memset, memcpy and pointer argument of every call has a root
    the module's rules allow. `counts` is what the audit saw, for the facts the document quotes."""
    functions, problems = xa.parse_functions(ir)
    defined = {fn.name for fn in functions}
    counts = {'functions': len(functions), 'stores': 0, 'by_root': {}, 'direct_calls': 0, 'indirect_calls': 0, 'memory_intrinsics': 0}
    for fn in functions:
        where = fn.name
        if fn.inttoptr:
            problems.append(f'{where} has {fn.inttoptr} integer-to-pointer conversions: this payload turns no number into a pointer')
        for atomic in fn.atomics:
            problems.append(f'{where} has an atomic or a fence: {atomic[:60]}')
        for volatile, atomic, dst, rhs in fn.stores:
            counts['stores'] += 1
            kind = xa.roots(fn, dst) if dst else {'U'}
            for root in kind:
                counts['by_root'][root] = counts['by_root'].get(root, 0) + 1
            if atomic:
                problems.append(f'{where} has an atomic store: {rhs[:60]}')
            if fn.name == ENTRY and 'A' in kind:
                problems.append(f'{where} stores through the arguments the runner passed (root A): {rhs[:70]}')
            elif not kind or not kind <= STORE_ROOTS:
                problems.append(f'{where} stores through a pointer that is not its own stack (root {sorted(kind)}): {rhs[:70]}')
        for dst in fn.mem:
            counts['memory_intrinsics'] += 1
            kind = xa.roots(fn, dst)
            if not kind or not kind <= STORE_ROOTS:
                problems.append(f'{where} has a memset, memcpy or memmove into a pointer that is not its own stack (root {sorted(kind)})')
        for callee, operands in fn.calls:
            indirect = callee.startswith('%')
            counts['indirect_calls' if indirect else 'direct_calls'] += 1
            if not indirect and callee not in defined and not callee.startswith('llvm.'):
                problems.append(f'{where} calls {callee}, which the module does not define (a libcall the runner never linked)')
            allowed = INDIRECT_ARGUMENT_ROOTS if indirect else DIRECT_ARGUMENT_ROOTS
            for operand in operands:
                kind = xa.roots(fn, operand)
                if not kind or not kind <= allowed:
                    problems.append(f'{where} hands {"an indirect call" if indirect else callee} a pointer that is not its own memory (root {sorted(kind)}), '
                                    f'which the callee could store through')
    return problems, counts


def frame_sizes(source, out_dir, root=ROOT):
    """{function: bytes of its frame}, from an object built with -fstack-size-section and the Makefile's flags."""
    import shutil
    root, out_dir = Path(root).resolve(), Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    readobj = shutil.which('llvm-readobj', path=lib.ENV['PATH']) or 'llvm-readobj'
    output = out_dir / (Path(source).stem + '.o')
    done = lib.run(compile_command(root, source, output, '-fstack-size-section', '-c'), cwd=root)
    if done.returncode:
        raise RuntimeError(f'{source} did not compile: {done.stderr[-800:]}')
    listing = lib.run([readobj, '--stack-sizes', str(output)]).stdout
    return {name.strip(): int(size, 16) for name, size in re.findall(r'Functions:\s*\[([^\]]+)\]\s*Size:\s*(0x[0-9a-fA-F]+)', listing)}


def stack_depth(sizes, disassembly):
    """(bytes, path) of the deepest chain of frames below the entry; ValueError on a recursion or a function without a frame size."""
    return xa.depth(xa.call_graph(disassembly), sizes, ENTRY)
