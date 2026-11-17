# SPDX-License-Identifier: MIT
"""Audits of the compiled payload `xhci` that a disassembly cannot make (docs/SP11-PAYLOAD-XHCI.md): where every store of the code goes, from the
LLVM IR of each part built with the Makefile's own flags, and how deep the payload's own frames reach into the stack the runner leaves it, from
the frame sizes of `-fstack-size-section` objects and the call graph of the linked ELF. Each audit is a function of text with faulty texts it must
reject (tools/test-q1n1-sp11-payload-xhci.py); the build helpers write only below the directory they are given. Hardware: NOT RUN.
Evidence: EXPERIMENTAL (host model only).

The store audit holds the record's sentence "only two stores of the binary use a pointer that is not rooted in the payload's own stack, context or
line buffers: the two sinks" to the compiled code without counting stores (how many there are depends on the compiler): every pointer is followed to
its root, and the roots of a store, of a memset or memcpy destination and of a pointer handed to a call must be an `alloca` of the function
(S) or a pointer parameter of a function other than the entry (P), whose callers are held to the same rule, except in the two sinks, which
store through one volatile `inttoptr` each. It proves the BASE of every store and not its offset: a store at a run-time offset from one of those
buffers (a buffer too small, an index gone wild) has a good base and passes. The offsets are checked on the paths the host tests run: the harness's audit
of every device and RAM store of its model, and AddressSanitizer and UBSan on every run (tools/test-q1n1-sp11-payload-xhci.py has a mutant with a
digit buffer that is too small, and tools/test-q1n1-sp11-payload-xhci-compiled.py shows that this audit passes it)."""
from pathlib import Path
import re
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_xhci_lib as xl  # noqa: E402

ENTRY = 'payload_entry'
SINK_STORES = ('mmio_store32', 'ram_store32')
# The functions that may turn an integer into a pointer, exactly once each: the two store sinks and the one load of RAM the xHC may have written.
INTTOPTR = {'mmio_store32': 1, 'ram_store32': 1, 'ram_load32': 1}
# And the three that read the runner's own UEFI memory map in place (loads only: a pointer made from an integer is never stored through or handed on).
INTTOPTR_READERS = ('map_init', 'map_range_in', 'map_top_low')
STORE_ROOTS = {'S', 'P'}
ARGUMENT_ROOTS = {'S', 'P', 'G', 'K'}
# The text functions take strings the payload loaded or was returned (names of registers and refusals) and only read them: their own bodies are held to
# STORE_ROOTS like every other, so a store through one of those strings in them is a problem there.
TEXT_CALLEES = ('refuse', 'say', 'line_to')
TEXT_ARGUMENT_ROOTS = {'L', 'C'}
# What the ABI keeps free of the payload's stack for q1n1's own ops and a fault frame (platform/uefi/sp11-payload-abi.h).
OPS_ALLOWANCE = 16 * 1024


# ---- LLVM IR: a small parser of what clang writes for these parts ------------------------------------------------------------------

def balanced(text, start):
    """The index just past the ')' that closes the '(' at text[start]."""
    depth = 0
    for i in range(start, len(text)):
        depth += text[i] == '('
        depth -= text[i] == ')'
        if depth == 0:
            return i + 1
    raise ValueError('unbalanced parentheses: ' + text[start:start + 60])


def split_top(text):
    """`text` split at the commas outside any bracket."""
    parts, depth, begin = [], 0, 0
    for i, ch in enumerate(text):
        depth += ch in '([{<'
        depth -= ch in ')]}>'
        if ch == ',' and depth == 0:
            parts.append(text[begin:i].strip())
            begin = i + 1
    if text[begin:].strip():
        parts.append(text[begin:].strip())
    return parts


class Function:
    def __init__(self, name, params):
        self.name, self.params = name, params          # params: {name: type}
        self.defs, self.stores, self.mem, self.calls, self.atomics = {}, [], [], [], []
        self.inttoptr = 0


def parse_functions(ir):
    """([Function], [problem]): every `define` of a module, with its definitions, stores, memory intrinsics and calls, and a problem for each global
    that is writable."""
    functions, problems, current = [], [], None
    for line in ir.splitlines():
        if line.startswith('define '):
            found = re.search(r'@([\w.$]+)\(', line)
            start = found.end() - 1
            params = {}
            for param in split_top(line[start + 1:balanced(line, start) - 1]):
                words = param.split()
                if words and words[0] == 'ptr':
                    params[words[-1]] = 'ptr'
            current = Function(found.group(1), params)
            functions.append(current)
        elif line.startswith('}'):
            current = None
        elif line.startswith('@'):
            found = re.match(r'@([\w.$]+)\s*=\s*(.*)', line)
            words = found.group(2).split() if found else []
            if 'global' in words and ('constant' not in words or words.index('global') < words.index('constant')) and 'external' not in words:
                problems.append(f'@{found.group(1)} is a writable global')
        elif current is not None:
            parse_instruction(current, line)
    return functions, problems


def operand_of(argument):
    """The pointer an argument names: its last word, or the global inside a constant `getelementptr (...)` expression."""
    if 'getelementptr' in argument:
        found = re.search(r'ptr\s+(@[\w.$]+|%[\w.]+)', argument[argument.index('getelementptr'):])
        return found.group(1) if found else '?'
    return argument.split()[-1]


def callee_arguments(text):
    """(callee, [(type, operand)]) of the call in `text`, or None for an inline assembly statement."""
    call = re.search(r'\bcall\b', text)
    head = text[call.end():]
    if re.match(r'[^@%(]*\basm\b', head):
        return None
    for found in re.finditer(r'(@[\w.$]+|%[\w.]+)\(', head):
        arguments = head[found.end():balanced(head, found.end() - 1) - 1]
        return found.group(1).lstrip('@'), [(argument.split()[0], operand_of(argument)) for argument in split_top(arguments) if argument.split()]
    raise ValueError('no callee in: ' + text)


def parse_instruction(function, line):
    text = line.strip()
    if not text or text.startswith(';') or re.match(r'^[\w.$]+:', text):
        return
    defined = re.match(r'(%[\w.]+)\s*=\s*(.*)', text)
    name, rhs = (defined.group(1), defined.group(2)) if defined else (None, text)
    words = re.sub(r'^(?:tail|musttail|notail)\s+', '', rhs).split()
    op = words[0] if words else ''
    if name:
        function.defs[name] = rhs
    if op == 'inttoptr':
        function.inttoptr += 1
    if op == 'store':
        flags = words[1:3]
        found = re.search(r',\s*ptr\s+(%[\w.]+|@[\w.$]+|null)(?:\s+\w+)?\s*,\s*align\b', rhs)
        function.stores.append(('volatile' in flags, 'atomic' in flags, found.group(1) if found else None, rhs))
    elif op in ('cmpxchg', 'atomicrmw', 'fence'):
        function.atomics.append(rhs)
    elif op == 'call':
        parsed = callee_arguments(rhs)
        if parsed is None:
            return
        callee, arguments = parsed
        if re.search(r'@llvm\.mem(?:cpy|move|set)\b', rhs):
            function.mem.append(arguments[0][1])
        function.calls.append((callee, [operand for kind, operand in arguments if kind == 'ptr']))


def roots(function, token, seen=None):
    """The set of origins of a pointer value: S an alloca, P a pointer parameter, A one of the entry's, I an integer turned into a pointer, G a global,
    L a pointer loaded from memory, C a pointer a call returned, K null or undefined, U anything else."""
    seen = set() if seen is None else seen
    if token.startswith('@'):
        return {'G'}
    if token in ('null', 'undef', 'poison', 'zeroinitializer'):
        return {'K'}
    if token in function.params:
        return {'A'} if function.name == ENTRY else {'P'}
    if token not in function.defs or token in seen:
        return set() if token in seen else {'U'}
    seen.add(token)
    rhs = function.defs[token]
    op = re.sub(r'^(?:tail|musttail|notail)\s+', '', rhs).split()[0]
    if op == 'alloca':
        return {'S'}
    if op == 'inttoptr':
        return {'I'}
    if op == 'load':
        return {'L'} if re.match(r'load\s+(?:(?:volatile|atomic)\s+)*ptr\b', rhs) else {'U'}
    if op == 'getelementptr':
        found = re.search(r',\s*ptr\s+(%[\w.]+|@[\w.$]+|null)', rhs)
        return roots(function, found.group(1), seen) if found else {'U'}
    if op == 'select':
        return set().union(*(roots(function, t, seen) for t in re.findall(r',\s*ptr\s+(%[\w.]+|@[\w.$]+|null)', rhs)))
    if op == 'phi':
        return set().union(*(roots(function, t, seen) for t in re.findall(r'\[\s*([^,\]]+?)\s*,', rhs)))
    if op == 'call':
        return {'C'}
    return {'U'}


def provenance(irs):
    """(problems, counts) of the IR of every part ({part: text}): empty problems mean that every store, memset, memcpy and pointer argument of every
    call has a root the record allows. `counts` is what the audit saw, for the facts the document quotes."""
    problems = []
    counts = {'functions': 0, 'stores': 0, 'by_root': {}, 'sink_stores': 0, 'inttoptr': {}, 'calls_with_pointers': 0}
    for part, ir in irs.items():
        functions, found = parse_functions(ir)
        problems += [f'{part}: {p}' for p in found]
        for fn in functions:
            counts['functions'] += 1
            where = f'{part}:{fn.name}'
            allowed_conversions = INTTOPTR.get(fn.name, 0)
            if fn.name not in INTTOPTR_READERS and fn.inttoptr != allowed_conversions:
                problems.append(f'{where} has {fn.inttoptr} integer-to-pointer conversions, the record allows {allowed_conversions}')
            if fn.inttoptr:
                counts['inttoptr'][fn.name] = fn.inttoptr
            for atomic in fn.atomics:
                problems.append(f'{where} has an atomic or a fence: {atomic[:60]}')
            for volatile, atomic, dst, rhs in fn.stores:
                counts['stores'] += 1
                kind = roots(fn, dst) if dst else {'U'}
                for root in kind:
                    counts['by_root'][root] = counts['by_root'].get(root, 0) + 1
                if atomic:
                    problems.append(f'{where} has an atomic store: {rhs[:60]}')
                if volatile and kind == {'I'} and fn.name in SINK_STORES:
                    counts['sink_stores'] += 1
                    continue
                if not kind or not kind <= STORE_ROOTS:
                    problems.append(f'{where} stores through a pointer that is not its own memory (root {sorted(kind)}): {rhs[:70]}')
            for dst in fn.mem:
                kind = roots(fn, dst)
                if not kind or not kind <= STORE_ROOTS:
                    problems.append(f'{where} has a memset or memcpy into a pointer that is not its own memory (root {sorted(kind)})')
            for callee, operands in fn.calls:
                counts['calls_with_pointers'] += bool(operands)
                allowed = ARGUMENT_ROOTS | (TEXT_ARGUMENT_ROOTS if callee in TEXT_CALLEES else set())
                for operand in operands:
                    kind = roots(fn, operand)
                    if not kind or not kind <= allowed:
                        problems.append(f'{where} hands {callee} a pointer that is not its own memory (root {sorted(kind)}), which the callee could store through')
        for sink in SINK_STORES:
            if any(f.name == sink for f in functions):
                sink_fn = next(f for f in functions if f.name == sink)
                if len(sink_fn.stores) != 1:
                    problems.append(f'{part}:{sink} has {len(sink_fn.stores)} stores, the sink is one')
    return problems, counts


def build_ir(controller, out_dir, root=xl.ROOT):
    """{part: IR text} of every part for one controller, from the sources of `root`, with the Makefile's own flags."""
    root, out_dir = Path(root).resolve(), Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    irs = {}
    for part in xl.PARTS:
        output = out_dir / f'{part}.ll'
        done = lib.run(compile_command(root, controller, part, output, '-S', '-emit-llvm'), cwd=root)
        if done.returncode:
            raise RuntimeError(f'{part} did not compile to IR: {done.stderr[-800:]}')
        irs[part] = output.read_text(encoding='utf-8')
    return irs


def compile_command(root, controller, part, output, *extra):
    root = Path(root)
    return (['clang'] + lib.payload_cflags(root / 'platform' / 'uefi' / 'Makefile') + [f'-DXHCI_S1_CONTROLLER={controller}', '-Ipayloads'] + list(extra) +
            [str(root / 'payloads' / f'{part}.c'), '-o', str(output)])


# ---- the frames ------------------------------------------------------------------------------------------------------------------------

def frame_sizes(controller, out_dir, root=xl.ROOT):
    """{function: bytes of its frame} for every part, from objects built with -fstack-size-section and the Makefile's flags."""
    root, out_dir = Path(root).resolve(), Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    readobj = shutil.which('llvm-readobj', path=lib.ENV['PATH']) or 'llvm-readobj'
    sizes = {}
    for part in xl.PARTS:
        output = out_dir / f'{part}.o'
        done = lib.run(compile_command(root, controller, part, output, '-fstack-size-section', '-c'), cwd=root)
        if done.returncode:
            raise RuntimeError(f'{part} did not compile: {done.stderr[-800:]}')
        listing = lib.run([readobj, '--stack-sizes', str(output)]).stdout
        for name, size in re.findall(r'Functions:\s*\[([^\]]+)\]\s*Size:\s*(0x[0-9a-fA-F]+)', listing):
            if name.strip() in sizes:
                raise ValueError(f'two functions named {name.strip()}: the call graph could not tell them apart')
            sizes[name.strip()] = int(size, 16)
    return sizes


def call_graph(disassembly):
    """{function: {direct callees}} from `llvm-objdump -d`: a bl or a b to the start of another function (a b into the middle of one is a branch)."""
    graph, function = {}, None
    for line in disassembly.splitlines():
        label = re.match(r'[0-9a-f]+ <([^>]+)>:', line)
        if label:
            function = label.group(1)
            graph.setdefault(function, set())
            continue
        found = re.search(r'\t(?:bl|b)\t0x[0-9a-f]+ <([^>+]+)>\s*$', line)
        if found and function and found.group(1) != function:
            graph[function].add(found.group(1))
    return graph


def depth(graph, sizes, entry=ENTRY):
    """(bytes, path) of the deepest chain of frames below `entry`; ValueError on a recursion or a function without a frame size."""
    memo, visiting = {}, []

    def walk(name):
        if name in visiting:
            raise ValueError('recursion: ' + ' -> '.join(visiting + [name]))
        if name not in sizes:
            raise ValueError(f'no frame size for {name}')
        if name not in memo:
            visiting.append(name)
            below = max((walk(callee) for callee in sorted(graph.get(name, ()))), default=(0, []))
            visiting.pop()
            memo[name] = (sizes[name] + below[0], [name] + below[1])
        return memo[name]

    return walk(entry)
