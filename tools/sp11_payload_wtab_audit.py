# SPDX-License-Identifier: MIT
"""The policy tooling of the write-table payload policy (docs/SP11-PAYLOAD-WTAB.md): what a payload may do when its device words are changed by
the runner from a table and never by the payload. Three independent layers, each a function of text or bytes with faulty inputs it must reject
(tools/test-q1n1-sp11-payload-wtab.py):

  the IR     (ir_problems)           built with the Makefile's own flags. No integer becomes a pointer; every store, memset and memcpy has a root in the
                                     payload's own stack (a select or a phi counts every operand, and an operand it cannot read is unknown), and a store
                                     through a computed index is a finding outside the functions the policy names, and so is a pointer moved by a
                                     computed index and handed to a function of the module; the only indirect calls are the four
                                     ops of the payload ABI (puts, hex, load32, counter) and the three of the write table, found by where the pointer was loaded from; `open` gets the
                                     table constant itself and nothing else; `row` gets a literal below the table's row count, and over the code every
                                     row index is asked for exactly once.
  the binary (binary_call_problems)  tools/sp11_payload_memcheck.py with `ops=True`: every `blr` of the disassembly has a register loaded from the ops tables
                                     (so no call to an address the payload made up, and nothing hidden in inline assembly), and the literal in w0 before each
                                     `row` call is read from the code: the same set as in the IR. The `read_only` policy key checks the base of the stores
                                     and `register_offset_stores` pins the stores whose offset is a register and refuses a stack pointer moved by a register
                                     as the base of a store.
  the table  (table_problems)        the table constant is found in the ELF by its symbol, decoded by the runner's own rules (tools/sp11_wtab.py,
                                     validate_blob) and, when the approval names one, hashed: the bytes the payload carries are the bytes approved. The
                                     flat binary holds the table magic once: no second table, and none inside the first.

Every finding is a sentence that starts with a CODE, so that a seeded bug is held to the reason it was seeded for (CODES). This is a lint, not a proof that a payload cannot write a device word: it checks the BASE of every
store, a computed index where the IR shows one (in a store's own function and in a pointer a function of the module is handed, CALL_ARGUMENT_INDEXED), the register
offset of a store and a stack pointer moved by a register (the binary, under the key `register_offset_stores`), and the INDEX of every row; an offset that is a literal
is not compared with the size of the stack object here, a pointer advanced by a loop is not followed, the pointer an op of the payload ABI is given (the destination of hex, the
string of puts, the `out` of load32: S38, S39, S40) is asked only to be rooted in the stack or the image, and a payload is not trusted because it passes. What keeps a store to a device word out of a payload is that its bytes are reviewed and pinned by the SHA-256 in the
manifest (tools/sp11_payload_testlib.py, sp11-payload-abi.h); these checks catch the accident. What the hardware does with a word is the runner's job at run time
(docs/SP11-PAYLOAD-WTAB.md), and a runner with the write table refuses an op's pointer outside the stack (outside the stack and the image, for puts) when the code runs
(platform/uefi/sp11-payload-run.c). A call of an `llvm.*` intrinsic is exempt from CALL_ARGUMENT_INDEXED (the destination of a memset or a memcpy is judged as a store); an exclusive store hidden in a builtin
(S46) is a finding of the binary policy and of nothing here. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host tool)."""
from collections import Counter
import hashlib
from pathlib import Path
import re
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_wtab as wtab  # noqa: E402


class _LazyXhciAudit:
    """tools/sp11_payload_xhci_audit.py (its IR parser), imported on first use: importing it registers the xHCI policies in the shared list of tools/sp11_payload_testlib.py,
    which the tests of the other payloads must not see just because the policy of a payload with a write table checked its binary (that check does not parse IR)."""
    def __getattr__(self, name):
        import sp11_payload_xhci_audit
        return getattr(sp11_payload_xhci_audit, name)


xa = _LazyXhciAudit()

# wtabref (tools/wtab-ref/ref-payload.c, docs/SP11-PAYLOAD-WTAB.md) is the reference of the write-table policy: a payload that never reads a system register, whose stores have
# the base of its own stack (`read_only`, which tools/sp11_payload_memcheck.py checks from the disassembly), whose only stores with a register offset are those of the helpers that
# append a line (`register_offset_stores`), and that changes device words only by asking the runner for the rows of the table it carries (`write_table`: the table of the ELF by
# the runner's own rules, and every indirect call of the code). It is built by the tests of this tool and by nothing else, so its policy is registered here and not in the shared
# list the build test builds a payload from. The append function `line_text` of the reference payload (the loop of `pl_text`, payloads/payload-util.h: the text of a line is written through an
# index) is its only function that stores through a register offset.
lib.POLICIES.setdefault('wtabref', {'registers': set(), 'smc': 0, 'bytes': 4096, 'forbid': {'isb', 'dsb', 'dmb', 'sb', 'sev', 'sevl'}, 'read_only': True,
                                    'register_offset_stores': {'line_text': 2}, 'write_table': {}})
ROOT = Path(__file__).resolve().parents[1]
ENTRY = 'payload_entry'
ABI_OPS = {120: 'puts', 128: 'hex', 136: 'load32', 144: 'counter'}
WTAB_OPS = {16: 'open', 24: 'row', 32: 'unwind'}
WTAB_POINTER_OFFSET = 152
STORE_ROOTS = {'S', 'P'}
DIRECT_ARGUMENT_ROOTS = {'S', 'P', 'G', 'K'}
# The runner's ops store through the pointers they are given only where a pointer is where they put a result: hex's buffer and load32's `out`. A line of text is
# only read, so a constant string is fine for puts.
OP_ARGUMENT_ROOTS = {'puts': {'S', 'P', 'G', 'K'}, 'hex': {'S', 'P'}, 'load32': {'S', 'P'}, 'counter': set()}
CODES = {
    'INTTOPTR': 'an integer is turned into a pointer',
    'ATOMIC': 'an atomic or a fence',
    'WRITABLE_GLOBAL': 'a writable global',
    'INLINE_ASM': 'inline assembly, which the IR audit cannot see into',
    'STORE_INTTOPTR': 'a store through a pointer made from a number (a device or RAM store at a fixed address)',
    'STORE_ARGS': 'a store through the arguments the runner passed',
    'STORE_LOADED': 'a store through a pointer that was read from memory (for example the runner\'s own ops table)',
    'STORE_GLOBAL': 'a store to a global',
    'STORE_UNKNOWN': 'a store whose base is not one of the above and not the payload\'s own stack',
    'STORE_INDEXED': 'a store to the payload\'s own stack through an index that is not a literal, in a function the policy does not name (register_offset_stores)',
    'CALL_UNDEFINED': 'a call to a function the module does not define',
    'CALL_TARGET_UNKNOWN': 'an indirect call whose function pointer is not one of the ops',
    'CALL_ARGUMENT_ROOT': 'a pointer argument that is not the payload\'s own memory',
    'CALL_ARGUMENT_INDEXED': 'a pointer argument of a function of the module that was moved by an index that is not a literal (the callee may store through it)',
    'OPEN_COUNT': 'the table is not opened exactly once',
    'OPEN_ARGUMENT': 'open is not given the table constant itself (the whole operand, not an address inside it) and nothing else',
    'ROW_ARITY': 'row is not called with exactly one integer',
    'ROW_INDEX_NOT_CONSTANT': 'a row index that is not a literal',
    'ROW_INDEX_RANGE': 'a row index at or above the table\'s row count',
    'ROW_COVERAGE': 'a row of the table that no call site asks for, or that two do',
    'READ_ADDRESS_NOT_CONSTANT': 'a read at an address that is not a literal',
    'READ_NOT_GATED': 'a read of a word that is in no readable block and in no window of the table',
    'TABLE_MISSING': 'no table constant in the ELF',
    'TABLE_REFUSED': 'the runner would refuse the table the binary carries',
    'TABLE_COUNT': 'the flat binary holds the table magic other than exactly once (a second table, or one nested in the first)',
    'TABLE_DRAFT': 'the table is a draft (its name ends with -DRAFT)',
    'TABLE_SHA': 'the table the binary carries is not the one approved',
    'BIN_INDIRECT_CALL': 'a blr whose register was not loaded from an ops table',
    'BIN_ROW_INDEX': 'a row call whose literal cannot be read from the code before it',
    'BIN_ROW_COVERAGE': 'the literals of the row calls of the binary are not each row once',
    'BIN_OPEN_COUNT': 'the binary does not call open exactly once',
}


def finding(code, text):
    return f'{code}: {text}'


def codes_of(findings):
    return {item.split(':', 1)[0] for item in findings}


# ---- The IR ------------------------------------------------------------------------------------------------------------------------

def cflags(root=ROOT):
    return lib.payload_cflags(Path(root) / 'platform' / 'uefi' / 'Makefile')


def build_ir(source, out_dir, root=ROOT, extra=()):
    """The IR text of `source`, built from `root` with the Makefile's flags (and `extra`, the include path of a generated table, after them)."""
    root, out_dir = Path(root).resolve(), Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / (Path(source).stem + '.ll')
    done = lib.run(['clang'] + cflags(root) + ['-Ipayloads'] + list(extra) + ['-S', '-emit-llvm', str(Path(source).resolve()), '-o', str(output)], cwd=root)
    if done.returncode:
        raise RuntimeError(f'{source} did not compile to IR: {done.stderr[-800:]}')
    return output.read_text(encoding='utf-8')


CALL = re.compile(r'^\s*(?:(%[\w.]+)\s*=\s*)?(?:tail\s+|musttail\s+|notail\s+)?call\b(.*)$')
GEP = re.compile(r'getelementptr(?:\s+(?:inbounds|nuw|nusw))*\s+i8,\s*ptr\s+(%[\w.]+|@[\w.$]+),\s*i64\s+(-?\d+)\s*(?:,\s*!.*)?$')
LOAD = re.compile(r'load\s+(?:volatile\s+)?ptr,\s*ptr\s+(%[\w.]+|@[\w.$]+)')


def parse_calls(ir):
    """[(function, callee, args)] of every call of the module, `callee` '@name', '%n' or 'asm', `args` [(type, token)]."""
    found, current = [], None
    for line in ir.splitlines():
        if line.startswith('define '):
            current = re.search(r'@([\w.$]+)\(', line).group(1)
            continue
        if line.startswith('}'):
            current = None
            continue
        match = CALL.match(line) if current else None
        if not match:
            continue
        head = match.group(2)
        if re.match(r'[^@%(]*\basm\b', head):
            found.append((current, 'asm', []))
            continue
        for call in re.finditer(r'(@[\w.$]+|%[\w.]+)\(', head):
            inner = head[call.end():xa.balanced(head, call.end() - 1) - 1]
            args = []
            for argument in xa.split_top(inner):
                words = argument.split()
                if not words:
                    continue
                token = argument[argument.index('getelementptr'):] if 'getelementptr' in argument else words[-1]
                args.append((words[0], token))
            found.append((current, call.group(1), args))
            break
    return found


def constants(fn, token, seen=None):
    """The set of integers an SSA integer can be when it is made only of literals (through phi, select and width changes), else None."""
    seen = set() if seen is None else seen
    if re.fullmatch(r'-?\d+', token):
        return {int(token)}
    if token in seen or token not in fn.defs:
        return None
    seen.add(token)
    rhs = fn.defs[token]
    op = rhs.split()[0]
    if op in ('zext', 'sext', 'trunc'):
        source = re.match(rf'{op}\s+(?:nneg\s+|nuw\s+|nsw\s+)*\w+\s+(\S+)\s+to\b', rhs)
        return constants(fn, source.group(1), seen) if source else None
    if op == 'phi':
        values = [constants(fn, item, seen) for item in re.findall(r'\[\s*([^,\]]+?)\s*,', rhs)]
    elif op == 'select':
        items = xa.split_top(rhs[len('select'):])
        values = [constants(fn, items[i].split()[-1], seen) for i in (1, 2)] if len(items) >= 3 else [None]
    else:
        return None
    return None if any(value is None for value in values) else set().union(*values)


def address(fn, token):
    """(base token, byte offset) of a pointer that is the base moved by literal byte offsets, else (token, None)."""
    offset = 0
    while token in fn.defs and fn.defs[token].startswith('getelementptr'):
        match = GEP.match(fn.defs[token])
        if not match:
            return token, None
        offset += int(match.group(2))
        token = match.group(1)
    return token, offset


def is_entry_argument(fn, token):
    return fn.name == ENTRY and token in fn.params


def callee_op(fn, token):
    """The op (puts, hex, load32, counter, open, row, unwind) a function pointer `token` was loaded from, or None."""
    rhs = fn.defs.get(token, '')
    match = LOAD.match(rhs)
    if not match:
        return None
    base, offset = address(fn, match.group(1))
    if offset is None:
        return None
    if is_entry_argument(fn, base):
        return ABI_OPS.get(offset)
    inner = LOAD.match(fn.defs.get(base, ''))
    if inner:
        origin, where = address(fn, inner.group(1))
        if where == WTAB_POINTER_OFFSET and is_entry_argument(fn, origin):
            return WTAB_OPS.get(offset)
    return None


def roots_of(fn, token, seen=None):
    """The origins of a pointer operand: S an alloca, P a pointer parameter, A one of the entry's, I an integer turned into a pointer, G a global, L a pointer loaded from
    memory, C a pointer a call returned, K null or undefined, U anything else. Fail closed: an operand that is not a name, a global or null (a constant expression
    `inttoptr (i64 N to ptr)` in a `select` or a `phi`, for one) is an integer turned into a pointer or unknown, never silently left out of the set
    (tools/sp11_payload_xhci_audit.py roots reads only `%name`, `@name` and `null` operands of a select or a phi, so a constant-expression operand drops out of its set)."""
    seen = set() if seen is None else seen
    token = (token or '').strip()
    if not token:
        return {'U'}
    if token.startswith('inttoptr'):
        return {'I'}
    if token.startswith('getelementptr'):
        base = re.search(r'\bptr\s+(@[\w.$]+|%[\w.]+|inttoptr\s*\(.*?\)|null)\s*(?:,|\))', token)
        return roots_of(fn, base.group(1), seen) if base else {'U'}
    if token.startswith('@'):
        return {'G'}
    if token in ('null', 'undef', 'poison', 'zeroinitializer'):
        return {'K'}
    if token in fn.params:
        return {'A'} if fn.name == ENTRY else {'P'}
    if not token.startswith('%') or token not in fn.defs:
        return {'U'}
    if token in seen:
        return set()
    seen.add(token)
    rhs = fn.defs[token]
    op = re.sub(r'^(?:tail|musttail|notail)\s+', '', rhs).split()[0]
    if op == 'alloca':
        return {'S'}
    if op == 'inttoptr':
        return {'I'}
    if op == 'call':
        return {'C'}
    if op == 'load':
        return {'L'} if re.match(r'load\s+(?:(?:volatile|atomic)\s+)*ptr\b', rhs) else {'U'}
    items = xa.split_top(rhs[len(op):])
    if op == 'getelementptr':
        return roots_of(fn, items[1].split(None, 1)[1], seen) if len(items) > 1 and items[1].startswith('ptr ') else {'U'}
    if op == 'select':
        branches = items[1:3]
        if len(branches) != 2 or not all(item.startswith('ptr ') for item in branches):
            return {'U'}
        return set().union(*(roots_of(fn, item.split(None, 1)[1], seen) for item in branches))
    if op == 'phi':
        incoming = re.findall(r'\[\s*(.+?)\s*,\s*%[\w.]+\s*\]', rhs)
        return set().union(*(roots_of(fn, item, seen) for item in incoming)) if incoming else {'U'}
    return {'U'}


def indexed_gep(fn, token, seen=None):
    """True when the pointer `token` is made, through getelementptr, select or phi, from a base moved by an index that is not a literal."""
    seen = set() if seen is None else seen
    token = (token or '').strip()
    if token in seen or token not in fn.defs:
        return False
    seen.add(token)
    rhs = fn.defs[token]
    op = re.sub(r'^(?:tail|musttail|notail)\s+', '', rhs).split()[0]
    items = xa.split_top(rhs[len(op):])
    if op == 'getelementptr' and len(items) > 1:
        if any(re.search(r'%[\w.]+\s*$', index) for index in items[2:]):
            return True
        return items[1].startswith('ptr ') and indexed_gep(fn, items[1].split(None, 1)[1], seen)
    if op == 'select' and len(items) > 2:
        return any(indexed_gep(fn, item.split(None, 1)[1], seen) for item in items[1:3] if item.startswith('ptr '))
    if op == 'phi':
        return any(indexed_gep(fn, item, seen) for item in re.findall(r'\[\s*(.+?)\s*,\s*%[\w.]+\s*\]', rhs))
    return False


def ir_problems(ir, rows, table_symbol, readable=(), windows=(), indexed_ok=()):
    """(findings, facts) of the IR of a write-table payload whose table has `rows` rows, in the constant `table_symbol`. Every address the payload reads with
    load32 must be a literal inside one of `readable` (blocks that answer whatever the table does: [(base, size)]) or inside one of the table's own read
    `windows`, which the runner opens only once the rows before them are done: a read of anything else could be a read of a block behind a closed gate. A store
    to the payload's own stack through an index that is not a literal is a finding (STORE_INDEXED) in every function but those of `indexed_ok`, the functions the
    policy key `register_offset_stores` names (the line-append helpers): the base of a store is proved, and so a computed offset is not allowed to move it. A pointer
    moved by such an index and handed to a function of the module is a finding in every function (CALL_ARGUMENT_INDEXED), for the callee may store through its parameter
    and its own store would show a plain base."""
    functions, problems = xa.parse_functions(ir)
    findings = [finding('WRITABLE_GLOBAL', p) for p in problems]
    by_name = {fn.name: fn for fn in functions}
    defined = set(by_name)
    facts = {'functions': len(functions), 'stores': 0, 'row_calls': 0, 'open_calls': 0, 'unwind_calls': 0, 'reads': 0, 'indirect_calls': Counter()}
    for fn in functions:
        if fn.inttoptr:
            findings.append(finding('INTTOPTR', f'{fn.name} has {fn.inttoptr} integer-to-pointer conversions'))
        for atomic in fn.atomics:
            findings.append(finding('ATOMIC', f'{fn.name}: {atomic[:60]}'))
        for volatile, atomic, destination, rhs in fn.stores:
            facts['stores'] += 1
            if destination:
                roots = roots_of(fn, destination)
            else:
                # a constant expression `ptr inttoptr (i64 N to ptr)` as the destination is an integer turned into a pointer, which the parser of the xHCI audit does not name
                roots = {'I'} if re.search(r',\s*ptr\s+inttoptr\s*\(', rhs) else {'U'}
            if atomic:
                findings.append(finding('ATOMIC', f'{fn.name} has an atomic store'))
            if not roots <= STORE_ROOTS or not roots:
                code = ('STORE_INTTOPTR' if 'I' in roots else 'STORE_ARGS' if 'A' in roots else 'STORE_LOADED' if 'L' in roots
                        else 'STORE_GLOBAL' if 'G' in roots else 'STORE_UNKNOWN')
                findings.append(finding(code, f'{fn.name} stores through a pointer with root {sorted(roots)}: {rhs[:60]}'))
            elif destination and fn.name not in indexed_ok and indexed_gep(fn, destination):
                findings.append(finding('STORE_INDEXED', f'{fn.name} stores through a pointer moved by an index that is not a literal: {rhs[:60]}'))
        for destination in fn.mem:
            roots = roots_of(fn, destination)
            if not roots <= STORE_ROOTS or not roots:
                code = ('STORE_INTTOPTR' if 'I' in roots else 'STORE_ARGS' if 'A' in roots else 'STORE_LOADED' if 'L' in roots
                        else 'STORE_GLOBAL' if 'G' in roots else 'STORE_UNKNOWN')
                findings.append(finding(code, f'{fn.name} has a memset, memcpy or memmove into a pointer with root {sorted(roots)}'))
            elif fn.name not in indexed_ok and indexed_gep(fn, destination):
                findings.append(finding('STORE_INDEXED', f'{fn.name} has a memset, memcpy or memmove through a pointer moved by an index that is not a literal'))
    row_values = Counter()
    for where, callee, args in parse_calls(ir):
        fn = by_name[where]
        if callee == 'asm':
            findings.append(finding('INLINE_ASM', f'{where} has inline assembly'))
            continue
        pointers = [token for kind, token in args if kind == 'ptr']
        if callee.startswith('@'):
            name = callee[1:]
            if name not in defined and not name.startswith('llvm.'):
                findings.append(finding('CALL_UNDEFINED', f'{where} calls {name}, which the module does not define'))
            for token in pointers:
                roots = roots_of(fn, token)
                if not roots or not roots <= DIRECT_ARGUMENT_ROOTS:
                    findings.append(finding('CALL_ARGUMENT_ROOT', f'{where} hands {name} a pointer with root {sorted(roots)}'))
                elif not name.startswith('llvm.') and indexed_gep(fn, token):
                    findings.append(finding('CALL_ARGUMENT_INDEXED', f'{where} hands {name} a pointer moved by an index that is not a literal'))
            continue
        op = callee_op(fn, callee)
        facts['indirect_calls'][op] += 1
        if op is None:
            findings.append(finding('CALL_TARGET_UNKNOWN', f'{where} calls through {callee}, which is not loaded from an ops table of the arguments'))
            continue
        if op == 'open':
            facts['open_calls'] += 1
            if len(args) != 1 or args[0][1] != '@' + table_symbol:
                findings.append(finding('OPEN_ARGUMENT', f'{where} opens {args}, not @{table_symbol}'))
        elif op == 'row':
            facts['row_calls'] += 1
            if len(args) != 1 or args[0][0] != 'i32':
                findings.append(finding('ROW_ARITY', f'{where} calls row with {args}'))
                continue
            values = constants(fn, args[0][1])
            if values is None:
                findings.append(finding('ROW_INDEX_NOT_CONSTANT', f'{where} asks for row {args[0][1]}, which is not made of literals'))
                continue
            for value in sorted(values):
                row_values[value] += 1
                if not 0 <= value < rows:
                    findings.append(finding('ROW_INDEX_RANGE', f'{where} asks for row {value} of a table of {rows}'))
        elif op == 'unwind':
            facts['unwind_calls'] += 1
            if args:
                findings.append(finding('ROW_ARITY', f'{where} calls unwind with {args}'))
        else:
            for token in pointers:
                roots = roots_of(fn, token)
                if not roots or not roots <= OP_ARGUMENT_ROOTS[op]:
                    findings.append(finding('CALL_ARGUMENT_ROOT', f'{where} hands {op} a pointer with root {sorted(roots)}'))
            if op == 'load32':
                facts['reads'] += 1
                addresses = constants(fn, args[0][1]) if args and args[0][0] == 'i64' else None
                if addresses is None:
                    findings.append(finding('READ_ADDRESS_NOT_CONSTANT', f'{where} reads an address that is not a literal'))
                    continue
                for value in sorted(addresses):
                    if not any(base <= value < base + size for base, size in tuple(readable) + tuple(windows)):
                        findings.append(finding('READ_NOT_GATED', f'{where} reads {value:#x}, which is in no readable block and in no window of the table'))
    if facts['open_calls'] != 1:
        findings.append(finding('OPEN_COUNT', f'{facts["open_calls"]} calls of open'))
    missing = [i for i in range(rows) if row_values[i] != 1]
    if missing:
        findings.append(finding('ROW_COVERAGE', f'rows {missing} are asked for {[row_values[i] for i in missing]} times, not once'))
    facts['rows_asked'] = dict(sorted(row_values.items()))
    return findings, facts


# ---- The binary ------------------------------------------------------------------------------------------------------------------

def w0_literal(items, call_index, targets, branches):
    """The literal in w0 at the `blr` items[call_index]: the straight-line mov of the smc machinery (tools/sp11_payload_testlib.py), or 0 when the code that
    leads to the call is a run that neither names w0 nor transfers control and every way into it has w0 zero: falling through a `cbnz w0, ...`, a
    `cbz w0, <its first instruction>`, or no fall-through at all (after an unconditional branch). The compiler reuses w0 like that after a successful open.
    `branches` is {target: [(mnemonic, first operand)]} of every direct branch of the code; anything else is None."""
    value = lib._w0_before(items, call_index, targets)
    if value is not None:
        return value
    start = call_index
    while start > 0:
        address_, mnemonic, operands = items[start - 1]
        if mnemonic == '<label>' or lib._ANY_TRANSFER.match(mnemonic) or re.search(r'\b[wx]0\b', operands):
            break
        start -= 1
    if any(start < index <= call_index and items[index][0] in branches for index in range(start, call_index + 1)):
        return None
    if start == 0:
        return None
    before = items[start - 1]
    first_operand = before[2].split(',')[0].strip()
    falls_through = not re.match(r'^(b|br|ret|retaa|retab|eret)$', before[1])
    if falls_through and not (before[1] == 'cbnz' and first_operand == 'w0'):
        return None
    if any(not (kind == 'cbz' and register == 'w0') for kind, register in branches.get(items[start][0], [])):
        return None
    return 0


def binary_call_problems(disassembly, rows):
    """Findings of the disassembly of a write-table payload (llvm-objdump -d): the classes of the registers of every `blr` from tools/sp11_payload_memcheck.py
    (`ops=True`) and, for each `row` call, the literal in w0 before it (the machinery of the smc function ids, tools/sp11_payload_testlib.py)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('sp11_payload_memcheck', Path(__file__).with_name('sp11_payload_memcheck.py'))
    memcheck = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(memcheck)
    calls = []
    problems, _, _ = memcheck.analyse(disassembly, ops=True, calls=calls)
    findings = []
    items = lib._addressed_instructions(disassembly)
    index_of = {address_: i for i, (address_, _, _) in enumerate(items)}
    targets, branches = set(), {}
    for _, mnemonic, operands in items:
        if lib._DIRECT_BRANCH.match(mnemonic):
            found = re.search(r'\b0x([0-9a-f]+)\b', operands)
            if found:
                targets.add(int(found.group(1), 16))
                branches.setdefault(int(found.group(1), 16), []).append((mnemonic, operands.split(',')[0].strip()))
    allowed = {'f:puts', 'f:hex', 'f:load32', 'f:counter', 'f:open', 'f:row', 'f:unwind'}
    values, opens = Counter(), 0
    for function, where, register, klass in calls:
        if klass not in allowed:
            findings.append(finding('BIN_INDIRECT_CALL', f'the blr {register} in {function} at {where:#x} has class {klass}'))
            continue
        if klass == 'f:open':
            opens += 1
        if klass == 'f:row':
            value = w0_literal(items, index_of[where], targets, branches)
            if value is None:
                findings.append(finding('BIN_ROW_INDEX', f'the literal in w0 before the row call at {where:#x} cannot be read'))
            else:
                values[value] += 1
    if opens != 1:
        findings.append(finding('BIN_OPEN_COUNT', f'{opens} calls of open'))
    missing = [i for i in range(rows) if values[i] != 1]
    extra = sorted(set(values) - set(range(rows)))
    if missing or extra:
        findings.append(finding('BIN_ROW_COVERAGE', f'rows {missing} are not asked for exactly once, rows {extra} are outside the table'))
    return findings


# ---- The table in the ELF -------------------------------------------------------------------------------------------------------

def table_symbol(elf, nm='llvm-nm'):
    """(name, address, size) of the one `wtab_*` constant of the ELF, or None."""
    done = lib.run([shutil.which(nm, path=lib.ENV['PATH']) or nm, '-S', '--defined-only', str(elf)])
    found = []
    for line in done.stdout.splitlines():
        match = re.match(r'([0-9a-f]+)\s+([0-9a-f]+)\s+\w\s+(wtab_\w+)$', line.strip())
        if match:
            found.append((match.group(3), int(match.group(1), 16), int(match.group(2), 16)))
    return found[0] if len(found) == 1 else None


def table_problems(elf, flat, approved_sha256=None):
    """(findings, info): the table the payload carries, decoded by the runner's own rules, and its digest against the approval's."""
    symbol = table_symbol(elf)
    if not symbol:
        return [finding('TABLE_MISSING', 'the ELF has no single wtab_* symbol')], {}
    name, where, size = symbol
    data = Path(flat).read_bytes()
    blob = data[where:where + size]
    findings = []
    # The runner is handed an address of the payload's image and validates what it finds there: a second table in the image, a constant of another name or one inside the
    # first, is a table the symbol-based approval does not cover.
    magic_count = data.count(wtab.MAGIC.to_bytes(8, 'little'))
    if magic_count != 1:
        findings.append(finding('TABLE_COUNT', f'the flat binary holds the table magic {magic_count} times, not once'))
    reason, index = wtab.validate_blob(blob, allow_draft=True)      # a draft is a finding of its own (TABLE_DRAFT, below), which a policy may allow for the host model
    info = {'symbol': name, 'address': where, 'size': size, 'rows': None, 'sha256': hashlib.sha256(blob).hexdigest()}
    if reason != 'OK':
        findings.append(finding('TABLE_REFUSED', f'{reason}' + ('' if index is None else f' at {index}')))
    else:
        info['rows'] = wtab.HEADER.unpack_from(blob)[3]
        info['windows'] = [wtab.WINDOW.unpack_from(blob, wtab.HEADER.size + wtab.ROW.size * info['rows'] + k * wtab.WINDOW.size)[:2]
                           for k in range(wtab.HEADER.unpack_from(blob)[4])]
        if wtab.HEADER.unpack_from(blob)[-1].rstrip(b'\0').endswith(b'-DRAFT'):
            findings.append(finding('TABLE_DRAFT', 'the table is a draft: some of its expectations were never observed, and no approval note can be made for it'))
    if approved_sha256 and info['sha256'] != approved_sha256:
        findings.append(finding('TABLE_SHA', f'the binary carries {info["sha256"]}, the approval names {approved_sha256}'))
    return findings, info


def audit(source, out_dir, extra_flags=(), approved_sha256=None, root=ROOT, readable=(), register_offset_stores=None):
    """Everything above for one payload source: builds the IR, the object, the ELF and the flat binary; returns (findings, facts). The policy
    key `write_table` of tools/sp11_payload_testlib.py runs the binary half on the finished ELF; this is the whole of it for the tests. `readable` are
    the blocks the payload may read whatever the table does (see ir_problems); `register_offset_stores` is the policy key of that name, whose functions
    may store to their own stack through a computed index (ir_problems, `indexed_ok`)."""
    root, out_dir = Path(root).resolve(), Path(out_dir)
    done, elf, flat = lib.build_payload(source, out_dir, extra_cflags=list(extra_flags), root=root)
    if done.returncode:
        return [finding('BUILD', (done.stderr or done.stdout)[-400:])], {}
    findings, info = table_problems(elf, flat, approved_sha256)
    facts = {'table': info}
    if info and info.get('rows') is None:
        return findings, facts
    # Without any table constant the IR is still audited, against a table of no rows: what the payload opens cannot be a constant of its image, and that is the finding.
    ir = build_ir(source, out_dir, root, extra_flags)
    ir_found, ir_facts = ir_problems(ir, info.get('rows', 0), info.get('symbol', ''), readable, info.get('windows', ()), set(register_offset_stores or ()))
    dis = lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout
    return findings + ir_found + binary_call_problems(dis, info.get('rows', 0)), dict(facts, ir=ir_facts, elf=str(elf), flat=str(flat))
