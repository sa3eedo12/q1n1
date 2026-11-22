# SPDX-License-Identifier: MIT
"""Where the loads and stores of a payload binary can point, read from its disassembly (docs/SP11-PAYLOAD-EL2MEM.md).

    python3 tools/sp11_payload_memcheck.py [--objdump llvm-objdump] build/uefi/payloads/el2mem.elf

The allow-list of tools/sp11_payload_testlib.py says which instructions a payload may hold; this says what its memory accesses may
reach. It is switched on by two optional policy keys and costs nothing to a policy without them:

  `read_only`   every store has a base register that is provably the payload's own stack, and every load a base that is provably
                the stack, the payload's own image, the arguments structure or a pointer the arguments hold (the final memory map
                and the preload table are read through such a pointer). A load through any other base is a violation unless
                the policy also says
  `bulk_reads`  loads may use any base: the payload reads memory it was told about (a loaded file) in place.

How "provably": every general register carries one provenance class, joined at control-flow merges, and followed through calls: a
function's entry state is the join of the states at its call sites, kept only for the argument and callee-saved registers, and a call
leaves the callee-saved registers alone and makes every other one OTHER. _start is entered with x0 = the arguments, as the runner
enters it. The classes:

  STACK   sp, and add/sub/mov of a STACK value. Where the offset from the function's entry sp is known it is kept (an integer), so that
          the 64-bit slots the compiler spills registers to are followed: a register stored to a known stack slot and loaded back has
          the class it had; a store to a stack address of unknown offset forgets every slot. The check proves the base of an access,
          never its offset: the host tests bound the offsets
  CALLER  a stack pointer a caller passed in, or derived from one: an address above this function's own frame, so a store through
          it cannot reach this function's spill slots, which a store through STACK of unknown offset might
  IMAGE   adrp/adr results and a literal load's address: a pointer into the payload's own image
  ARGS    the arguments pointer
  ARGS1   a 64-bit value loaded through an ARGS base (map_base, preload_table, an op); a value loaded through anything else is OTHER
  READABLE the join of two different classes among STACK, CALLER, IMAGE, ARGS and ARGS1: memory the payload may read through (a
          string may be on the stack or in the image) and never stores through
  STACKX  (only for a policy with the key `register_offset_stores`) the result of add/sub of a stack pointer and a register that is not a
          pointer, and sp itself after `add/sub sp, sp, xN`: readable like a pointer into the stack, never a base a store may use, and kept
          through a call, so a callee that stores through it is refused as well

A conservative check: it may refuse a safe binary (the source is then written differently), it must never pass an unsafe one, with
two assumptions it states: a callee does not overwrite the caller's spill slots (it writes only where the caller pointed it), and the
runner's ops, which are outside the binary, are trusted by ABI. A pointer made from a STACK value by other arithmetic (and, orr,
shifts) is OTHER, so refused. The check proves the base of a store, not its offset: the optional policy key `register_offset_stores` pins the exact
{function: count} of the stores whose address has a register offset (register_offset_stores below) and, because the offset of such a store is
a number the program computes, also makes a stack pointer moved by a register (STACKX) unusable as the base of a store. Hardware: NOT RUN."""
import re
import subprocess
import sys

STACK, CALLER, IMAGE, READABLE, ARGS, ARGS1, OTHER = 'S', 'C', 'P', 'R', 'A', 'B', 'X'
STACKX = 'Y'
STACKISH = {STACK, CALLER}
POINTERS = {STACK, CALLER, IMAGE, READABLE, ARGS, ARGS1, STACKX}
# `analyse(..., ops=True)` (the write-table policy, tools/sp11_payload_wtab_audit.py) also names where a function pointer was loaded from: a 64-bit
# load at a known offset of the arguments gives the op of the payload ABI (offsets 120 to 144) or the pointer to the write table's ops (152, class
# WOPS), and a load at a known offset of that gives one of its three ops. The tags are only ever created when `ops` is set, so every other
# policy is analysed as it always was.
WOPS = 'W'
ARGS_TAGS = {120: 'f:puts', 128: 'f:hex', 136: 'f:load32', 144: 'f:counter', 152: WOPS}
WOPS_TAGS = {16: 'f:open', 24: 'f:row', 32: 'f:unwind'}
POINTERS = POINTERS | {WOPS}
CALLEE_SAVED = list(range(19, 30))
ARGUMENT_REGISTERS = list(range(0, 8))
CALL_CLOBBERED = list(range(0, 19)) + [30]
NO_DESTINATION = {'cmp', 'cmn', 'tst', 'ccmp', 'ccmn', 'b', 'br', 'bl', 'blr', 'ret', 'cbz', 'cbnz', 'tbz', 'tbnz', 'nop', 'hint',
                  'isb', 'dsb', 'dmb', 'at', 'sys', 'msr', 'bti', 'smc', 'hvc', 'svc', 'eret', 'wfe', 'wfi', 'sev', 'sevl',
                  'yield', 'prfm', 'prfum', 'dc', 'ic', 'tlbi'}
REGISTER = re.compile(r'^([xw])(\d+)$')
INSTRUCTION = re.compile(r'^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$')
LABEL = re.compile(r'^([0-9a-f]+) <(.+)>:\s*$')
TARGET = re.compile(r'\b0x([0-9a-f]+)\b')
CONDITIONAL = re.compile(r'^b\.[a-z]{2}$')
MESSAGES_MAX = 12
REGISTER_BYTES = {'x': 8, 'w': 4, 'q': 16, 'd': 8, 's': 4, 'h': 2, 'b': 1, 'v': 16}


class State:
    """The 31 general registers (a class string, or an int for a stack pointer whose offset from the entry sp is known), the
    offset of sp (None when unknown, STACKX when a register moved it under the key `register_offset_stores`) and the 64-bit stack slots whose content is known ({offset: value})."""
    __slots__ = ('regs', 'sp', 'slots')

    def __init__(self, regs, sp=0, slots=None):
        self.regs, self.sp, self.slots = regs, sp, {} if slots is None else slots

    def copy(self):
        return State(list(self.regs), self.sp, dict(self.slots))

    def __eq__(self, other):
        return (self.regs, self.sp, self.slots) == (other.regs, other.sp, other.slots)


def cls(value):
    return STACK if isinstance(value, int) else value


def join_value(a, b):
    if a == b:
        return a
    ca, cb = cls(a), cls(b)
    if ca == cb:
        return ca
    if {ca, cb} <= STACKISH:
        return STACK
    return READABLE if {ca, cb} <= POINTERS else OTHER


def join_state(a, b):
    slots = {k: join_value(v, b.slots[k]) for k, v in a.slots.items() if k in b.slots}
    return State([join_value(x, y) for x, y in zip(a.regs, b.regs)], a.sp if a.sp == b.sp else STACKX if STACKX in (a.sp, b.sp) else None, slots)


def split_operands(text):
    """Operands at the top level: the commas inside [...] do not split."""
    out, depth, current = [], 0, ''
    for char in text.split('//')[0].strip():
        depth += char == '['
        depth -= char == ']'
        if char == ',' and depth == 0:
            out.append(current.strip())
            current = ''
        else:
            current += char
    if current.strip():
        out.append(current.strip())
    return out


def functions(text):
    """{name: (start address, [(address, mnemonic, operands as a list, operand text)])} in disassembly order."""
    found, current = {}, None
    for line in text.splitlines():
        label = LABEL.match(line)
        if label:
            current = label.group(2)
            found[current] = (int(label.group(1), 16), [])
            continue
        instruction = INSTRUCTION.match(line)
        if instruction and current:
            operands = instruction.group(3).split('//')[0].strip()
            found[current][1].append((int(instruction.group(1), 16), instruction.group(2).lower(), split_operands(operands), operands))
    return found


def register_index(name):
    match = REGISTER.match(name)
    return int(match.group(2)) if match and int(match.group(2)) < 31 else None


def is_register(name):
    return name in ('sp', 'wsp') or register_index(name) is not None


def get(state, name):
    """The value of a register operand: an int offset or a class string."""
    if name == 'sp':
        return STACK if state.sp is None else state.sp
    index = register_index(name)
    return state.regs[index] if index is not None and name[0] == 'x' else OTHER


def put(state, name, value):
    if name == 'sp':
        state.sp = value if isinstance(value, int) or value == STACKX else None
        return
    index = register_index(name)
    if index is not None:
        state.regs[index] = value


def immediate(text, shift=None):
    """The value of an immediate operand ('#0x70', '#-16', with an optional 'lsl #12' operand), or None."""
    if not text.startswith('#'):
        return None
    try:
        value = int(text[1:], 0)
        if shift:
            match = re.match(r'lsl\s+#(\d+)$', shift)
            value = value << int(match.group(1)) if match else None
        return value
    except ValueError:
        return None


def offset_value(value, delta):
    """A pointer value moved by a known immediate: the offset follows, a class stays."""
    return value + delta if isinstance(value, int) else value


def parse_memory(operands):
    """(index of the memory operand, base register, immediate offset or None when indexed by a register, pre-indexed, post-index
    immediate or None) of an instruction with a [..] operand, else None."""
    for index, operand in enumerate(operands):
        if not operand.startswith('['):
            continue
        parts = [part.strip() for part in operand[1:operand.index(']')].split(',')]
        base, second = parts[0], parts[1] if len(parts) > 1 else None
        offset = 0 if second is None else immediate(second)
        post = immediate(operands[index + 1]) if index + 1 < len(operands) else None
        return index, base, offset, operand.endswith('!'), post, index + 1 < len(operands)
    return None


def access_bytes(mnemonic, register):
    if mnemonic.endswith('b'):
        return 1
    if mnemonic.endswith('h'):
        return 2
    return REGISTER_BYTES.get(register[:1], 0)


def destinations(mnemonic, operands):
    if mnemonic in NO_DESTINATION or mnemonic.startswith('st') or CONDITIONAL.match(mnemonic) or not operands:
        return []
    return operands[:2] if mnemonic in ('ldp', 'ldpsw', 'ldnp') else operands[:1]


def address_of(state, memory):
    """The address value of a memory operand: an int when the stack offset is known, else a class string."""
    _, base, offset, _, _, _ = memory
    value = get(state, base)
    if offset is None:
        return cls(value)
    return offset_value(value, offset)


def write_back(state, memory, old):
    _, base, offset, pre, post, post_register = memory
    if pre:
        put(state, base, offset_value(get(old, base), offset or 0))
    elif post is not None:
        put(state, base, offset_value(get(old, base), post))
    elif post_register:
        put(state, base, cls(get(old, base)))


def step_store(new, old, mnemonic, operands, memory):
    base_value = get(old, memory[1])
    if cls(base_value) == STACK:
        registers = [name for name in operands[:memory[0]] if is_register(name) or name[:1] in REGISTER_BYTES]
        size = access_bytes(mnemonic, registers[0]) if registers else 0
        address = address_of(old, memory)
        if isinstance(address, int) and size:
            total = size * len(registers)
            for key in [k for k in new.slots if k < address + total and k + 8 > address]:
                del new.slots[key]
            if size == 8 and mnemonic in ('str', 'stur', 'stp'):
                for position, name in enumerate(registers):
                    if name[0] == 'x' and is_register(name):
                        new.slots[address + 8 * position] = get(old, name)
        else:
            new.slots.clear()
    write_back(new, memory, old)


def step_load(new, old, mnemonic, operands, memory):
    base_class = cls(get(old, memory[1]))
    address = address_of(old, memory)
    for position, name in enumerate(destinations(mnemonic, operands)):
        index = register_index(name)
        if index is None:
            continue
        value = OTHER
        if name[0] == 'x' and mnemonic in ('ldr', 'ldur', 'ldp', 'ldnp'):
            if base_class == STACK and isinstance(address, int) and address + 8 * position in old.slots:
                value = old.slots[address + 8 * position]
            elif base_class == ARGS:
                value = ARGS1
                if _tag_ops and mnemonic in ('ldr', 'ldur') and memory[2] in ARGS_TAGS:
                    value = ARGS_TAGS[memory[2]]
            elif _tag_ops and base_class == WOPS and mnemonic in ('ldr', 'ldur') and memory[2] in WOPS_TAGS:
                value = WOPS_TAGS[memory[2]]
        new.regs[index] = value
    if memory[3] or memory[4] is not None or memory[5]:
        write_back(new, memory, old)


_tag_ops = False
_strict_stack = False


def moved_by_register(klass):
    """The class of a pointer that a register was added to: only a policy that asked for it (`strict_stack`) loses the right to store through
    a stack pointer moved this way, because an address that an earlier add moved by a run-time number looks like any other [xN] at the store."""
    return STACKX if _strict_stack and klass in STACKISH else klass


def step_other(new, old, mnemonic, operands):
    if operands and operands[0] in ('sp', 'wsp') and mnemonic not in NO_DESTINATION:
        value = OTHER
        if operands[0] == 'sp' and len(operands) >= 2:
            source = get(old, operands[1])
            if mnemonic == 'mov':
                value = source
            elif mnemonic in ('add', 'sub') and len(operands) >= 3:
                delta = immediate(operands[2], operands[3] if len(operands) > 3 else None)
                value = offset_value(source, delta if mnemonic == 'add' else -delta) if delta is not None else moved_by_register(cls(source))
        put(new, 'sp', value)
        return
    for name in destinations(mnemonic, operands):
        index = register_index(name)
        if index is None:
            continue
        wide, result = name[0] == 'x', OTHER
        if mnemonic in ('adrp', 'adr'):
            result = IMAGE if wide else OTHER
        elif mnemonic == 'mov' and wide and len(operands) == 2 and is_register(operands[1]):
            result = get(old, operands[1])
        elif mnemonic in ('add', 'sub', 'adds', 'subs') and wide and len(operands) >= 3 and is_register(operands[1]):
            first = get(old, operands[1])
            delta = immediate(operands[2], operands[3] if len(operands) > 3 else None)
            if delta is not None:
                result = offset_value(first, delta if mnemonic.startswith('add') else -delta)
            else:
                second = get(old, operands[2]) if is_register(operands[2]) else OTHER
                if cls(first) in POINTERS and cls(second) not in POINTERS:
                    result = moved_by_register(cls(first))
                elif cls(second) in POINTERS and cls(first) not in POINTERS and mnemonic.startswith('add'):
                    result = moved_by_register(cls(second))
        elif mnemonic == 'madd' and wide and len(operands) == 4 and is_register(operands[3]):
            result = moved_by_register(cls(get(old, operands[3]))) if cls(get(old, operands[3])) in POINTERS else OTHER
        elif mnemonic == 'csel' and wide and len(operands) == 4:
            first, second = get(old, operands[1]), get(old, operands[2])
            result = join_value(first, second) if cls(first) in POINTERS and cls(second) in POINTERS else OTHER
        new.regs[index] = result


def transfer(state, mnemonic, operands):
    """The state after one instruction (a new State); calls are handled by the caller."""
    new = state.copy()
    memory = parse_memory(operands)
    if mnemonic.startswith('st') and memory:
        step_store(new, state, mnemonic, operands, memory)
    elif mnemonic.startswith('ld') and memory:
        step_load(new, state, mnemonic, operands, memory)
    else:
        step_other(new, state, mnemonic, operands)
    return new


def call_entry(state):
    """What a callee starts with: the argument and callee-saved registers, with every stack pointer now a pointer above its frame."""
    regs = [OTHER] * 31
    for index in ARGUMENT_REGISTERS + CALLEE_SAVED:
        value = cls(state.regs[index])
        regs[index] = CALLER if value in STACKISH else value
    return State(regs)


def after_call(state):
    new = state.copy()
    for index in CALL_CLOBBERED:
        new.regs[index] = OTHER
    return new


def branch_target(operands):
    found = TARGET.search(operands[-1]) if operands else None
    return int(found.group(1), 16) if found else None


def run_function(instructions, entry, span, by_start, entries):
    """The state before each reachable instruction of one function; joins the call sites into `entries` and returns whether any
    callee's entry state changed."""
    start, end = span
    index = {instruction[0]: position for position, instruction in enumerate(instructions)}
    states, work, grown = {0: entry}, [0], False
    while work:
        position = work.pop()
        state = states[position]
        _, mnemonic, operands, _ = instructions[position]
        target = branch_target(operands)
        inside = target is not None and start <= target < end
        branch = mnemonic in ('b', 'cbz', 'cbnz', 'tbz', 'tbnz') or CONDITIONAL.match(mnemonic)
        fall, flows = mnemonic not in ('ret', 'br', 'b'), []
        if branch and inside:
            flows = [target]
        after = after_call(state) if mnemonic in ('bl', 'blr', 'smc') else transfer(state, mnemonic, operands)
        if (mnemonic == 'bl' or (branch and not inside)) and target in by_start:
            callee = by_start[target]
            merged = call_entry(state) if callee not in entries else join_state(entries[callee], call_entry(state))
            if callee not in entries or merged != entries[callee]:
                entries[callee] = merged
                grown = True
        for nxt in ([position + 1] if fall and position + 1 < len(instructions) else []) + [index[t] for t in flows if t in index]:
            merged = after if nxt not in states else join_state(states[nxt], after)
            if nxt not in states or merged != states[nxt]:
                states[nxt] = merged
                work.append(nxt)
    return states, grown


def analyse(text, root='_start', ops=False, calls=None, strict_stack=False):
    """(problems, loads, stores): loads and stores are lists of (function, address, mnemonic, operand text, base, class). With `ops`, a function
    pointer loaded from the arguments' ops table or from the write table's (see ARGS_TAGS) carries the name of its op as its class, and when `calls`
    is a list every `blr` of the code reached is appended to it as (function, address, register, class of the register). With `strict_stack` a
    stack pointer moved by a register is STACKX, which no store may use as its base."""
    global _tag_ops, _strict_stack
    _tag_ops, _strict_stack = ops, strict_stack
    try:
        return _analyse(text, root, calls)
    finally:
        _tag_ops = _strict_stack = False


def _analyse(text, root, calls):
    table = functions(text)
    if root not in table:
        return [f'the disassembly has no {root}'], [], []
    ordered = sorted((start, name) for name, (start, _) in table.items())
    spans = {name: (start, ordered[rank + 1][0] if rank + 1 < len(ordered) else start + 4 * len(table[name][1]) + 4)
             for rank, (start, name) in enumerate(ordered)}
    by_start = {start: name for start, name in ordered}
    first = State([OTHER] * 31)
    first.regs[0] = ARGS
    entries = {root: first}
    states = {}
    while True:
        grown = False
        for _, name in ordered:
            if name in entries and table[name][1]:
                states[name], more = run_function(table[name][1], entries[name], spans[name], by_start, entries)
                grown = grown or more
        unreached = [name for _, name in ordered if name not in entries]
        for name in unreached:
            entries[name] = State([OTHER] * 31)
        if not grown and not unreached:
            break
    problems, loads, stores = [], [], []
    for name, reached in states.items():
        start, end = spans[name]
        for position, (address, mnemonic, operands, text_) in enumerate(table[name][1]):
            if position not in reached:
                continue
            state = reached[position]
            target = branch_target(operands)
            direct = mnemonic in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') or CONDITIONAL.match(mnemonic)
            if mnemonic == 'br':
                problems.append(f'an indirect branch (br) in {name} at {address:#x}')
            elif direct and not (target is not None and start <= target < end) and target not in by_start:
                problems.append(f'a branch in {name} at {address:#x} to {target if target is None else hex(target)}, which is not '
                                'the start of a function of the binary')
            if operands and operands[0] in ('sp', 'wsp') and mnemonic not in NO_DESTINATION and not mnemonic.startswith('st'):
                from_sp = mnemonic in ('add', 'sub') and len(operands) >= 2 and operands[1] == 'sp'
                from_stack = mnemonic in ('add', 'sub', 'mov') and len(operands) >= 2 and cls(get(state, operands[1])) in STACKISH
                if operands[0] != 'sp' or not (from_sp or from_stack):
                    problems.append(f'sp is set in {name} at {address:#x} ({mnemonic} {text_}) from something that is not the stack')
            memory = parse_memory(operands)
            if calls is not None and mnemonic == 'blr':
                calls.append((name, address, operands[0] if operands else '', cls(get(state, operands[0])) if operands else OTHER))
            if mnemonic.startswith('st') and memory:
                stores.append((name, address, mnemonic, text_, memory[1], cls(get(state, memory[1]))))
            elif mnemonic.startswith('ld'):
                loads.append((name, address, mnemonic, text_, memory[1] if memory else None,
                              cls(get(state, memory[1])) if memory else IMAGE))
    return problems, loads, stores


def memory_violations(text, policy):
    """Sentences for everything the policy's memory keys refuse; empty when clean, and for a policy with neither key."""
    if not (policy.get('read_only') or policy.get('bulk_reads')):
        return []
    found = []
    if policy.get('bulk_reads') and not policy.get('read_only'):
        found.append('the policy has bulk_reads without read_only')
    problems, loads, stores = analyse(text, strict_stack=policy.get('register_offset_stores') is not None)
    found += problems
    for name, address, mnemonic, operands, base, klass in stores:
        if klass not in STACKISH:
            found.append(f'a store in {name} at {address:#x} ({mnemonic} {operands}) whose base {base} is not provably the payload\'s own stack')
    if not policy.get('bulk_reads'):
        for name, address, mnemonic, operands, base, klass in loads:
            if klass not in POINTERS:
                found.append(f'a load in {name} at {address:#x} ({mnemonic} {operands}) whose base {base} is not provably the stack, the '
                             'image, the arguments or a pointer read from them (the policy has no bulk_reads)')
    if len(found) > MESSAGES_MAX:
        found = found[:MESSAGES_MAX] + [f'{len(found) - MESSAGES_MAX} more']
    return found


def register_offset_stores(text):
    """{function: count} of the stores whose address is a base plus a register ([Xn, Xm], [Xn, Wm, uxtw], [Xn, Xm, lsl #k]) in every function of the disassembly.
    The check above proves the base of a store, never its offset. A policy that names the exact map (policy key `register_offset_stores`) knows every
    store whose own addressing mode adds a register; an offset an earlier add folded into the base register is not seen here, and the same key makes
    memory_violations refuse the base of such a store (STACKX), also in a callee that stores through its pointer parameter."""
    found = {}
    for name, (_, instructions) in functions(text).items():
        for _, mnemonic, operands, _ in instructions:
            if not mnemonic.startswith('st'):
                continue
            memory = parse_memory(operands)
            if memory and memory[2] is None:
                found[name] = found.get(name, 0) + 1
    return found


def main(argv=None):
    arguments = list(argv if argv is not None else sys.argv[1:])
    objdump = 'llvm-objdump'
    if arguments[:1] == ['--objdump']:
        objdump, arguments = arguments[1], arguments[2:]
    if len(arguments) != 1:
        print(__doc__.split('\n\n')[0], file=sys.stderr)
        return 2
    done = subprocess.run([objdump, '-d', '--no-show-raw-insn', arguments[0]], capture_output=True, text=True)
    if done.returncode:
        print(done.stderr, file=sys.stderr)
        return 2
    problems, loads, stores = analyse(done.stdout)
    print(f'{len(loads)} loads, {len(stores)} stores, {len(problems)} problems')
    for report in (stores, loads):
        counts = {}
        for item in report:
            counts[item[5]] = counts.get(item[5], 0) + 1
        print(dict(sorted(counts.items())))
    for problem in problems:
        print(problem)
    return 0


if __name__ == '__main__':
    sys.exit(main())
