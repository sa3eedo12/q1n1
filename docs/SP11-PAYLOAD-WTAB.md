<!-- SPDX-License-Identifier: MIT -->
# The write table: the one way a stick payload may change a device register

`platform/uefi/sp11-payload-wtab{,-abi}.{c,h}`, `tools/sp11_wtab.py` and `tools/sp11_payload_wtab_audit.py` are an opt-in extension of the stick payload runner described in
[SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest, the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the
[line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not repeated. Every payload so far is read only: `tools/sp11_payload_memcheck.py` checks from the
disassembly that the base of each of its stores is its own stack. Boot 29 (the keyboard-link and touch engines' clocks are off) and boot 30 (the Adreno X1-85's CX power domain and its
clocks are off) both need register **writes** to be examined further. This document is the framework that has to exist before any payload writes a device word, and the
first use of it ([GPU stage S1](#first-use-gpus1-and-gpus1d)). Evidence labels as there: VERIFIED, OBSERVED, INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN.
**EXPERIMENTAL; hardware NOT RUN: nothing of this has run on the unit, the host model is this tree's own statement of what a domain and a clock do, and this document
authorises no run.** Each run that writes needs the operator's approval of [its note](#the-approval-note).

The gate is `Q1N1_SP11_WTAB` (default 0, `make WTAB=1` on top of `PAYLOAD=1`). With it at 0 the new runner file compiles to nothing, every other file preprocesses to the
text it had before, and the runner is the pinned runner ([Building it](#building-it)).

## The rule

A payload stores **nowhere but its own stack** (`read_only`, unchanged). A payload that must change a device word carries a **table** in its read-only data, and the runner,
not the payload, does everything that touches the device:

```
rc = wtab->open(&table);      // once; the table is a constant of the payload's own image
rc = wtab->row(k);            // k is a literal of the payload's code: the next row, in table order
rc = wtab->unwind();          // optional; the runner undoes whatever is still in force when the payload returns
```

The payload cannot name an address or a value through these three ops, so the table, whose SHA-256 the operator quotes, is the whole of what **the runner** will write for it. The ops of
the payload ABI take pointers of the payload's choosing, though: `hex` writes into a buffer it names, `puts` reads a string it names and `load32` writes its answer where `out` says. A runner
with the table refuses a `hex` whose destination is not inside the payload's stack and a `puts` whose string is not in the stack or in the payload's image when the code runs, as `load32`
always refused an `out` outside the stack; no tool sees this (see the last row below). What the payload's own stores could reach is another question, and the tools only **lint** it: they check that the **base** of every store of the payload is its own stack, that no store shows a
register offset or a computed index outside the functions the policy names, that a pointer moved by a computed index is not handed to another function, and that a stack pointer moved by a
register is not the base of a store; they do not prove that a payload cannot write a device word. What keeps a device store out of a payload is that its bytes are reviewed and pinned
by the SHA-256 of the manifest ([SP11-PAYLOAD.md](SP11-PAYLOAD.md)); these checks catch the accident. Five things are checked, the last by the runner and not by the tools:

| What is checked | By what | Refused with |
|---|---|---|
| the base of every store of the payload's code is its own stack (stack stores allowed), no store of the code shows, in its own function, an index that is not a literal (a register offset, or a getelementptr with a computed index), except in the functions the policy names, a pointer moved by such an index is not handed to a function of the payload, and a stack pointer moved by a register is not the base of a store, in a callee either | `read_only`: `tools/sp11_payload_memcheck.py` on the disassembly; the policy key `register_offset_stores` (the exact `{function: count}` map of the stores whose addressing mode has a register offset, compared for equality, and, with the key, the class `STACKX` of a stack pointer an `add` moved by a register, which no store may use as its base); the IR audit `tools/sp11_payload_wtab_audit.py` on the IR (every store's pointer is rooted in an `alloca`, a `select` or a `phi` counts every operand and an operand it cannot read is unknown, an index off such a root must be a literal outside the named functions, and no function is handed a pointer moved by a computed index) | `STORE_INTTOPTR`, `STORE_ARGS`, `STORE_LOADED`, `STORE_GLOBAL`, `STORE_UNKNOWN`, `STORE_INDEXED`, `CALL_ARGUMENT_INDEXED`, `INTTOPTR`, the memcheck's "whose base", the policy's "stores with a register offset" |
| the table's three ops take no address and no value, so every row is the runner's: every indirect call of the code is `open`, `row`, `unwind`, `puts`, `hex` or `load32` of the ops table of the arguments, `open` gets the table constant itself (the whole operand), `row` a literal below the row count, every row is asked for exactly once (the pointer `hex`, `puts` and `load32` are given is only asked to be rooted in the stack or the image: a pointer the payload chooses passes, S38 to S40) | the IR audit, and the same facts again from the disassembly (`binary_call_problems`: the register class of every `blr`, and the literal in `w0` before every `row` call) | `OPEN_ARGUMENT`, `OPEN_COUNT`, `ROW_INDEX_NOT_CONSTANT`, `ROW_INDEX_RANGE`, `ROW_COVERAGE`, `CALL_TARGET_UNKNOWN`, `INLINE_ASM`, `BIN_INDIRECT_CALL`, `BIN_ROW_COVERAGE` |
| the table is well formed, is the only table of the image, and is the table that was approved | the runner's own rules, run on the ELF's table by `tools/sp11_wtab.py` (the Python mirror, tested against the C on thousands of damaged tables), the count of the table magic in the flat binary (exactly one), and the digest of the note | `TABLE_REFUSED(<reason>)`, `TABLE_COUNT`, `TABLE_SHA`, `TABLE_MISSING`, `TABLE_DRAFT` |
| every word the payload reads **with `load32`** is in a block that answers whatever the table does or in a window of the table (which the runner opens only after the rows before it) | the IR audit, given the readable blocks | `READ_NOT_GATED`, `READ_ADDRESS_NOT_CONSTANT` |
| the pointer a payload gives `hex` (the destination), `puts` (the string) or `load32` (`out`) | **the runner, when the code runs**, not the tools: `hex` writes only inside the stack, `puts` reads only from the stack or the payload's image (up to the 101 bytes it can read, and not past the end of either), `load32` refuses an `out` outside the stack; a refusal does nothing, is counted (`REFUSED` of the `PAYLOAD DONE` line, which is never dropped) and the first one of `hex` and of `puts` is a line of the page | `PAYLOAD OP REFUSED HEX\|PUTS`, `E_OUT` of `load32` |

The runner also checks at run time what the tools can only check before. At `open`: a table named as a draft is refused unless the runner was built to take one (`DRAFT`); a row address
inside RAM or reserved memory of the firmware's memory map is refused (`ROW_ADDR_TYPE`: a row that writes may address only a word absent from the map or in a memory-mapped-I/O
descriptor); the platform must offer what the table needs (`PLATFORM`: a read, a store and an SError poll for a table that writes, a counter that counts for a table that writes or
waits); the mapping attribute of **every** row's page is printed (`WTAB ATTR <tag> DEVICE|NORMAL|NONE|UNKNOWN`, check rows included) and a row that **writes** to a page that is not Device
is refused (`ROW_ATTR`: an unknown answer is a refusal). Then the table is copied and hashed once and the copy is what runs (the payload's image can change under a run; the copy
cannot), a payload's load inside a window is refused until the window's row is done, a `hex` whose destination is not inside the payload's stack and a `puts` whose string is not in the stack or the payload's
image are refused (the same limit `load32` always had for its `out`), counted in `REFUSED` of the `PAYLOAD DONE` line and, the first time, on the page (`PAYLOAD OP REFUSED`).

## The table

Layout (`sp11-payload-wtab-abi.h`, mirrored in `tools/sp11_wtab.py`; every offset is asserted): a 64-byte header, `rows` rows of 88 bytes, `windows` windows of 16 bytes, no
padding. At most 48 rows, 8 windows, 16 steps and a 30 s pause; the table's `bytes` is the length its SHA-256 covers.

A row is one 32-bit device word. The runner does, in this order:

1. `pre = load(addr)` (guarded: a fault stops the run). `(pre & found_mask) == found_value` or the run stops **before** the row writes: a unit or firmware that differs from what the
   author saw is an answer, not a licence. A row that writes must say what the bits it writes hold when found (`found_mask` covers `mask`: `ROW_NO_FOUND`, so no blind read-modify-write)
   and that is not already the wanted value (`ROW_NEVER_WRITES`).
2. `mask == 0`: a **CHECK** row, nothing is written. Otherwise `new = (pre & ~mask) | value` is stored **once**: the runner first polls for an SError (a pending error response of an earlier access is not taken for the store's), prints the `W` line that
   names the row, **journals the row**, and only then stores.
3. After `settle_us`: poll `load(rb_addr)` until `(v & rb_mask) == rb_value` or `rb_timeout_us` has passed (a write row must have one; at most 100 ms). After the read-back the
   runner polls for an SError again; one stops the run (so does one after the store itself).
4. `after_us` (at most 1 ms) before the next row: the hardware's own settle time, from the driver the row is derived from.

**A row is a read-modify-write of the whole word**: the bits outside `mask` are stored as they were read, status bits included (the way Linux's `regmap_update_bits` does). A
table's author must say in the row's `rmw` field why that is safe for the word (a plain control word; no write-one-to-clear bits outside the mask). `tools/sp11_wtab.py` refuses a
write row without it, and prints it in the note.

**Undo.** `restore`: the masked bits go back to what the runner read just before it wrote them. `value`: the masked bits are set to `undo_value`. `none`: only with the header flag
`allow_irreversible`, the note must say so, and the run can then end only as `PARTIAL`. Each undo reads the word, writes the bits back (not when they are already right), polls for an
SError, waits `undo_after_us`, then **proves** it: the same word must read back the restored bits, and, if the row names one, `undo_rb_addr` must match `undo_rb_value` within
`undo_timeout_us`; an SError after that read-back fails the undo too. A table in which a write row has no undo, no undo read-back or an undo that cannot change the word is refused
(`ROW_UNDO`, `ROW_UNDO_RB`).

**Steps** group the rows; `pause_s` is a wait **before the first store of every step that writes** (`WTAB NEXT STEP=n AFTER p S`), which is the operator's time to see the page.

**Windows** (`base`, `size`, `after_row`): words the payload may read through `ops.load32` only while the row `after_row` is complete, and never again once the run has stopped or
been undone: blocks behind a power domain or a clock the table switches on. A read outside every window is not gated by the runner (the audit holds it to the readable blocks).
A table in which a row up to and including `after_row` itself addresses a word of the window (its address, its read-back or its undo read-back) is refused (`WIN_ROW_READS`):
the rows that open a window never touch it.

**Header flags.** `restore_at_end`: when the payload **returns** with rows still in force the runner undoes them (`WTAB AUTO_UNWIND`); a payload that forgot to call `unwind`, or returned on
its own error, cannot leave the device changed (the table may still not rely on it: the payload should call `unwind` itself, which the model tests). A payload that takes an
**exception** is not covered: `q1n1_fault` halts (no console) or resets after 30 s, no undo runs, and a row in force stays in force until the next power-off. Without the flag the
run ends `LEFT`.

## The run-time contract: fail closed

* **Any** of: a read that faults, a found value that is not the expected one, a store that faults or raises an SError, an SError pending before a store, a read-back that does not
  match in time, a counter that does not count or runs backwards, a row asked out of order or out of range, a windowed read that faults or raises an SError **stops the run**.
  Nothing is retried.
* On a stop the runner **prints why first** (`WTAB STOP WHY=<NAME> ROW=n A=.. GOT=.. WANT=.. MASK=..`, so that a hang in the undo still leaves the reason on the page), **latches**
  (every later `row` returns `STOPPED`; every later windowed read is refused), runs the **undo rows in reverse order** and proves each, and ends with **one** `END` line:
  `WTAB END RESULT=RESTORED|UNDO_FAILED|PARTIAL|LEFT WHY=<NAME> ROWS=n STORES=n UNDOS=n RESTORED=n OF=n`.
* An SError in an undo (after its store or after its read-back) ends the undo of every row that is left (`U n FAIL NOT_TRIED`): the bus is not trusted with more. A row whose undo
  fails stays in force and is named.
* A row is journaled **before** its store, so that a store that **faulted** is undone too: an external abort on a write leaves the word unknown (it may or may not have written), and the
  undo reads the word, puts the bits back if they differ and proves them. A store that raised an SError, or whose read-back never matches, is exactly the one that must be undone.
* Time comes from the counter the runner is given (the `CNTFRQ_EL0` rate, 1 to 1000 MHz); a counter that does not advance, or goes backwards, stops the run (`COUNTER`): the timeouts
  that guard a write are never "spin until it changes".
* **Print as you go.** Every store is announced by its `W` line **before** the store, and every line is emitted when it is made (never buffered): the last line on the panel names
  what hung. The table's own lines are at most **32**: the ordinary lines (the open line, one `WTAB ATTR` line for each row, a `NEXT STEP` line for each step that writes and one or two
  lines for each row) and a **reserve** that they cannot use, 2 + 2 per write row (+2 for a table with windows): the `STOP` (or `AUTO_UNWIND`) line, a `U` line and at most one
  `U FAIL` line for each write row, the `END` line and, in a table with windows, the two `READ REFUSED` lines. A table whose ordinary lines plus its reserve exceed 32 is refused
  when it is opened (`LINES`), so the stop, the undo and the end always have their lines; a line beyond the limit is dropped and counted (`DROPPED`), never cut in half, and a store
  whose own `W` line cannot be printed is not made. The ATTR lines cost one line per row: 4 for the dry table of S1, 11 for the live draft.

## A hang is not recoverable by the guard

A guarded load returns a **synchronous** abort as a code. It cannot return from a bus that never answers (a read of an unclocked block), and it does not see an SError that EL3
routes away (`blind` in the host model documents that limit on purpose). So the table's note carries the operator's rules, and they are the same for every table:

* The page stops on a `W` line, a `NEXT STEP` line or the line of a window: **wait 60 s**; if nothing moves, **hold the power button until the panel is dark**, wait 10 s, power on.
  INFERRED, never observed on the unit: a hard power-off returns every register a table touches to its power-on state; nothing is "undone" by anything else, and the table must not rely on it.
* **Where a hang is.** The last line names the store or the check that was in flight: after a `W` line, the store or its read-back; **after a `C` line, the hang is in the next row**
  (its first read), or in the payload's own reads between two rows (reads that are not rows of the table), and after the `WTAB OPEN` line it is in the first row. A stop with
  no `WTAB` line after `PAYLOAD CALL` is in the open itself (the counter check or the page walk of the first row), and a stop after fewer `WTAB ATTR` lines than the table has rows is in the page walk of the
  first row that has none yet. The `WTAB ATTR` lines are printed before the table opens; they read the firmware's translation tables, never a device word.
* **Do not run the bundle again.** Photograph the last lines and record the last one: the line names the store, the read-back or the window that hung, and that is the result.
* A reboot by itself during a run (the board resets) is a result too: the lines before the last one are on the panel only if they were made before it.
* A run that is **not** a hang but an exception of the payload itself (`q1n1: unhandled exception`) gets no undo either: see the header flags.

## The approval note

`python3 tools/sp11_wtab.py note <table.json> --payload <name> --payload-sha <hex> --runner-sha <hex>` prints the note: the table's SHA-256 and size, what the runner prints on `open` (the `WTAB ATTR` lines and the
line count included), the flags, **every row** (address, mask and value, what is expected to be found, the read-back and its timeout, the undo and its proof, the `rmw` argument, **the effect
of the write**, why, the source and the label), every window, what the runner asks before it runs and what stops a run, the **exposure** (a hang or a reset; the run writes no storage;
the recovery is a power cycle), the **pre-conditions** the operator confirms in writing (AC power or at least 50 % battery, the thermal state: the runner has no battery or thermal service,
so these are the operator's decisions and not run-time checks), the table's own **hang rule** and how to read a hang, what is **unknown**, what a successful run looks like, and the sentence
that fixes the approval: **the operator quotes four SHA-256 values: of the note, of the table, of the payload and of the runner image** (the WTAB=1 image the run is staged with). The tool refuses a table that has no note text, a
**draft** table (a table with unobserved expectations: `draft` list and the `-DRAFT` suffix of the name, which the runner refuses at `open` unless it was built to take one), a window nobody
reads, a write row without its `effect`, and a row without its evidence label. **A table that writes is approved only with the `WTAB ATTR` line of the page it writes to in a film of the dry
run**: the dry table checks the very word the live row would store to.

An approval is for one table. Any change of a row, a window or a flag changes the table's digest; the policy of the payload pins the digest (`table_sha256`), so a payload built over another
table fails its policy. No tracked source may change between `--prepare` and the boot ([the main tree's rule](../AGENTS.md)).

## Line catalogue

| Line | Where | Meaning |
|---|---|---|
| `WTAB ATTR <tag> DEVICE\|NORMAL\|NONE\|UNKNOWN` | page | one for **every** row, before the open line: the mapping attribute of the row's page as the runner classifies it (the classification of `stk_attr` in `main.c`: `NONE` no valid descriptor, `UNKNOWN` a walk that failed or no answer); a row that writes needs `DEVICE` |
| `WTAB OPEN <name> ROWS=n STEPS=n SHA=<first 8 bytes>` | page | the table was validated and copied; the digest the operator approved |
| `WTAB REFUSED=<NAME> [AT=n]` | page | `open` or a row was refused; nothing was written (`DRAFT`, `PLATFORM`, `ROW_ATTR` and `ROW_ADDR_TYPE` name the row) |
| `WTAB NEXT STEP=n AFTER p S` | page | a step that writes begins after the pause |
| `PAYLOAD OP REFUSED HEX\|PUTS A=.. [CAP=..]` | page | the first time the payload gave `hex` a destination outside its stack or `puts` a string outside its stack and image: nothing was written or read; at most one line for each op (two in all), counted in the payload's own line budget and not in the table's 32, so `STOP`, the `U` lines and `END` are never crowded out; every refusal is in `REFUSED` of the `PAYLOAD DONE` line |
| `W n <tag> A=.. OLD=.. NEW=..` | page | **before** the store: the row, the word, what was read and what will be written |
| `R n OK [RB=.. US=n]` | page | the store's read-back matched after that many microseconds |
| `C n <tag> A=.. V=.. [RB=.. US=n]` | page | a CHECK row: the value found and its read-back |
| `S n <tag> A=.. V=..` | page | a write row whose word was already as wanted, so no store was made; no table that passes the rules can produce it (a write row's `found` covers its `mask` and is not already the wanted value), the runner keeps the line as a defence |
| `WTAB STOP WHY=<NAME> ROW=n A=.. GOT=.. WANT=.. MASK=..` | page | why the run stopped, before any undo |
| `U n <tag> A=.. NOW=.. NEW=..` / `U n FAIL <why>` | page | the undo of a row, in reverse order; `FAIL VERIFY|FAULT|SERROR|COUNTER|NOT_TRIED` |
| `WTAB READ REFUSED A=.. GATE_CLOSED|RUN_ENDED` | page | a payload's read of a window that is not open (at most two lines) |
| `WTAB AUTO_UNWIND IN_FORCE=n` | page | the payload returned with rows in force; the runner undoes them |
| `WTAB END RESULT=.. WHY=.. ROWS=.. STORES=.. UNDOS=.. RESTORED=.. OF=..` | page | exactly one, last of the runner's lines; `RESULT=RESTORED` means every row that was changed was put back **and proven** |

## Building it

`make -f platform/uefi/Makefile SP11=1 PAYLOAD=1 WTAB=1 payload-runner payloads` (with the SP11 table sources, as for any runner). `WTAB=1` without `PAYLOAD=1` is an error. **`WTAB=1` does not
build the runner to take a draft table** (`Q1N1_WTAB_ALLOW_DRAFT` stays 0: the host model and the QEMU harness of a draft set it themselves, by name). With
`WTAB=0` the runner is the runner of the base tree: `sp11-payload-wtab.c` compiles to an empty object, `sp11-payload.h`, `sp11-payload-run.c` and `main.c` preprocess to exactly the text
they had with every `#if Q1N1_SP11_WTAB` block removed (`DefaultOff` in the tests), `make -n` plans the same commands, and the runner image built from the base commit and from this tree with
the gate off is one byte string (`GateOffBuild`). The platform side is `main.c`'s two guarded accesses (one 32-bit load into the runner's variable, one 32-bit store of a value, both through `live_guarded`),
the mapping classification `wtab_attr` (the logic of `stk_attr`, over `live_attr`) and one `q1n1_wtab_attach` call: the runner loop reads the attached services, and `struct q1n1_payload_env`
is untouched. A runner without the gate hands a payload no ops (`args.reserved[0]` stays zero), and a table payload says so and stops (`REFUSED=NO_WTAB_RUNNER`); it never writes.

## Tests

| Command | What it says |
|---|---|
| `python3 tools/test-q1n1-sp11-payload-wtab.py` | the framework: `TableTool`, `Differential` (C against Python on thousands of damaged tables, every table reason reached, the draft included), `Harness` (`tools/test-q1n1-sp11-payload-wtab.c` with `-rules.c`, `-open.c`, `-faults.c` and `-ops.c`, twelve suites under ASan and UBSan against a fake device that faults, applies a write and then faults, raises an SError at the n-th poll, sticks, hangs, loses its page and runs on a counter that lies, and a probe that hands the runner's ops pointers of its choosing; built with and without the draft allowance), `CompiledCode`, `IrAudit`, `Mutants` (payload, table and runner seeded bugs, the ops' seeds S38 to S40 run through the real loop, each by its own check), `DefaultOff`, `GateOffBuild` (its base is the parent of the commit that added the runner's table source, derived from the history) |
| `python3 tools/test-q1n1-sp11-payload-gpus1.py` | the first use: the tables, the audit of the two payloads, the model of the CX domain (live, dry and the two refusals of a draft), the seeded bugs of the payload and the review's seeds |

The seeded bugs of the policy tooling, each refused for its own reason:

| Seeded bug | Refused by | Reason |
|---|---|---|
| a store outside the table (the payload writes a device word) | IR audit, memcheck | `STORE_INTTOPTR` / `INTTOPTR`, "whose base" |
| a store through a pointer held in memory, or through the arguments | IR audit, memcheck | `STORE_LOADED`, `STORE_ARGS` |
| a wrong value (the table changed) | the policy's digest, the note | `TABLE_SHA` |
| a dropped undo | the table rules (both runner and tool) | `TABLE_REFUSED(ROW_UNDO)` |
| an unchecked index (`row(i)` of a run-time value) | IR audit | `ROW_INDEX_NOT_CONSTANT` |
| an index past the table | IR audit | `ROW_INDEX_RANGE` |
| a row asked twice and another never | IR audit, disassembly | `ROW_COVERAGE`, `BIN_ROW_COVERAGE` |
| `open` of a table that is not the constant (a stack table) | IR audit | `OPEN_ARGUMENT` |
| a store, or a call to a made-up address, in inline assembly | IR audit, disassembly | `INLINE_ASM`, "whose base", `BIN_INDIRECT_CALL` |
| a read of a word in no readable block and no window | IR audit | `READ_NOT_GATED` |
| a read of a computed address | IR audit | `READ_ADDRESS_NOT_CONSTANT` |
| a store through the stack base plus a run-time offset that lands on a device word (S02, S22: also with the address laundered through a volatile) | IR audit, the policy's map of register-offset stores, memcheck: in the function of the store | `STORE_INDEXED`, "stores with a register offset", "whose base" |
| the same store in a helper that stores through its pointer parameter, the caller adding the run-time offset (S27), and the same with a four-byte `memset` in the helper (S30) | IR audit (the call argument), memcheck (`STACKX`, in the callee) | `CALL_ARGUMENT_INDEXED`, "whose base" |
| the address folded into one register by an empty `asm`, so that the store is a plain `[xN]` (S28) | IR audit, memcheck (`STACKX`) | `INLINE_ASM`, `STORE_UNKNOWN`, "whose base" |
| a stack store with an index the runner passed (S18) | IR audit, the policy's map | `STORE_INDEXED`, "stores with a register offset" |
| a store through a `select` or a `phi` of a device literal and a stack address (S03, S04) | IR audit (every operand counts), memcheck | `STORE_INTTOPTR`, "whose base" |
| `open` of an address inside the approved table (S09) | IR audit (the whole operand) | `OPEN_ARGUMENT` |
| a second table in the image that has no `wtab_` name (S10) | the table check of the flat binary, IR audit | `TABLE_COUNT`, `OPEN_ARGUMENT` |
| `hex` given the stack base plus a run-time offset that lands outside the stack (S38), `puts` given a string there (S39), `load32` given an `out` there (S40): **no tool refuses them** (the seeds pass the IR audit and the binary policy, which the test pins) | the runner, when the code runs (the harness compiles each seed into the reference payload and runs it through the real loop; a runner without the check shows the damage) | `PAYLOAD OP REFUSED HEX\|PUTS`, `E_OUT` of `load32`; the checks `hex_outside_the_stack.*`, `puts_of_a_string_in_neither.*`, `load32_out_of_the_stack.*` |
| the runner, one change each: a row journaled after its store, no SError poll before a store, after a store's read-back or after an undo's read-back, the reserve of lines not kept back, an undo that does not wait, a timed poll without a counter, an undo store that faults and ends the other undos, a draft opened, a write row on a page that is not Device accepted, the mapping asked for the read-back's page, an unknown mapping taken for Device, a settle time not waited, a store after its line was dropped, a write row that says nothing about its bits accepted, an op pointer not checked, a refusal not counted, a refusal line printed every time or past the line budget, the two ops sharing one "refusal printed" bit, `hex` allowed to write into the payload's image, the window of `hex` or `puts` moved by a few bytes at an edge, a hole of one byte in the image window of `hex`, a refused `hex` that still writes, a refusal line that names no pointer or is not charged to the budget | the host harness | the checks `store_fault_applied.*`, `serror_before_store.*`, `undo_serror_readback.*`, `worst_case_*`, `draft.*`, `attr.*`, `late_serror.*`, `undo_waits.*`, `counter_unusable.*`, `undo_store_fault.*`, `attr_of_the_row.*`, `settle_waits.*`, `no_line_no_store.*`, `refuses.write row with no found mask`, `hex_*`, `puts_*`, `load32_out_of_the_stack.*` |

## What this does not establish

* That any table is right. A row is its author's claim; the label (VERIFIED in a pinned source, OBSERVED on the unit, INFERRED) is in the note, and a draft has none of an approval.
* That a payload cannot write a device word or read where it likes. The checks above are a lint of the base of every store, of the computed indices a store's own function shows and of a pointer a computed index
  moved, and of a stack pointer an `add` moved by a register. They do not follow a pointer that a loop advances (a pointer walked by a literal stride until it equals a run-time address: S32), they do
  not compare an offset that is a literal with the size of the stack object (S43), and they ask the pointer an op of the ABI is given (the destination of `hex`, the string of `puts`, the `out` of `load32`) only to
  be rooted in the stack or the image (S38, S39, S40). The runner refuses those three pointers when the code runs, if they leave the stack (the image too, for `puts`); for everything else
  the control is that the payload's bytes are reviewed (a disassembly audit of the staged binary, **including the pointer argument of every `hex`, `puts` and `load32` call and any pointer
  advanced in a loop**) and pinned by the manifest. A payload is not trusted because it passes. A refused `hex` or `puts` is not a stop of the table's run: it does nothing and says so, and a payload that does it is not the reviewed one.
  (The comment at the top of `platform/uefi/sp11-payload-abi.h` says the same: the ops table holds no store of its own, but `hex`, `puts` and `load32` act through pointers the payload chooses. The
  header is in the set of files the gate-off test of `SMMUMAP` allows to differ from the base, for that comment-only change.)
* The IR audit exempts a call of an `llvm.*` intrinsic from `CALL_ARGUMENT_INDEXED` (the destination of a `memset`, `memcpy` or `memmove` is judged as a store). An exclusive store hidden in a builtin (S46) is
  no finding of the IR audit; the binary policy, which refuses every exclusive and atomic instruction, is the layer for it.
* The runner's skip path (the `S n` line: a write row whose word is already as wanted) is dead defence. No table that passes the rules can reach it (a write row's `found` covers its `mask` and is not the wanted
  value), and no test reaches it either: it is kept because it can only avoid a store.
* That a write is safe on the unit. The framework makes a write **examined, bounded, announced and undone**; it does not make an unclocked access, an SError that EL3 hides, or a power
  domain that does not come up recoverable. [A hang is not recoverable by the guard.](#a-hang-is-not-recoverable-by-the-guard)
* That the undo restores the **system**: the runner proves the words it wrote read back as found. Another master's vote, a latch that does not drop, or state a clock or a domain
  gave to a block while it was on is not what it proves.
* The write is visible to the device by its read-back: the model treats a read of the same word as ordered after the store; on the unit that is the device memory's ordering. The runner
  refuses a write to a page it cannot show to be Device (`ROW_ATTR`), which is what makes that ordering the right one; no payload has a barrier (`forbid isb/dsb/dmb`), the runner's glue owns that.
* The Python mirror of the C rules proves the tool and the runner agree, not that either is complete.

## First use: gpus1 and gpus1d

[`payloads/gpus1.c`](../payloads/gpus1.c) is GPU stage S1: the CX power domain of the Adreno X1-85 powered from the off state boot 30 found, and returned to how it was found. It has **no
device store anywhere in its code**; its live table ([`payloads/gpus1.wtab.json`](../payloads/gpus1.wtab.json)) writes exactly one word, the CX GDSC control word, has **no window** (nothing
behind the domain is read), and is a **draft**: the CX-domain clock tree is only partly observed, the note tool refuses it, the runner as the Makefile builds it refuses it at `open`
(`DRAFT`), and the payload stops after saying so unless it is built for the host model. [`payloads/gpus1d.c`](../payloads/gpus1d.c) is the same code over the dry table
([`payloads/gpus1d.wtab.json`](../payloads/gpus1d.wtab.json)), which writes nothing: its rows check the words the live table would find, with a settle and a read-back of their own, so that
the runner's timed machinery and its `WTAB ATTR` lines run on the unit before any write. It is the first run of the framework there, and its digest is pinned by the policy `gpus1d`.
**The live table is not to be approved**: that needs the read-only survey of the clock-tree words it never read, turned into check rows, and the `WTAB ATTR CXGDSC` line of the dry run in a
film. The design, the sources, what is unknown and the survey are in [SP11-GPU-S1-DESIGN.md](SP11-GPU-S1-DESIGN.md).
