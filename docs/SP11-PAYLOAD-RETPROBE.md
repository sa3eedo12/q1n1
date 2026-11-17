<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `retprobe`: does a page of DRAM keep its bytes across a reset? (the retention probe M10)

**EXPERIMENTAL; hardware NOT RUN.** No value of this payload is OBSERVED on the unit. No run is authorised by this document, by its
tests, or by the fact that its files are on a stick: a run needs the operator's written authorisation (below).

`payloads/retprobe.c` is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest, the
stick files, the chain, ABI v1 and the line catalogue are defined there and not repeated. PHASE 1 here is the read-only query that
[SP11-PAYLOAD-PSCI.md](SP11-PAYLOAD-PSCI.md) made. Evidence labels as there: VERIFIED, OBSERVED, INFERRED, EXPERIMENTAL,
UNIMPLEMENTED, UNKNOWN.

It is one part of a design whose purpose is that every later hardware run hands its result over as a **file on the stick** and not as
a photograph of the panel. The whole design (the operator's runbook, the stick-side extraction, the host tool that reads the dumps and
its verdicts, the result log the probe's outcome would select, and the fallbacks if nothing is retained) is Snapintosh
`docs/SP11-RETENTION-PROBE.md`. This document is the payload's own: what it reads, what it writes, what it may call and what it prints.

## The question

A reset takes the panel with it. If a page of DRAM keeps its bytes across a reset, the next boot can read what the last boot knew and
put it on the stick. Nothing here is assumed. The payload writes three canary pages, optionally resets the machine by a path that
the operator's configuration names, and in the next boot (another run of the same payload, or the Shell's dump) the pages are read
back and judged WHOLE, PARTIAL or NONE.

<!-- retprobe-evidence -->
| Statement | Label | Where it comes from |
| --- | --- | --- |
| `PSCI_FEATURES(SYSTEM_RESET)` answers 0 on the unit | OBSERVED once (boot 5, payload `psci`) | [SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md) |
| `PSCI_FEATURES(SYSTEM_RESET2)` answers `NOT_SUPPORTED(-1)` on the unit | OBSERVED once (boot 5) | the same |
| a 0 from `PSCI_FEATURES` means the function is implemented | INFERRED (the PSCI specification was not re-read) | |
| the architectural warm reset type 0 is implied by `SYSTEM_RESET2` being implemented | INFERRED | `PSCI_FEATURES` has no reset-type argument |
| after a restart by itself the unit boots its normal order, not the stick | OBSERVED (operator report, as after boot 4) | [SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md#the-restart-probe) |
| a `SYSTEM_RESET` call restarts the unit, and the call does not return | UNKNOWN | this probe |
| DRAM keeps its bytes across that reset | UNKNOWN | this probe |
| the point of coherency that `DC CVAC` reaches is DRAM and not a system cache in front of it | UNKNOWN | cannot be told from software alone |
| a read of memory never written since power-on does not abort | UNKNOWN | the guarded `load32` catches an abort and says so |
| firmware does not use or clear the three pages before the next boot reads them | UNKNOWN | what the probe measures, with the memory map of that boot |
<!-- /retprobe-evidence -->

## What it does, in order

1. **PHASE 1, always.** It looks for its configuration (below), prints what it found, asks `PSCI_FEATURES` about `SYSTEM_RESET`
   (`0x84000009`) and `SYSTEM_RESET2` (`0xC4000012`), and prints the answers and what they imply for the warm reset type. This phase
   writes nothing. Without a valid configuration the payload stops here with return 0 (a configuration that is present but
   refused ends with return 4): a manifest that lists `retprobe` alone is a PHASE 1 run.
2. **Checks, before any store.** The map, the configuration and every page are checked and all of PHASE 2 is refused when one
   check fails. Each of the three pages must lie inside one descriptor of the final memory map, of type 7 (conventional: free
   memory, in no range of the runner or of a payload), must overlap no descriptor of another type nor the payload, its stack, the
   preload table or the map buffer, and EL2's stage 1 must translate it for a read (`AT S1E2R`) and for a write (`AT S1E2W`) to
   itself as Normal write-back memory. The two translation instructions make no access and cannot abort; they write `PAR_EL1`, the
   one system register the payload writes. They show that EL2's stage 1 maps the page and nothing more: not that TrustZone, an XPU or QHEE
   leave the physical page alone outside UEFI's memory map (INFERRED: nothing here can see their use), and a store the hardware rejected
   would be an external abort, which only a power cycle ends. If the configuration names a
   reset, `PSCI_FEATURES` must have said that function is implemented: otherwise the payload refuses here, return 7, with no store.
3. **It reads the previous boot's three pages first**, through the runner's guarded `load32` (3072 loads, below the budget of
   4096 per call): a second reader, independent of the Shell's dump and of the host tool. Each page is WHOLE, PARTIAL or NONE
   (below), or UNREADABLE when a load aborted. The boot counter of this run is the highest WHOLE counter plus one, or 1. Every other
   read is a plain load that nothing guards: of the runner's preload table, of the configuration file the table names, of the runner's
   memory map and, after the stores, of the three pages it wrote.
4. **It writes the three new pages.** `page_store` holds the only stores to memory outside the payload's own stack. The host test compares
   every buffer the payload is given (the preload table, the memory map, the configuration file) and the rest of the arena with what
   they were before, after every run, so a store anywhere else fails it. Every cache
   line is then cleaned with `DC CVAC` and a `DSB SY` follows: a reset takes the caches with it, so a line that is only dirty is gone.
   `DC CVAC` and `DC CIVAC` reach the point of coherency and no further: whether a system cache (LLCC), a buffer of the memory controller,
   DRAM's self-refresh or a scrub of memory at boot keeps or loses a page is not named here, and is part of what the run measures.
5. **It verifies the write**: `DC CIVAC` over every line, `DSB SY`, then the CRC of each page is recomputed from memory.
6. **It prints the countdown** `NEXT RESET AFTER <n> S` and waits that many seconds of the generic counter, so that the page can be
   seen and the operator can do what the runbook says, then it calls the reset the configuration names, once. It is never called
   when a store or its verification failed, when the counter does not advance or runs backwards, or when `PSCI_FEATURES` did not report it
   implemented. If the call returns, the line says what it returned and nothing else is done: no second call, no other path.

## The page record

Layout version 1, little endian, 4096 bytes: a 128-byte header of 32 words and 992 body words.

<!-- retprobe-page -->
| Words | Field | Value |
| --- | --- | --- |
| 0-1 | magic | `RETCAN01` |
| 2 | layout version | 1 |
| 3 | page index | 0 to 2 |
| 4-5 | physical address of the page | |
| 6 | boot counter of the boot that wrote it | 1 to `0xFFFFF` |
| 7 | previous counter | the highest WHOLE counter read at the start of that boot, else 0 |
| 8-9 | `CNTPCT_EL0` when written | |
| 10 | `CNTFRQ_EL0`, low 32 bits | |
| 11 | raw x0 of `PSCI_FEATURES(SYSTEM_RESET)` | |
| 12 | raw x0 of `PSCI_FEATURES(SYSTEM_RESET2)` | |
| 13 | four bytes | reset path requested, reset path used (0 none, 1 `SYSTEM_RESET`, 2 `SYSTEM_RESET2`), previous state of page 0, of page 1 |
| 14 | four bytes | previous state of page 2 (0 NONE, 1 PARTIAL, 2 WHOLE, 3 UNREADABLE), flush method 1 (`DC CVAC` by line, `DSB SY`), two zero bytes |
| 15 | descriptor type | 7, the type of the memory-map descriptor that holds the page |
| 16-17 | descriptor start | |
| 18-19 | descriptor size in bytes | |
| 20-30 | reserved | zero |
| 31 | CRC-32 | IEEE, the value of `zlib.crc32` over the page with this word taken as zero |
| 32-1023 | body | word i (0 to 991) is the bitwise OR of `counter << 12`, `page index << 10` and `i` |
<!-- /retprobe-page -->

The body is built so that no word of a decayed page (all zero, all ones) can be mistaken for one, and so that a page whose header is
gone can still say which words are intact and from which write they come.

**The state of a page**, decided the same way by the three readers (this payload, the host tool of Snapintosh
`tools/sp11_retention_check.py` over the Shell's dump, and the independent oracle of the tests):

* **WHOLE:** the header names this very page (magic, version 1, index, address, a counter from 1 to `0xFFFFF`), the CRC holds, and
  not one body word is wrong.
* **PARTIAL, header named:** the header names this page but the CRC fails or a body word is wrong. The count of wrong words and the
  CRC verdict are reported.
* **PARTIAL, header lost:** among the body words whose low ten bits equal their own index, the epoch (the bits above ten) that most of them agree
  on is found, ties going to the smallest epoch; at least 16 words of exactly that epoch make the page PARTIAL.
* **NONE:** anything else, an all-zero page, an all-ones page and noise included. It is not proof that DRAM lost the page: firmware
  may have used it (the memory map of the next boot says so, in the design document).

## The configuration

The manifest lists the payload and, after it, one data file of exactly 64 bytes that starts with the magic `RETCFG01`; the payload
finds it in the runner's preload table, skipping its own entry. A stick that has no such file, or two of them, is a PHASE 1 run.
The pages and the reset path are data, not code, so that one reviewed binary serves the unit and the QEMU tests, and the
authorisation names both files by SHA-256.

<!-- retprobe-config -->
| Words | Field | Rule |
| --- | --- | --- |
| 0-1 | magic | `RETCFG01` |
| 2 | layout version | 1 |
| 3 | reset path | 0 none, 1 `PSCI_RESET`, 2 `PSCI_RESET2` |
| 4 | countdown in seconds | 1 to 60 |
| 5 | page count | 3 |
| 6-11 | three page addresses | 64-bit each, 4 KiB aligned, not zero, distinct, below the address limit |
| 12-14 | reserved | zero |
| 15 | CRC-32 | of words 0 to 14, checked before any field is believed |
<!-- /retprobe-config -->

A sample (the stick test's; it authorises nothing): path 1, countdown 8 and the pages `0x9C000000`, `0xF8400000` and
`0xFFFF00000`, chosen in the design document from the six memory maps of the unit's runs.

## The reset paths

<!-- retprobe-paths -->
| Path | Value | Call | Gate, before any store | On the unit |
| --- | --- | --- | --- | --- |
| `NONE` | 0 | none | nothing is called | the default and the negative control: the canaries stay for a reset the operator makes |
| `PSCI_RESET` | 1 | `SYSTEM_RESET` (`0x84000009`), no argument | `PSCI_FEATURES(SYSTEM_RESET)` is not negative as a 32-bit result, else return 7 | answered 0 once (OBSERVED) |
| `PSCI_RESET2` | 2 | `SYSTEM_RESET2` (`0xC4000012`), reset type 0 (the architectural warm reset), cookie 0 | `PSCI_FEATURES(SYSTEM_RESET2)` is not negative as a 32-bit result, else return 7 | answered `NOT_SUPPORTED(-1)` once (OBSERVED): the payload refuses |
<!-- /retprobe-paths -->

UNIMPLEMENTED: the UEFI `ResetSystem` (OBSERVED not to work after the bounce, X1, in Snapintosh `docs/SP11-STICK-LOG.md`; the payload ABI
has no such operation either), a forced hang left for a watchdog, and a long power-button reset (the operator's, with path `NONE`).

`SYSTEM_RESET` is the architectural cold-reset call and the warm reset is `SYSTEM_RESET2`, which the unit answered `NOT_SUPPORTED` once
(OBSERVED; the PSCI specification was not re-read here: INFERRED). A NONE after path `PSCI_RESET` is therefore a likely outcome, and it
says nothing is wrong with the probe or the unit.

## What it may call and execute

<!-- retprobe-calls -->
| Helper | Function id | x1 | x2 |
| --- | --- | --- | --- |
| `smc_features` | `0x8400000A` | `0x84000009` or `0xC4000012`, by index | 0 |
| `smc_system_reset` | `0x84000009` | 0 | 0 |
| `smc_system_reset2` | `0xC4000012` | 0 | 0 |
<!-- /retprobe-calls -->

Each helper holds one function id and nothing else can be put in x0: an index outside the table issues no SMC. It never calls
`CPU_ON`, `CPU_OFF`, `SYSTEM_OFF`, `SYSTEM_SUSPEND` or any vendor id, and it writes no system register but `PAR_EL1`, which `AT S1E2R` and
`AT S1E2W` write as their answer. It reads `CurrentEL`,
`CTR_EL0` (the line size), `CNTFRQ_EL0` and `PAR_EL1`, and calls the runner's `load32` and `counter` ops (the counter is `CNTPCT_EL0`, read by the runner's
helper). Besides `smc` the binary
holds `AT S1E2R` and `AT S1E2W`, `DC CVAC` and `DC CIVAC`, one `DSB` form and the `ISB` that `PAR_EL1` needs: the allow-list in
`tools/sp11_payload_testlib.py` (policy `retprobe`) admits exactly these, and the test applies it to the built binary.
This is the first payload that stores to memory other than its own stack, and it issues a call that can reset the machine: those
are the reasons for the authorisation below.

## What it prints

Every line is `PAYLOAD RETPROBE <line>`. The payload never prints more than 21 lines of its own (a test measures it over random
worlds: `LINES_MAX=21`), inside its budget of 40 and the runner's page of at least 60 lines. The lines that say what happened next
are marked essential and are never dropped.

<!-- retprobe-lines -->
| Line | When |
| --- | --- |
| `CONFIG OK PATH=<path> COUNTDOWN=<s> PAGES=3` | the configuration is valid |
| `CONFIG REFUSED=<reason>` | a file is there and one check of it failed (the reasons below) |
| `CONFIG NONE=NO_FILE` or `NO_TABLE` or `TWO_FILES` | no usable configuration: PHASE 1 only |
| `NEXT FEATURES` | before the PSCI queries |
| `FEATURES SYSTEM_RESET=<raw>:<answer>` | `IMPLEMENTED`, a `NOT_SUPPORTED(-1)`-style error name, or `NEGATIVE` |
| `FEATURES SYSTEM_RESET2=<raw>:<answer>` | the same |
| `WARM_TYPE ARCH=0X0 QUERY=NONE SYSTEM_RESET2=YES` or `NO` | what the second answer implies for the warm reset type |
| `SKIPPED NOT_AT_EL2` | the payload was not called at EL2 (return 2) |
| `SKIPPED PHASE2=NO_CONFIG` | PHASE 1 only |
| `REFUSED CONFIG` | a present configuration was refused (return 4) |
| `REFUSED MAP` | the runner's memory map is unusable (return 3) |
| `PAGE INDEX=<k> BASE=<address> EXTENT=<start> BYTES=<size> MAP=<attributes>` | a page passed every check |
| `REFUSED PAGE=<reason> INDEX=<k> BASE=<address>` | a page failed a check (return 5) |
| `REFUSED CACHE_LINE_SIZE` | `CTR_EL0` gives no usable line size (return 11) |
| `REFUSED RESET_NOT_IMPLEMENTED SYSTEM_RESET` or `SYSTEM_RESET2` | the gate above (return 7) |
| `NEXT READ PREVIOUS PAGES` | before the 3072 loads |
| `PREV INDEX=<k> NONE` or `WHOLE COUNTER=<n>` | the state of the previous page |
| `PREV INDEX=<k> PARTIAL BAD_WORDS=<n> CRC=OK` or `CRC=BAD` | a damaged page |
| `PREV INDEX=<k> UNREADABLE LOAD_ERROR=<e> WORD=<w>` | a load aborted at that word |
| `REFUSED COUNTER_OVERFLOW` | the counter would pass `0xFFFFF` (return 10) |
| `COUNTER THIS=<n> PREVIOUS=<m>` | the boot counters |
| `NEXT WRITE PAGES` | before the first store |
| `WROTE PAGE=0 CRC=<crc> PAGE=1 CRC=<crc> PAGE=2 CRC=<crc>` | the stores are done |
| `CLEAN DC_CVAC_DSB LINE=<bytes> LINES=<n>` | the cache lines were cleaned |
| `VERIFY OK` or `VERIFY FAILED PAGES=<n>` | the read-back (a failure is return 6) |
| `PATH REQUESTED=<path> USED=<path>` | the path |
| `RESET NONE CANARIES STAY FOR A MANUAL RESET` | path `NONE`: nothing more happens (return 0) |
| `NEXT RESET AFTER <n> S` | the countdown |
| `REFUSED COUNTER_NOT_ADVANCING` | the counter did not move or ran backwards: no reset (return 9) |
| `RESET CALL SYSTEM_RESET` or `SYSTEM_RESET2 TYPE=ARCH_WARM` | the instant before the call; if it takes the machine, this is the last line |
| `RESET RETURNED=<raw>:<answer>` | the call came back (return 8) |
<!-- /retprobe-lines -->

The refusal reasons of the configuration are `BAD_CRC`, `BAD_VERSION`, `BAD_PATH`, `BAD_COUNTDOWN`, `BAD_PAGE_COUNT`,
`RESERVED_NOT_ZERO`, `PAGE_UNALIGNED`, `PAGE_RANGE` and `PAGES_NOT_DISTINCT`; those of a page are `NOT_IN_MAP`,
`OVERLAPS_OTHER`, `PROTECTED`, `NOT_MAPPED`, `NOT_WRITABLE`, `NOT_WRITE_BACK`, `NOT_IDENTITY` and `READ_WRITE_DIFFER`.

The page of a run on a fresh arena, as the host program prints it (the addresses, sizes, CRCs and mapping attributes below are examples:
the test compares these lines with the program's output after the hexadecimal values and the mapping are masked):

<!-- retprobe-page-none -->
```
PAYLOAD RETPROBE CONFIG OK PATH=NONE COUNTDOWN=8 PAGES=3
PAYLOAD RETPROBE NEXT FEATURES
PAYLOAD RETPROBE FEATURES SYSTEM_RESET=0X0:IMPLEMENTED
PAYLOAD RETPROBE FEATURES SYSTEM_RESET2=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)
PAYLOAD RETPROBE WARM_TYPE ARCH=0X0 QUERY=NONE SYSTEM_RESET2=NO
PAYLOAD RETPROBE PAGE INDEX=0 BASE=0X48000000 EXTENT=0X48000000 BYTES=0X140F7000 MAP=WB.IS
PAYLOAD RETPROBE PAGE INDEX=1 BASE=0X50000000 EXTENT=0X48000000 BYTES=0X140F7000 MAP=WB.IS
PAYLOAD RETPROBE PAGE INDEX=2 BASE=0X58000000 EXTENT=0X48000000 BYTES=0X140F7000 MAP=WB.IS
PAYLOAD RETPROBE NEXT READ PREVIOUS PAGES
PAYLOAD RETPROBE PREV INDEX=0 NONE
PAYLOAD RETPROBE PREV INDEX=1 NONE
PAYLOAD RETPROBE PREV INDEX=2 NONE
PAYLOAD RETPROBE COUNTER THIS=1 PREVIOUS=0
PAYLOAD RETPROBE NEXT WRITE PAGES
PAYLOAD RETPROBE WROTE PAGE=0 CRC=0XC773C4B8 PAGE=1 CRC=0XFEB369D4 PAGE=2 CRC=0X6942E812
PAYLOAD RETPROBE CLEAN DC_CVAC_DSB LINE=64 LINES=192
PAYLOAD RETPROBE VERIFY OK
PAYLOAD RETPROBE PATH REQUESTED=NONE USED=NONE
PAYLOAD RETPROBE RESET NONE CANARIES STAY FOR A MANUAL RESET
```
<!-- /retprobe-page-none -->

With path 1 the last four lines become the following. If the call returns, one more line follows it:
`PAYLOAD RETPROBE RESET RETURNED=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)`.

<!-- retprobe-page-reset -->
```
PAYLOAD RETPROBE PATH REQUESTED=PSCI_RESET USED=PSCI_RESET
PAYLOAD RETPROBE NEXT RESET AFTER 8 S
PAYLOAD RETPROBE RESET CALL SYSTEM_RESET
```
<!-- /retprobe-page-reset -->

With path 2 and the unit's answer the page ends after the three `PAGE` lines with
`PAYLOAD RETPROBE REFUSED RESET_NOT_IMPLEMENTED SYSTEM_RESET2`.

## Return values

<!-- retprobe-returns -->
| Value | Name | When |
| --- | --- | --- |
| 0 | OK | PHASE 1 only, or PHASE 2 done with path `NONE` |
| 1 | BAD_ARGS | the runner's argument block is wrong, or it lacks `load32` or `counter` |
| 2 | NOT_EL2 | not running at EL2 |
| 3 | MAP | the memory map is refused |
| 4 | CONFIG | a present configuration is refused |
| 5 | PAGE | a page is refused |
| 6 | VERIFY | a written page did not read back whole |
| 7 | NOT_IMPLEMENTED | the configured reset is not implemented |
| 8 | RETURNED | the reset call came back |
| 9 | COUNTER | the counter does not advance or ran backwards |
| 10 | OVERFLOW | the boot counter would overflow |
| 11 | CACHE | `CTR_EL0` gives no usable line size |
<!-- /retprobe-returns -->

## The unit's pages and the memory the payload leaves alone

The pages are chosen outside this payload, in Snapintosh `tools/sp11_retention.py`, from the memory maps of the six runs that exist: the
big conventional extents are the same in all of them, so a page in the middle of one is no firmware's or runner's allocation in any of
them, and the top page of the 30 GiB bank is above where the guest monitor places the guest. The payload does not trust that
reasoning: it checks the map of the boot it runs in, and every page must be conventional there, or the whole of PHASE 2 is refused.
The next boot's firmware may still use a free page before the Shell's dump reads it: the design document's memory map of that boot
says whether it did.

## Authorisation and the stop rule

The payload writes memory the runner does not own and calls the firmware to reset the machine. It is authorised **by name and SHA-256, for
one boot, in writing by the operator**, together with its configuration file, the reset path and the three addresses. The text of the
record (the payload, the configuration and the payload manifest by SHA-256, the reset firmware call, the Shell's stick write, the stop rules, and what
is not written: the internal disk, NVRAM and firmware settings) is produced by Snapintosh `tools/sp11_retention_plan.py`. The
stick carries `retprobe` and its configuration **alone**: no other payload shares the boot.

**Stop rule.** The operator reads the page, or the extraction the next boot writes, before anything else runs. A `REFUSED` line means nothing was
stored and nothing was reset. A `VERIFY FAILED` line means no reset was called. A page that ends at `RESET CALL` and a machine that does
not restart within a minute is left alone and the run is reported: from the reset call until the extraction is written a power cycle loses
the pages, so the power button is only for the end of the run and for danger (heat, a fan at full speed, a smell); before the reset call
a stuck page is ended with it. A line `RESET RETURNED` ends the run: the payload
makes no second call, and neither does the operator by another path in the same boot. The probe is repeated by a new authorisation,
never by habit.

## Tests

<!-- retprobe-tests -->
| Command | What it holds |
| --- | --- |
| `python3 tools/test-q1n1-sp11-payload-retprobe.py` | ten native suites under ASan and UBSan over a modelled machine (a cache that agrees with DRAM only through cache maintenance, PSCI, guarded loads, a counter that stops or runs backwards, the memory map and the MMU's answers) and an independent oracle of the page format, with every buffer the payload is given and the rest of the arena compared after every run; the source audits; the seeded-bug mutants; the allow-list applied to the built binary with seeded bad binaries; the manifest tool and the runner's validator on the stick |
| `python3 tools/test-q1n1-sp11-payload-qemu-retprobe.py` | the real binary at EL2 under QEMU's EDK2: five boots (no configuration, path none, `SYSTEM_RESET` with a countdown, `SYSTEM_RESET2` refused, a page outside the map) |
| `python3 tools/test-q1n1-sp11-payload-retprobe-doc.py` | this document against the source, the host program's pages, the driver and the runner's document, and 70 seeded mistakes in a copy of the document |
<!-- /retprobe-tests -->

The 115 seeded bugs include a reset without the feature check (for each of the two functions), a gate that reads the other function's
answer, no wait, a wait that takes a counter that ran backwards for an endless one, no fence after the clean, no verification, reading after
writing, a WHOLE page without the CRC, a store one word past the page, a stray store to the configuration file, the preload table or the
memory map, a write without a configuration, a configuration found by half its magic, and a reader whose vote takes the rarest epoch.

**What QEMU cannot show.** QEMU's RAM, its cache and its PSCI are not the unit's: a QEMU run says that the payload reads, writes,
cleans and calls what it is configured to call, and nothing about whether this DRAM, or a system cache in front of it, keeps bytes across
this firmware's reset. The end-to-end test in Snapintosh (`tools/test-sp11-retention-qemu.py`) runs the payload, the reset and the
Shell's dump under QEMU, where RAM survives a reset by construction.

## UNKNOWN, and what would settle it

* Whether `SYSTEM_RESET` restarts the unit, and whether DRAM keeps a page across it: a run, by the operator's authorisation.
* Whether a held Volume-Down key through a PSCI reset starts the stick again: a run (the runbook's first operator action).
* Whether the point of coherency that `DC CVAC` reaches is DRAM: not measurable from this payload; a retained page after a reset
  is the only evidence, and a lost one does not say which.
* Whether `SYSTEM_RESET2` is ever implemented (the unit says no, once).
* Whether firmware uses or clears the chosen pages before the next boot reads them: the memory map of that boot, read with the dump.
