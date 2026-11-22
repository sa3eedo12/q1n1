<!-- SPDX-License-Identifier: MIT -->
# GPU stage S1: the Adreno X1-85's CX power domain up from the off state, and back (design)

Stage S1 of the first-contact plan for the Adreno X1-85 of the Surface Pro 11 (Snapdragon X1E80100): bring the CX power domain up from the state the stick survey found it in, check the clocks
it is meant to bring up, and **return the domain to the state it was found in before the payload ends**. It is the first use of the [write table](SP11-PAYLOAD-WTAB.md) and rests on that
framework. **Design, a draft table, a payload and a host model. Hardware NOT RUN. Nothing here authorises a run.** Evidence labels: VERIFIED (read in a pinned public source), OBSERVED (one
word, one read, one unit), INFERRED, EXPERIMENTAL (host model), UNKNOWN.

**The live table (`GPUS1-DRAFT`) is NOT TO BE APPROVED.** A successor table (a new name, a new digest) becomes approvable only when the read-only survey of [section 6](#6-the-order-of-the-first-runs-and-the-read-only-survey) has turned
its list of unread words into check rows, and the dry run has shown, in a film, the mapping attribute the runner reports for the page it would write to
([section 7](#7-the-mapping-attribute-of-the-page-that-is-written)). Nothing in this document, in the tools or in the tests says otherwise.

**Sources.** Linux `torvalds/linux` at the pinned revision `7475ea8b58616b33c04afb976cf0fbaad9dd63fb`, files `drivers/clk/qcom/gdsc.c`, `gpucc-x1e80100.c`, `gcc-x1e80100.c`, `clk-branch.c`, `clk-rcg2.c`,
`common.c`, `drivers/gpu/drm/msm/adreno/a6xx_gmu.c` and `arch/arm64/boot/dts/qcom/hamoa.dtsi`; line numbers below are those of that revision. GPL source is evidence here, not code: no line of it is
copied, and the table is a list of words with citations. **The found words** are derived facts: one read of each word on one unit, by the survey stick of this tree at its boot 30
([SP11-PAYLOAD.md](SP11-PAYLOAD.md)); the survey's own output is not in the repository, and none of it is evidence about another unit or another boot.

## 1. The verdict, in six lines

1. **One write is unavoidable for S1: clear `SW_COLLAPSE` (bit 0) of the CX GDSC control word `GPU_CC_CX_GDSCR` `0x03d99108`** (Linux `gdsc_enable`, then the status bit 31 of `0x03d9953c`). Everything
   else the Linux power-up does is either already in the state it would write at hand-off, or left alone on purpose (the GPUCC AHB branch enable, found 0: section 5), so the first live table has **one store**.
2. **The table is a DRAFT and no approval note can be made for it.** The CX-domain clock tree is only partly observed: six entries (seven words) were never read (section 6). The order is the dry run (zero
   stores), then a read-only survey, then the live table.
3. **It is not established that the domain powers from EL2 without a vote from the GMU, the RSC or AOSS.** Linux makes no vote before the GDSC (section 4; VERIFIED), and the A16 bring-up
   powered the same GDSC from EL2 with no votes (OBSERVED on another SoC), but this unit has never been tried (UNKNOWN).
4. **A hang is not recoverable by the guard**: an unclocked read of GPUCC, or a read of anything behind the domain while it is off, hangs the bus; the only recovery is a hard power-off
   (section 8). The order of the reads is the safety argument.
5. **The first live table reads nothing behind the domain**: it has no window (CX_MISC, the GMU and the RSCC come in a later table, after the survey; section 6).
6. S1 starts no GMU, loads no firmware, and touches no SMMU, no PLL, no RCG and no vote.

## 2. The state found (boot 30, OBSERVED once)

| Word | Address | Found | Meaning |
|---|---|---|---|
| `GPU_CC_CX_GDSCR` | `0x03d99108` | `0x0022f801` | SW_COLLAPSE=1, HW_CONTROL=0, SW_OVERRIDE=0, RETAIN_FF=1, waits EN_REST 2, EN_FEW 2, CLK_DIS 0xf: **exactly what Linux's `gdsc_init` would leave** (gdsc.c:439-453; `gpu_cx_gdsc` waits 2/2/0xf, gpucc-x1e80100.c:532-543). The table asserts it (found `0x0022f801` under `0x00fff807`) rather than assuming it. |
| status (`gds_hw_ctrl`) | `0x03d9953c` | bit 31 clear | the domain is off |
| GMU RCG | cmd `0x03d99318` = `0x80000000` (root off), cfg `0x03d9931c` = 0 | | parked on XO (source 0, divider 0); no request |
| hub RCG | cmd `0x03d993ec` = 0, cfg `0x03d993f0` = 0 | | on XO |
| `GPU_CC_AHB_CLK` CBCR | `0x03d9911c` | 0 | enable clear, CLK_OFF clear: not what Linux's halt model expects (the A16's AHB CBCR did not latch its enable either) |
| `GPU_CC_CX_GMU_CLK` | `0x03d9913c` | `0x80002001` | enable set, CLK_OFF set (domain off) |
| `GPU_CC_CXO_CLK` / `HUB_CX_INT` / `DEMET` | `0x03d99144` / `0x03d99148` / `0x03d9900c` | `0x80000001` / `0x80000001` / `0x1` | enable set; CLK_OFF set on the first two, DEMET (an always-on class) running |
| GCC `GPU_CFG_AHB` | `0x00171004` | `0x1` | **running**: this is why GPUCC answers at all |
| GCC memnoc / axi | `0x00171010` / `0x0017115c` | `0x82000003` / `0x82300003` | enable and hardware clock gating set |
| GCC `GPU_GPLL0_CPH` vote | `0x00152000` bit 15 | 0 | the hub's parent PLL path is not voted |

The firmware's memory map of the unit (231 descriptors, boot 6) covers none of the S1 addresses; the only descriptor below 2 GiB is one type-11 page at `0x0C264000`. The runner's write check
(`ROW_ADDR_TYPE`: a row that writes must be absent from the map or in an I/O descriptor) therefore accepts the S1 rows; it says nothing about whether the firmware uses the word.

## 3. What Linux does, and what S1 does of it

Order of `a6xx_gmu_resume` (a6xx_gmu.c:1322-1360; VERIFIED): `pm_runtime_get_sync(gmu->dev)` (1335: the CX GDSC powers through the device link, 2481) → GX helper (1337) → `clk_set_rate` of
the GMU core and hub clocks (1340-1342) → `clk_bulk_prepare_enable` of the seven GMU clocks (1343) → secure init (not for the X1-85) → DDR bandwidth vote (`a6xx_gmu_set_initial_bw`, 1355) →
firmware start. **The GDSC is first. No vote of any kind precedes it.** The `gpucc` node has no `power-domains` and no `required-opps` (hamoa.dtsi:4225-4234); `gpu_cx_gdsc` has no `supply`, no
`needs_icc` and no `cxcs` (gpucc-x1e80100.c:532-543), so `gdsc_toggle_logic` takes no regulator and no interconnect path and `gdsc_force_mem_on` has nothing to do (gdsc.c:147-198, 233-244).

`gdsc_enable` for this GDSC (gdsc.c:285-341; VERIFIED): (1) `SW_COLLAPSE` cleared in `gdscr` with `regmap_update_bits` (`gdsc_toggle_logic`, 164); (2) `udelay(1)` because `gds_hw_ctrl` is set (188:
the controller "takes around 8 XO cycles" to start); (3) poll the status bit 31 of `0x953c` for up to 2000 µs (`STATUS_POLL_TIMEOUT_US`, 50, 104-125); (4) `udelay(1)` (319); (5) `RETAIN_FF` set
(321-322: already set at hand-off); (6) no HW_CTRL. `gdsc_disable` of a votable GDSC: `SW_COLLAPSE` set, **no status poll**, `udelay(500)` (166-175).

| Linux step | S1 (draft table) | Write? |
|---|---|---|
| GCC `GPU_CFG_AHB` must run (critical CBCR, gcc-x1e80100.c:7451) | row `GCCAHB`: check `0x80000001 → 1` | no |
| gpucc probe parks the GMU and hub RCGs on XO (clk-rcg2.c:1519-1546; the wedge comment 1531-1537) | rows `GMURCG`, `HUBRCG`: check cfg == 0 under `0x71f` | no (already parked) |
| gpucc probe sets the critical CBCR `GPU_CC_CB_CLK` `0x93a4` (gpucc-x1e80100.c:612-618, common.c:317-318) | **not in the table: never read** | unknown: survey, section 6 |
| `gdsc_init` waits, HW_CONTROL, SW_OVERRIDE (gdsc.c:439-453) | found-check of `GDSCR` under `0x00fff807` | no |
| `gdsc_enable`: clear SW_COLLAPSE, 1 µs, poll status ≤ 2 ms | row `CXGDSC`: `mask 1 value 0`, settle 1 µs, read-back `0x953c & 0x80000000 == 0x80000000` within 2000 µs | **yes (the only one)** |
| `clk_bulk_prepare_enable`: `AHB`, `CX_GMU`, `CXO`, `AXI`, `MEMNOC`, `HUB_CX_INT`, `DEMET` (hamoa.dtsi:4184-4197) | rows `AHB`, `CXGMU`, `CXO`, `AXI`, `MEMNOC`, `HUBCX`, `DEMET`: **checks** that the enable is as found and CLK_OFF clears (≤ 200 µs, the CBCR halt poll bound, clk-branch.c:80) | no (enables already set, except AHB: found 0, section 5) |
| `clk_set_rate`: the GMU core request rounds to 220 MHz (PLL1 ÷2); the hub is GCC GPLL0 ÷3 at 200 MHz and needs the `GCC 0x52000` bit 15 vote | **not done**: both RCGs stay on XO | none |
| DDR bandwidth vote, the AOSS ACD message (`{class: gpu, res: acd, val: 1}`), RSC and PDC programming, HFI (the 1.10 handshake applies to a legacy path only) | none | none |

## 4. Dependencies (what must hold for the GDSC to power from EL2)

* **GCC AHB branch running** (OBSERVED, found `0x1`): the GPUCC window answers only while it runs. If it is off the first read of GPUCC hangs the bus (section 8). The table's first row checks it
  and the payload reads no GPUCC word before that row has passed.
* **XO reaching the domain's controller**: the controller counts XO cycles (gdsc.c:188). The CXO branch's enable is set; its CLK_OFF is set only because the domain is off. INFERRED that XO is
  running (the RCGs are on XO and the AHB read answers).
* **RCGs on a live source**: a GDSC can wedge if turned on while an RCG is stuck on a dead source (clk-rcg2.c:1531-1537). Both are on source 0, which is `P_BI_TCXO` in both parent maps. The table
  refuses to write unless both read back as found. S1 does **not** raise the GMU to Linux's 220 MHz or the hub to 200 MHz: that is the next stage's business and a different state of the domain from
  Linux's. **Consequence (UNKNOWN):** the domain is on with XO-rate clocks, which Linux never configures; whether anything in the domain misbehaves is not known.
* **RPMh, AOSS and RSC votes**: Linux issues none before the GDSC (above). The votes it makes afterwards are the DDR bandwidth vote (a6xx_gmu.c:1200-1211, 1355, at the highest OPP) and the AOSS ACD
  message (2087); the RSC and PDC programming is done at probe by `a6xx_gmu_rpmh_init` (2530), and for a7xx the PDC lives in the AOP (700-702). **The CX rail level** is not voted by `gpucc` in Linux
  at the pin: INFERRED to be held by other consumers, and not observable from EL2 (UNKNOWN). The A16 powered its CX GDSC from EL2 with no RPMh or GMU votes after parking the RCGs (OBSERVED, another SoC).
  So: **required for S1 by what Linux does: none; required in fact: UNKNOWN until the dry run and the live run.**
* **The GDSC's own timing**: 1 µs, then ≤ 2000 µs for the status; the table's read-back has the same 2000 µs bound (the runner's ceiling is 100 ms).
* **The display's NoC votes**: the display holds its own interconnect votes through the same fabric the GPU's `GCC_GPU_MEMNOC_GFX` and `GCC_DDRSS_GPU_AXI` branches sit on (hamoa.dtsi:4184-4197 lists them
  among the GMU's clocks). S1 neither adds nor removes any vote and does not write those branches (both found with enable and hardware clock gating set); the table checks them as found. The display is on
  screen during the run (the page), so it keeps running; nothing S1 does is expected to change it, but that is INFERRED, not observed.
* **The GMU's own SMMU mapping**: the GMU firmware image is mapped at GMU IOVA `0x4000` (80,532 of its 81,312 bytes), so a mapping in the GPU SMMU is mandatory before the GMU runs. That is not S1: S1 starts no GMU.
* **RSCC reachable with CX off?** Linux writes RSCC words at probe (`a6xx_gmu_rpmh_init`, a6xx_gmu.c:2530, before any resume). Whether the CX domain is on at that moment on a Linux boot of this unit is not
  established by the files read (UNKNOWN). The first live table does not read the RSCC, the GMU or CX_MISC at all.

## 5. Writes: unavoidable and avoidable

| Candidate write | Verdict | Why |
|---|---|---|
| `GPU_CC_CX_GDSCR` bit 0 cleared (RMW of the whole word, `0x22f801 → 0x22f800`) | **unavoidable** | it is the AP's vote that powers the votable GDSC |
| `GPU_CC_CX_GDSCR` bit 0 set again at the end | **unavoidable** | returns the domain to the state found; the runner proves the word and the status |
| `GPU_CC_AHB_CLK` enable (`0x911c` bit 0) | avoidable for S1 | found 0 and CLK_OFF clear; Linux enables it in the bulk enable. Whether the blocks behind the domain answer with it off is the thing a later table tells; the row is a check that stops on CLK_OFF set |
| CBCR enables of `CX_GMU`, `CXO`, `HUB_CX_INT`, `DEMET`, GCC memnoc and axi | avoidable | already set (found) |
| `GPU_CC_CB_CLK` `0x93a4` enable | UNKNOWN | never read; Linux sets it at probe; the survey reads it |
| GMU and hub RCG reprogramming, PLL0 and PLL1, the GCC `GPU_GPLL0_CPH` vote | avoidable for S1 | Linux needs them to run the GMU at 220 and the hub at 200 MHz; S1 runs nothing |
| RPMh, AOSS (ACD), DDR bandwidth, RSC, PDC | avoidable for S1 | Linux makes none before the GDSC; they are for the stages that start the GMU |
| GPU SMMU clocks (`0x03d97000` HLOS vote, GCC SNOC_DVM `0x00171018`) and any SMMU word | **not S1** | the SMMU may be owned by the hypervisor or the XPU (the IORT says non-coherent; the GMU stream is 5); read-only first |
| CX_MISC `TCM_RET_CNTL` and the rest of the blocks behind the domain | none | S1 does not read them either (section 6) |

## 6. The order of the first runs, and the read-only survey

Six clock-tree entries (seven words) were **never read**, and each is a branch of the domain that may be enabled on a root parked on a dead source, or a gate Linux itself sets at probe: `GPU_CC_CB_CLK` `0x03d993a4` (and its CBCR
enable), `GPU_CC_FF_CLK_SRC` RCG cmd and cfg `0x03d99474`, `0x03d99478` and its branch `GPU_CC_CX_FF_CLK` `0x03d9914c`, `GPU_CC_CRC_AHB_CLK` `0x03d99120`, `GPU_CC_MEMNOC_GFX_CLK` `0x03d99150`, `GPU_CC_SLEEP_CLK`
`0x03d99134`. Also wanted before E3: the GCC `GPLL0` enable and lock and the `GPU_GPLL0_CPH` and `GPU_GPLL0_DIV_CPH` words (the parents the hub RCG could move to), the GPUCC PLL0 and PLL1 `MODE` words, and a
second read of everything in section 2 to measure boot-to-boot variance. All of these lie in the GCC window (`[0x00100000,+0x200000)`) and the GPUCC window (`[0x03d90000,+0xa000)`), which answer
while the GCC AHB branch runs and have been read before. **In order of risk, lowest first:**

1. **The dry run: `gpus1d`** (payload `payloads/gpus1d.c`, table digest `2e2a5adf1552aea2…`, zero stores, no window). It runs the runner's whole machinery on the unit: the `WTAB ATTR` lines, `WTAB OPEN`,
   the four rows (each now waits 1 µs and reads its own word back within 200 µs), the three snapshots, `END RESTORED STORES=0`. It answers: do the boot-30 words read the same again (the table stops on any
   difference: `FOUND`); does the counter count and do the timed polls work; what mapping attribute does the runner report for each page, and for the page of `0x03d99108` above all; does the line budget
   fit the page. **New runner code that has never run on the unit and runs here for the first time:** the counter-based `wait_us` and the timed `poll_match`, the mapping classification through `live_attr`
   in the payload path (the `WTAB ATTR` lines), the `PLATFORM` check at `open`, the ordinary and reserved line accounting, and the `DRAFT` check. The store path, the pre-store SError poll and the
   journal are **not** exercised by a table that writes nothing; the SError poll after each row's read-back is (it is not new).
2. **The survey: the list above as a read-only payload** (a `gpusnap` extension, Linux's own words first, words no Linux code reads last). It changes the draft table by adding one check row per word
   (each with its found value, label OBSERVED); the `draft` list is then emptied by hand, on evidence, never by the tool.
3. **Only then** the live table, as a new table name without `-DRAFT` (a new digest), a note (`tools/sp11_wtab.py note`), and the operator's approval quoting both digests, with the `WTAB ATTR CXGDSC`
   line of the dry run in a film (section 7).
4. **A later table**, separately: the blocks behind the domain (CX_MISC, the GMU, the RSCC), as windows opened only after the domain is verified on; then the SMMU clock votes and the SMMU windows,
   read-only first. The first live table has none of them, because a hang there would leave the domain on with no undo, with the GPUCC AHB branch found off.

What is **not** worth measuring read-only: the CX rail level (not readable from EL2), whether the status bit clears after collapse (needs the write), whether SErrors reach EL2 (needs a fault we do not want).

## 7. The mapping attribute of the page that is written

A store is guarded against a synchronous abort, not against a mapping that makes it behave otherwise: through a cacheable (Normal) mapping a store may stay in the data cache and the read-back succeed
on it, which would prove nothing about the device. So **the runner prints `WTAB ATTR <tag> DEVICE|NORMAL|NONE|UNKNOWN` for every row of every table it opens, check rows included, and refuses
(`ROW_ATTR`) a table in which a row that writes is on a page that is not Device**; an answer the platform cannot give is a refusal. The classification is the survey's own (`stk_attr`: `NONE` no valid
descriptor, `UNKNOWN` a failed walk, then Device or Normal from the descriptor's attribute index), so that the same page gives the same answer in both.

The dry table's `CXGDSC` row checks the very word the live row would store to, so its `WTAB ATTR CXGDSC` line **is the unit's answer for that page**. The live table can be approved only with that line
in a film of the dry run; until then the mapping attribute of the page of `0x03d99108` is UNKNOWN. If it is Normal, the finding is the plan: a Device mapping has to be made before any write, not a
different table.

## 8. What could hang the bus or raise an SError

| Hazard | Mechanism | Defence | What remains |
|---|---|---|---|
| a read of GPUCC while the GCC `GPU_CFG_AHB` branch is off | the access never completes | row 0 checks the branch; the payload reads no GPUCC word before row 2 passed; the host model hangs on a seeded violation | a branch that reads "running" and is not: UNKNOWN |
| a read of CX_MISC, the GMU or the RSCC with the domain off or its AHB path down | bus hang, or an SError | the first live table makes no such read; the model counts one (and fails) | a later table's windows: the runner refuses them until the rows before are done |
| the GDSC wedges because an RCG is on a dead source | the status never sets, or the domain misbehaves | the RCG rows are found-checks under `0x71f` | the unread branches (section 6) |
| the store to `0x03d99108` never completes | hang | the `W` line is printed **before** the store, so the page names it | none: unrecoverable by the guard |
| a store that faults after it wrote | the word is unknown | the row is journaled **before** the store, so the stop reads the word, puts the bits back and proves them | — |
| an SError from the store | the error response arrives after the access | polled before the store (an earlier access's error is not taken for it), right after it and after the read-back; a hit stops the run and undoes | if EL3 routes SErrors away the poll is **blind** (model: `blind.not_seen`) |
| the read-back poll of `0x953c` | none expected (GPUCC is clocked) | bounded 2000 µs, counter-checked | — |
| interrupts of the GPU and GMU (SPI 300, 301, 304, 305) when the domain powers | a spurious interrupt at EL2 | none known; the domain is on for the length of the checks and the snapshot | UNKNOWN: the GIC state at the payload's EL2 |
| the GMU's CM3 core starting by itself with the domain | unknown power-on state of `CM3_SYSRESET` | the payload does not read it; nothing is written | UNKNOWN |
| a payload that takes an exception | no undo runs (`q1n1_fault` halts, or resets after 30 s) | none by the runner: the payload's bytes are reviewed and pinned | the domain stays on until the next power-off |

**Operator rules (the note's hang text).** If the page stops on a `W` line, or on the `NEXT STEP` line before it, the store, its read-back or the pause hung: wait 60 s, hold the power button until the
panel is dark, wait 10 s, power on; **do not run the bundle again**; photograph the last lines and record the last one. A hang on `W 3 CXGDSC` says the GDSC write itself is the hazard (the unit may need
the RPMh path or a different sequence). **After a `C n` line the hang is in row n + 1** (its first read), or in the payload's own reads between two rows (the eight snapshot reads between rows 2 and 3 are not
rows); a stop with no `WTAB` line after `PAYLOAD CALL` is in the open itself (the counter check or the page walk of the first row); after `WTAB OPEN` it is in the first row. INFERRED, never observed on the unit:
a hard power-off returns every register this table touches to its power-on state, which is the state found.

## 9. Abort rules, pre-conditions and exposure

**Run time** (enforced by the runner, [SP11-PAYLOAD-WTAB.md](SP11-PAYLOAD-WTAB.md)): any pre-read fault, any found-state mismatch (including the domain already on, an RCG not parked, the GCC branch off,
the GDSC word's waits not Linux's), a store that faults, an SError before or after the store or after any read-back, a read-back that does not match within its bound, a counter that does not count. On a stop:
the `STOP` line first, then the undo in reverse (**the one write is undone: `SW_COLLAPSE` set, 500 µs, then the status must read clear within 2000 µs**), proof, one `END` line.

On the runtime path Linux does not poll a votable GDSC for OFF (`gdsc_disable` passes `domain->synced_poweroff`, gdsc.c:382; with it set Linux polls; gdsc.c:166-175: the status reflects every master's vote). S1's undo does, on purpose: it is the evidence that the domain really collapsed. If the status stays set
2 ms after the AP withdrew its vote the result is `UNDO_FAILED` with `U 3 FAIL VERIFY` (the control bit itself is verified first and reported separately by the payload's `STATE` line: `CXGD` and `CXST` are
two of its eight snapshot words). That would be a finding (another master holds CX, or the status lags), not a hang; if the survey shows the lag is normal the undo read-back is relaxed to the control word in
the next table version (a new digest).

**Pre-conditions.** The runner has no battery, AC or thermal service, so these are not run-time checks but the **operator's written decisions in the note**, made before the run: AC power connected or the battery
at least 50 %; the thermal state of the unit confirmed by the operator (the survey's temperature readings of the same session are the place to look); no other run on the hardware; the unit not to be used for
anything else until the run ends. The note carries blanks for them and a table that writes is not approved with a blank.

**Exposure, said plainly.** The run can hang the unit or reset it; the recovery is a power cycle (hold the power button, wait, power on). It writes **no storage** (nothing on the internal disk, no firmware
variable, no partition), only the one device word, and its undo puts that word back. What it cannot undo is a hang before the undo, which the power cycle clears, and an exception of the payload, which is
not undone either.

## 10. The tables as data

**Live: `payloads/gpus1.wtab.json`, name `GPUS1-DRAFT`**, digest of the packed blob `a962e8cd26cbfe8d8f0cd1d2b739fcd2ab4d603ac7e3c4d9a03e810edc5c9b66`. Flags `restore_at_end`; pause 8 s before the step that
writes; allowed blocks GCC `[0x00100000,+0x200000)` and GPUCC `[0x03d90000,+0xa000)`; **no window**; 25 ordinary lines (11 of them `WTAB ATTR`) and a reserve of 4, 29 of the 32 the runner allows.

| # | Tag | Step | Address | Kind | Expect found | Read-back | Label |
|---|---|---|---|---|---|---|---|
| 0 | `GCCAHB` | 0 | `0x00171004` | check | `0x80000001 → 0x1` | | OBSERVED |
| 1 | `GMURCG` | 0 | `0x03d9931c` | check | `0x71f → 0` | | OBSERVED |
| 2 | `HUBRCG` | 0 | `0x03d993f0` | check | `0x71f → 0` | | OBSERVED |
| 3 | `CXGDSC` | 1 | `0x03d99108` | **write** mask `1` value `0` (RMW of the word); the run stops (`FOUND`) if the word is already `0` | `0x00fff807 → 0x0022f801` | `0x03d9953c & 0x80000000 == 0x80000000`, settle 1 µs, ≤ 2000 µs; after 1 µs | OBSERVED |
| 4 | `AHB` | 2 | `0x03d9911c` | check | — | `0x03d9911c & 0x80000000 == 0`, ≤ 200 µs | OBSERVED |
| 5 | `CXGMU` | 2 | `0x03d9913c` | check | `1 → 1` | same word, `CLK_OFF` clear, ≤ 200 µs | OBSERVED |
| 6 | `CXO` | 2 | `0x03d99144` | check | `1 → 1` | same, ≤ 200 µs | OBSERVED |
| 7 | `AXI` | 2 | `0x0017115c` | check | `3 → 3` (HALT_SKIP: CLK_OFF says nothing) | | OBSERVED |
| 8 | `MEMNOC` | 2 | `0x00171010` | check | `3 → 3` | | OBSERVED |
| 9 | `HUBCX` | 2 | `0x03d99148` | check | `1 → 1` | same, ≤ 200 µs | OBSERVED |
| 10 | `DEMET` | 2 | `0x03d9900c` | check | `1 → 1` | same, ≤ 200 µs | OBSERVED |

Undo of row 3: `restore` (the bit goes back to what was read just before), wait 500 µs, the word must read back, and `0x03d9953c & 0x80000000 == 0` within 2000 µs. The write row's **effect** is, in the table's own
words, VERIFIED that Linux does this sequence for this GDSC at the pinned revision and UNKNOWN on this unit. The rationale of each row (`why`, `source`, `label`, and for the write the `rmw` argument) is in the JSON.

**Dry: `payloads/gpus1d.wtab.json`, name `GPUS1D`**, digest `2e2a5adf1552aea2eba39f7e1ce4596e9a1158b3b540541adc2a36d3167feee8`: rows 0 to 3 of the live table as checks only (the `CXGDSC` row reads the word the live row
would store to), each with a settle of 1 µs and a read-back of its own word within 200 µs; 9 ordinary lines and a reserve of 2. It reads 32 words in all (each row twice, and the payload's three snapshots of 8).

**Table decisions.** No disable or halt poll on any branch (none is disabled). The RCG rows exist so that the table refuses if either root is not on XO; S1 does not take Linux's
clock configuration. The host-side votes Linux makes are all after the GDSC and none is in S1. The GMU's SMMU mapping, the ACD message, the DDR bandwidth vote and the HFI path are not S1; they are listed so
that the approval of the live table cannot be mistaken for an approval of any of them.

## 11. What is unknown (plainly)

1. Whether the CX GDSC powers from EL2 here with no vote (the A16 says yes on another SoC; Linux makes none before it).
2. Whether the clocks come up by themselves once it does (CLK_OFF clearing within 200 µs is exactly what rows 5, 6, 9 and 10 check), and whether the AHB branch (found 0) is needed for the blocks behind the domain to answer.
3. The CX rail level and whether it holds the domain.
4. Whether the XO-rate configuration of the RCGs, which Linux never uses, is safe for the domain.
5. Whether an SError would be seen at all (EL3 may route it away: the poll is then blind and a bad access is a hang).
6. **The mapping attribute of the page of `0x03d99108`**, until the dry run's `WTAB ATTR CXGDSC` line has been filmed.
7. Whether the GMU, RSCC and CX_MISC words answer before any GMU firmware has run, and what the CM3 core does at power-up (the first live table does not ask).
8. Whether the status bit clears within 2 ms of the undo (Linux does not look).
9. The unread branches of section 6, and the boot-to-boot variance of every found word (one read, one unit).
10. The GPU SMMU's owner (the hypervisor or the XPU?) and whether its clock votes may be written.
11. Whether interrupts of the GPU domain arrive when it powers.

Hardware NOT RUN. What is host-proven (EXPERIMENTAL): the policy checks the base of every store of the payload's code and pins the stores whose offset is a register (a lint: the bytes of the staged payload are reviewed, including the pointer
every `hex`, `puts` and `load32` call is given, and the runner refuses such a pointer outside the stack, the image too for `puts`, when the code runs); the table is accepted by
the runner's rules and by the Python mirror; the model of the domain runs the real runner loop and the real payload: one store, every stop undone, a held vote reported, a hang on the store named by the last
line, a page that is not Device refused, a draft refused by the runner and by the payload. A model is the author's statement of Linux's behaviour; it does not become evidence about the unit.
