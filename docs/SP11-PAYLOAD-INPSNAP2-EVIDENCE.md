<!-- SPDX-License-Identifier: MIT -->
# Payload `inpsnap2`: the evidence behind the table, the pages and the tests

**Status: EXPERIMENTAL; hardware NOT RUN.** This is the companion of [SP11-PAYLOAD-INPSNAP2.md](SP11-PAYLOAD-INPSNAP2.md). It holds what that document cites: the pinned files and their digests (A), every row of the
read table with the line that says so (B), every seeded bug the host test must refuse (C), the pages the host model prints for the cases the document describes (D) and what the QEMU test does and does not show (E).
It is checked against the header, the host model and the module of seeded bugs by `tools/test-q1n1-sp11-payload-inpsnap2-doc.py` and against the pinned copies by `tools/test-q1n1-sp11-payload-inpsnap2-refs.py`.

**VERIFIED** here means a pinned file says so, or a host run shows it; it is never a statement about the unit. **OBSERVED** is a run on the unit: boot 29 (`inputsnap` v1) for five words (`MA0` `SA0`
`CR0` `SE0` `VT0`) and boot 30 (`gpusnap`) for `GV` (`GP0V=0X201`) are the only ones cited, and no run of this payload exists. Everything else about the unit is INFERRED or UNKNOWN.

## A. The pinned files and the ledger

Nine files of the Linux tree at one revision, `7475ea8b58616b33c04afb976cf0fbaad9dd63fb`, each read at `https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/<path>`. Every
digest below was checked against a fresh fetch of the file from that address when the payload was written (all nine matched the copies the other payloads' tests pin); a later check is
`curl -fsSL <address> | shasum -a 256`. The module `tools/sp11_payload_inpsnap2_refs.py` holds the same list and finds the copies on the machine (`INPSNAP2_REFS_DIR`, `GPUSNAP_REFS_DIR`, `INPUTSNAP_REFS_DIR`,
`SNAPINTOSH_DIR`); a test that cannot find a copy SKIPs and says which.

| Prefix | File | Path at the revision | SHA-256 |
| --- | --- | --- | --- |
| `dt` | `hamoa.dtsi` | arch/arm64/boot/dts/qcom/hamoa.dtsi | d5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0 |
| `gcc` | `gcc-x1e80100.c` | drivers/clk/qcom/gcc-x1e80100.c | f1c3779c7bc273dfe170ea2ff4d40f975083ee149e3b02a4f42d5939596eb775 |
| `cbc` | `clk-branch.c` | drivers/clk/qcom/clk-branch.c | d29259eb77a5d1d6a07adf4aa835588f8e04d1fa3c14be2b7d4162cce737abfa |
| `cbh` | `clk-branch.h` | drivers/clk/qcom/clk-branch.h | bac7dcf51a0da5b27eaa0d4dc276f540fec80013bd4862cfbbc115a50161ef72 |
| `cmn` | `common.c` | drivers/clk/qcom/common.c | ebefa181817ee8218b314218bbd94315ba239ff4f816a6565af3ec6aeed14226 |
| `rcg` | `clk-rcg2.c` | drivers/clk/qcom/clk-rcg2.c | b173e0f4d0b962f777c668422f5b1ca22137334b62de766f01f3ef5faf5d93b6 |
| `pll` | `clk-alpha-pll.c` | drivers/clk/qcom/clk-alpha-pll.c | 9a93019436b59ce3020940e0b91615bcaddc233da37951dcf492b2f09a9de433 |
| `gse` | `qcom-geni-se.c` | drivers/soc/qcom/qcom-geni-se.c | f8f7fc2a68e1ac8c927ac7d37c9d901c9aef75ef78f4ccc668ebe0a0ba71825e |
| `gsh` | `geni-se.h` | include/linux/soc/qcom/geni-se.h | 6aab274a8a269605887d426b71022ad018d5b9439f4e5fdfc980041a457c322d |

A citation is `prefix:first-last` (a single line `prefix:line`). The ledger below is the list of ranges the two documents may cite; the refs test holds each range to the text it is said to hold, and every
citation of the documents to a range of this list. A line number moves with the revision: the pinned copies are what the numbers refer to.

| Citation | What the range holds |
| --- | --- |
| `dt:758-760` | the `gcc` clock controller node: `reg = <0 0x00100000 0 0x200000>` |
| `dt:2141-2148` | the `qupv3_0` node: `reg = <0 0x00bc0000 0 0x2000>`, clocks `GCC_QUPV3_WRAP_0_M_AHB_CLK` and `GCC_QUPV3_WRAP_0_S_AHB_CLK` named `m-ahb` and `s-ahb` |
| `dt:2337-2343` | the `uart2` node: `reg = <0 0x00b88000 0 0x4000>`, `GIC_SPI 584`, clock `GCC_QUPV3_WRAP0_S2_CLK` |
| `gcc:113-127` | `gcc_gpll0`: offset 0, Lucid-OLE, vote word `0x52030` bit 0, the fixed ops |
| `gcc:130-150` | the OUT_EVEN post divider table and `post_div_shift = 10` of GPLL0 |
| `gcc:1142-1153` | the s2 frequency table: 64 MHz is GPLL0 OUT_EVEN with M/N 16/75; 200 MHz is GPLL0 OUT_MAIN divided by 3 |
| `gcc:1165-1172` | `gcc_qupv3_wrap0_s2_clk_src`: `cmd_rcgr = 0x42288`, `mnd_width = 16`, `hid_width = 5` |
| `gcc:2237-2250` | `gcc_qupv3_wrap0_s2_div_clk_src`: register `0x42284`, shift 0, width 4, read-only divider ops |
| `gcc:4336-4358` | the wrapper's two core clocks: halt `0x23018` vote bit 9 and halt `0x23008` vote bit 8, both in `0x52020` |
| `gcc:4434-4450` | `gcc_qupv3_wrap0_s2_clk`: halt `0x42274`, voted, vote bit 12 of `0x52020` |
| `gcc:4954-4982` | the wrapper's two AHB clocks: halt `0x23000` and `0x23004`, hardware gating bit 1 of the same word, vote bits 6 and 7 of `0x52020` |
| `gcc:7409-7412` | the DFS clock list holds the s2 root clock generator |
| `gcc:7468-7469` | the descriptor hands that list to the common code (`dfs_rcgs`) |
| `cmn:394-400` | the common code registers the DFS candidates |
| `cbc:17-27` | a branch is in hardware gating mode when its `hwcg_reg` bit is set |
| `cbc:43-60` | how the halt word is judged: CLK_OFF, or the NoC FSM status equal to the "on" value |
| `cbc:62-74` | the wait for a branch is skipped for a branch in hardware gating mode |
| `cbh:63-65` | CLK_OFF is bit 31, the FSM status bits 30:28, "on" is 2 |
| `rcg:26-47` | the generator's command, configuration, M, N and D offsets (0, 4, 8, 0xc, 0x10) and masks |
| `rcg:54-60` | the DFS constants: 8 levels, the DFS word at `cmd + 0x14` (bit 0 enables), the level words at `+ 0x1c`, `+ 0x5c`, `+ 0x9c` for each level `+ 4 l` |
| `rcg:67-77` | a generator is enabled when `CMD_ROOT_OFF` is clear |
| `rcg:193-227` | the rate from the configuration, M and N words (N stored inverted) |
| `rcg:1606-1650` | the level words read for each DFS level (configuration, M, N inverted) |
| `rcg:1688-1731` | the current level is bits 4:1 of the DFS word |
| `rcg:1743-1766` | the DFS flag: `cmd + 0x14`, bit 0 set makes the generator a DFS clock, clear leaves it plain |
| `rcg:1770-1781` | the registration walks every candidate and applies that test |
| `pll:16-34` | the mode word's bits: output control 0, reset 2, vote FSM 20, active flag 30, lock detect 31 |
| `pll:36-45` | the L value, alpha value and user control words; the post divider shift 8 and alpha enable bit 24 |
| `pll:62-63` | the status and opmode word macros |
| `pll:187-202` | the Lucid-OLE layout: opmode `+ 4`, state `+ 8`, status `+ 0xc`, L `+ 0x10`, alpha `+ 0x14`, user control `+ 0x18` |
| `pll:348-349` | the opmode values: standby 0, run 1 |
| `pll:396-412` | the wait for a PLL polls its mode word |
| `pll:428-429` | the wait for the lock tests the lock detect bit |
| `pll:719-750` | the rate from L, alpha and the user control word |
| `pll:1078-1089` | a PLL is enabled when its opmode says run and its mode word has the output enabled |
| `gse:188` | `QUPV3_HW_VER_REG` is at `0x4` of the wrapper |
| `gse:299-310` | the wrapper's version is read with one 32-bit load from `base + 4` |
| `gsh:336-344` | the version fields: major bits 31:28, minor 27:16, step 15:0 |

## B. The 44 rows

One row per word of the table of `payloads/inpsnap2-regs.h`, in page order: the block it is announced in, the key the page prints, the window, the offset in the window, the flags (a branch clock word `CBCR`, a
clock with a hardware gating bit `HWCG`, a word the wrapper's gate depends on `WRAP`; for a hardware-gated clock the bit of `VT0` that is the apps' vote), the pinned source, and what the word is. The test holds
the first five columns to the header and reads the rest of the rows back from the pinned files by name. All of them are VERIFIED as read in the files cited; none was ever read by this payload on the unit.
The 41 words of the host plan's I0 list (`python3 tools/geni_uart_plan.py reads`) are every row but the first three (`MA0` `SA0` `CR0`, the wrapper's gate).

| Block | Key | Window | Offset | Flags | Source | What it is |
| --- | --- | --- | --- | --- | --- | --- |
| GATE | `MA0` | GCC | `0x23000` | CBCR HWCG WRAP, vote bit 6 | `gcc:4954-4982`, `cbc:17-27` | the wrapper's M-AHB clock branch word (hardware gating bit 1 in the same word) |
| GATE | `SA0` | GCC | `0x23004` | CBCR HWCG WRAP, vote bit 7 | `gcc:4954-4982`, `cbc:17-27` | the wrapper's S-AHB clock branch word (same layout) |
| GATE | `CR0` | GCC | `0x23008` | CBCR WRAP | `gcc:4336-4358` | the wrapper's core clock branch word (voted, bit 8 of `VT0`) |
| GATE | `SE0` | GCC | `0x42274` | CBCR | `gcc:4434-4450` | the engine's own clock `gcc_qupv3_wrap0_s2_clk` branch word (voted, bit 12 of `VT0`) |
| GATE | `VT0` | GCC | `0x52020` | - | `gcc:4336-4358`, `gcc:4434-4450`, `gcc:4954-4982` | the apps' vote word of the wrapper's clocks: bits 6, 7, 8 and 12 |
| GATE | `GV` | GCC | `0x52030` | - | `gcc:113-127` | GPLL0's apps vote word, bit 0 |
| RCG | `DFS` | GCC | `0x4229c` | - | `rcg:54-60`, `rcg:1743-1766`, `rcg:1688-1731` | the s2 generator's DFS word, `cmd_rcgr + 0x14`: bit 0 the DFS flag, bits 4:1 the current level |
| RCG | `DIV` | GCC | `0x42284` | - | `gcc:2237-2250` | the read-only divider below the generator (4 bits at shift 0) |
| RCG | `CMD` | GCC | `0x42288` | - | `gcc:1165-1172`, `rcg:26-47`, `rcg:67-77` | the generator's command word `cmd_rcgr` (bit 31 ROOT_OFF) |
| RCG | `CFG` | GCC | `0x4228c` | - | `rcg:26-47`, `rcg:193-227` | the configuration word, `cmd + 4`: source, pre-divider, mode |
| RCG | `M` | GCC | `0x42290` | - | `rcg:26-47`, `rcg:193-227` | the M word, `cmd + 8` |
| RCG | `N` | GCC | `0x42294` | - | `rcg:26-47`, `rcg:193-227` | the N word, `cmd + 0xc`, stored inverted |
| RCG | `D` | GCC | `0x42298` | - | `rcg:26-47` | the D word, `cmd + 0x10` |
| PLL | `MODE` | GCC | `0x0` | - | `pll:16-34`, `pll:396-412`, `pll:428-429`, `gcc:113-127` | GPLL0's mode word: output control, reset, vote FSM, active flag, lock detect |
| PLL | `OP` | GCC | `0x4` | - | `pll:187-202`, `pll:348-349`, `pll:1078-1089` | GPLL0's opmode word: standby 0, run 1 |
| PLL | `ST` | GCC | `0xc` | - | `pll:62-63`, `pll:187-202` | GPLL0's status word |
| PLL | `L` | GCC | `0x10` | - | `pll:36-45`, `pll:187-202`, `pll:719-750` | GPLL0's L value |
| PLL | `AL` | GCC | `0x14` | - | `pll:36-45`, `pll:187-202`, `pll:719-750` | GPLL0's alpha value |
| PLL | `USR` | GCC | `0x18` | - | `pll:36-45`, `pll:187-202`, `pll:719-750`, `gcc:130-150` | GPLL0's user control word (alpha enable, the post divider shift of the output) |
| LVL | `LC0` | GCC | `0x422a4` | - | `rcg:54-60`, `rcg:1606-1650` | level 0 configuration word, `cmd + 0x1c` |
| LVL | `LC1` | GCC | `0x422a8` | - | `rcg:54-60`, `rcg:1606-1650` | level 1 configuration word |
| LVL | `LC2` | GCC | `0x422ac` | - | `rcg:54-60`, `rcg:1606-1650` | level 2 configuration word |
| LVL | `LC3` | GCC | `0x422b0` | - | `rcg:54-60`, `rcg:1606-1650` | level 3 configuration word |
| LVL | `LC4` | GCC | `0x422b4` | - | `rcg:54-60`, `rcg:1606-1650` | level 4 configuration word |
| LVL | `LC5` | GCC | `0x422b8` | - | `rcg:54-60`, `rcg:1606-1650` | level 5 configuration word |
| LVL | `LC6` | GCC | `0x422bc` | - | `rcg:54-60`, `rcg:1606-1650` | level 6 configuration word |
| LVL | `LC7` | GCC | `0x422c0` | - | `rcg:54-60`, `rcg:1606-1650` | level 7 configuration word |
| LVL | `LM0` | GCC | `0x422e4` | - | `rcg:54-60`, `rcg:1606-1650` | level 0 M word, `cmd + 0x5c` |
| LVL | `LM1` | GCC | `0x422e8` | - | `rcg:54-60`, `rcg:1606-1650` | level 1 M word |
| LVL | `LM2` | GCC | `0x422ec` | - | `rcg:54-60`, `rcg:1606-1650` | level 2 M word |
| LVL | `LM3` | GCC | `0x422f0` | - | `rcg:54-60`, `rcg:1606-1650` | level 3 M word |
| LVL | `LM4` | GCC | `0x422f4` | - | `rcg:54-60`, `rcg:1606-1650` | level 4 M word |
| LVL | `LM5` | GCC | `0x422f8` | - | `rcg:54-60`, `rcg:1606-1650` | level 5 M word |
| LVL | `LM6` | GCC | `0x422fc` | - | `rcg:54-60`, `rcg:1606-1650` | level 6 M word |
| LVL | `LM7` | GCC | `0x42300` | - | `rcg:54-60`, `rcg:1606-1650` | level 7 M word |
| LVL | `LN0` | GCC | `0x42324` | - | `rcg:54-60`, `rcg:1606-1650` | level 0 N word, `cmd + 0x9c`, stored inverted |
| LVL | `LN1` | GCC | `0x42328` | - | `rcg:54-60`, `rcg:1606-1650` | level 1 N word |
| LVL | `LN2` | GCC | `0x4232c` | - | `rcg:54-60`, `rcg:1606-1650` | level 2 N word |
| LVL | `LN3` | GCC | `0x42330` | - | `rcg:54-60`, `rcg:1606-1650` | level 3 N word |
| LVL | `LN4` | GCC | `0x42334` | - | `rcg:54-60`, `rcg:1606-1650` | level 4 N word |
| LVL | `LN5` | GCC | `0x42338` | - | `rcg:54-60`, `rcg:1606-1650` | level 5 N word |
| LVL | `LN6` | GCC | `0x4233c` | - | `rcg:54-60`, `rcg:1606-1650` | level 6 N word |
| LVL | `LN7` | GCC | `0x42340` | - | `rcg:54-60`, `rcg:1606-1650` | level 7 N word |
| QUP | `VER` | QUP | `0x4` | - | `gse:188`, `gse:299-310`, `gsh:336-344` | the wrapper's version word: major 31:28, minor 27:16, step 15:0 |

Not read, by construction: the wrapper's core 2x clock (`gcc:4336-4358`, halt `0x23018`, not needed by the gate), the divider's neighbours, any engine register (`dt:2337-2343`: the engine lies at `0x00b88000`, below the
wrapper's page), any word of the second wrapper, and every word that could change when read.

## C. The seeded bugs

Every defect below is an exact once-only replacement in the payload or its header (a needle that is not in the text exactly once is an error, never a pass). The host test, built over the mutated text, must
refuse it, name the stage that does and say the reason the module records: the stage is the native host test (harness) unless noted, the same test at a smaller line or load cap (caps), the compiler's static assertions
(build), the IR audit (audit), the policy on the linked binary (binary) or the stack check (stack). The audit and binary defects are never run natively: some of them store to a device address. A name that ends in
an upper-case key or a number stands for one defect per row or per line of the table, listed as a template: row-offset-&lt;KEY&gt; is one defect for each of the 44 keys, line-end-&lt;N&gt; one for each of the 13 lines.
The module (tools/sp11_payload_inpsnap2_mutants.py and tools/sp11_payload_inpsnap2_mutants_more.py) holds the text of each; the document test holds this list to it, name for name.

**The table, generated from the header.** A row's offset one word later, its printed key changed, its block moved on: `row-offset-<KEY>`, `row-key-<KEY>`, `row-block-<KEY>`. One row of each block and
of the wrapper moved to the other window: `row-window-MA0`, `row-window-VT0`, `row-window-DFS`, `row-window-MODE`, `row-window-LM3`, `row-window-VER`. A flag dropped or added: `flag-clock-dropped-MA0`,
`flag-clock-dropped-SA0`, `flag-clock-dropped-CR0`, `flag-clock-dropped-SE0`, `flag-clock-added-VT0`, `flag-clock-added-GV`, `flag-clock-added-CMD`, `flag-clock-added-VER`, `flag-hwcg-dropped-MA0`,
`flag-hwcg-dropped-SA0`, `flag-hwcg-added-CR0`, `flag-hwcg-added-SE0`, `flag-wrapper-dropped-MA0`, `flag-wrapper-dropped-SA0`, `flag-wrapper-dropped-CR0`, `flag-wrapper-added-SE0`,
`flag-wrapper-added-VT0`. A vote bit that is not the pinned one: `vote-bit-of-MA0-is-7`, `vote-bit-of-MA0-is-5`, `vote-bit-of-SA0-is-6`, `vote-bit-of-SA0-is-8`, `vote-bit-set-on-CR0`. A line that takes one row too
few, is announced under the next block or prints a changed head: `line-end-<N>`, `line-block-<N>`, `line-head-<N>`.

**The windows.** `gcc-window-base-moved`, `qup-window-base-moved`, `qup-window-is-the-engine`, `gcc-window-size-halved`, `qup-window-size-doubled`, `windows-in-the-other-order`, `window-names-swapped`.

**The text of the page.** Block heads renamed: `block-head-gate-renamed`, `block-head-rcg-renamed`, `block-head-pll-renamed`, `block-head-lvl-renamed`, `block-head-qup-renamed`. The prefix, the header and the
legend: `prefix-loses-the-version-digit`, `header-says-stage-i1`, `header-says-el-1`, `header-caps-swapped`, `header-caps-separator`, `header-line-lost`, `legend-line-lost`, `legend-says-clk`,
`legend-forgets-the-check`, `next-has-a-colon`, `next-names-the-block-before`. The end line: `end-says-load`, `end-says-fault`, `end-says-skip`, `end-says-blocks`, `end-says-cut`, `end-says-line`,
`end-says-stopped`, `end-says-no-for-none`, `end-lines-without-itself`, `end-loads-is-the-lines`, `end-blocks-in-decimal`, `end-stop-names-the-next-row`, `end-stop-blocks-not-marked`,
`end-stop-leaves-its-own-block`. A word, its verdict and its check: `k-label-changed`, `k-label-dropped`, `k-check-shifted`, `key-and-value-run-together`, `equals-is-a-colon`, `on-says-ok`, `off-says-of`,
`hw-says-hc`, `odd-says-od`, `fault-has-an-equals`, `fault-code-not-printed`, `skip-says-skipped`, `budget-says-budge`, `na-says-n-a`, `no-verdict-on-any-clock`, `verdict-on-every-word`, `put-row-ignores-hwcg`,
`numbers-all-decimal`. The texts of the gate and of the early exits: `gate-off-says-gate-off-text`, `gate-err-says-gate-err-text`, `gate-texts-swapped`, `not-at-el2-text`, `no-load32-text`.

**The helpers that build a line.** Decimal: `dec-prints-nothing-for-zero`, `dec-radix-nine`, `dec-overruns-a-full-line`. Number: `num-hex-from-nine`, `num-decimal-to-ten`, `num-always-hex`. Hex of the runner's op:
`hx-gives-the-op-one-byte-less`, `hx-gives-the-op-one-byte-more`, `hx-forgets-the-length`. The check's digits: `hex4-in-lower-case`, `hex4-three-digits`, `hex4-seven-bits-a-digit`, `hex4-overruns-a-full-line`.

**The line cap.** `room-takes-the-closing-slot`, `room-spares-one-line-too-many`, `closing-line-ignores-the-cap`, `closing-line-one-past-the-cap`, `a-cut-line-is-not-counted`, `a-cut-line-is-printed-anyway`,
`a-printed-line-is-not-counted`; at a smaller cap (caps): `room-is-always-there`, `end-line-takes-the-room-of-a-line`, `next-line-may-take-the-closing-slot`.

**The check of a line.** `crc-starts-from-zero`, `crc-polynomial-8005`, `crc-polynomial-1020`, `crc-tests-bit-14`, `crc-byte-enters-at-bit-7`, `crc-eight-steps-become-seven`, `crc-skips-the-state-byte`,
`crc-state-byte-is-zero`, `crc-value-big-endian`, `crc-three-value-bytes`, `crc-leaves-the-first-word-out`, `crc-leaves-the-last-word-out`, `crc-takes-the-first-word-of-the-line-for-all`,
`crc-is-not-reset-between-words`.

**The read primitive and the states of a row.** The load cap (caps): `load-cap-not-enforced`, `load-cap-one-too-many`. Loads: `loads-not-counted`, `load-value-is-lost`, `load-fault-code-is-lost`,
`load-is-tried-again-after-an-abort`, `load-address-is-the-window-base`, `load-address-is-the-offset`, `load-address-is-the-sum-of-the-bases`. The row and its window: `row-id-unchecked`,
`row-id-one-past-the-table`, `row-block-always-the-first`, `row-window-always-the-clock-controller`, `window-index-unchecked`, `offset-alignment-unchecked`, `offset-range-unchecked`,
`offset-range-one-word-late`, `offset-range-of-the-first-window`. The all-ones word and the abort: `all-ones-word-does-not-stop-the-reads`, `an-abort-does-not-stop-its-block`, `an-abort-stops-every-block`,
`an-abort-stops-the-next-block`, `an-abort-is-not-remembered`, `zero-word-stops-the-page`, `all-ones-word-never-stops-the-page`, `top-bit-word-stops-the-page`, `stop-names-the-row-before`. The state a row ends
in: `an-abort-leaves-no-state`, `an-abort-leaves-no-code`, `an-abort-is-not-counted`, `an-abort-does-not-flag-its-block`, `a-skip-is-not-counted`, `a-skip-does-not-flag-its-block`, `a-spent-budget-is-a-skip`,
`a-spent-budget-does-not-flag-its-block`, `a-read-word-is-not-kept`.

**The verdict of a branch clock word.** `clock-all-ones-has-a-verdict`, `clock-polarity-inverted`, `clock-fsm-on-is-one`, `clock-fsm-status-ignored`, `clock-fsm-status-from-bit-27`, `clock-hw-flag-ignored`,
`clock-hw-without-the-hw-control-bit`, `clock-hw-control-is-bit-0`.

**The wrapper's gate** (each is refused for the cell of the exhaustive matrix it gets wrong). Unknown, stopped and running: `gate-an-unread-word-is-fine`, `gate-an-unread-word-is-a-stopped-clock`,
`gate-unknown-before-off`, `gate-unknown-is-off`, `gate-off-is-unknown`, `gate-a-stopped-clock-does-not-gate`, `gate-an-all-ones-clock-does-not-gate`, `gate-anything-but-on-is-off`. Hardware gating and the
vote: `gate-hardware-gating-is-running`, `gate-hardware-gating-with-no-vote-word-is-stopped`, `gate-hardware-gating-with-a-clear-vote-is-unknown`, `gate-hardware-gating-with-a-set-vote-is-unknown`,
`gate-vote-bit-is-bit-zero`, `gate-vote-bit-is-the-neighbours`, `gate-vote-word-is-the-gpll0-vote`, `gate-a-zero-vote-word-is-fine`, `gate-an-all-ones-vote-word-is-fine`,
`gate-the-vote-word-is-not-asked-for`. Which rows count: `gate-every-row-counts`, `gate-never-sees-hardware-gating`, `gate-every-clock-may-be-hardware-gated`.

**Blocks and lines.** The wrapper's block: `wrapper-read-without-the-gate`, `wrapper-read-behind-the-closed-gate-only`, `wrapper-gated-block-is-not-flagged`, `wrapper-announce-result-ignored`,
`wrapper-announce-failure-is-not-flagged`, `wrapper-is-announced-after-a-stop`. The others: `block-is-announced-after-a-stop`, `block-announce-result-ignored`, `block-announce-failure-is-not-flagged`,
`lines-go-on-after-a-stop`, `every-block-prints-every-line`, `a-block-prints-the-lines-up-to-it`. A line: `line-without-room-is-read`, `line-without-room-is-not-counted`,
`line-without-room-does-not-flag-its-block`, `line-reads-one-row-less`, `line-reads-one-row-more`, `line-prints-one-row-less`, `line-head-is-not-printed`, `line-prefix-is-not-printed`.

**The entry.** `exception-level-not-checked`, `exception-level-compared-with-one`, `exception-level-field-from-bit-1`, `exception-level-is-read-twice`, `another-register-is-read`,
`missing-load32-not-checked`, `missing-load32-is-a-success`, `below-el2-is-an-error`, `arguments-not-checked`, `entry-returns-one`, `last-block-is-not-read`, `first-block-is-not-read`,
`wrapper-is-read-first`.

**The compiler's static assertions (build).** `load-cap-below-the-table`, `line-cap-below-the-page`, `packed-line-too-short`, `a-row-more`, `a-register-row-of-17-bytes`, `a-word-record-of-12-bytes`,
`a-window-that-is-not-whole-words`, `a-line-row-of-20-bytes`.

**The compiled code (audit, binary, stack).** The IR audit refuses: `a-word-is-read-without-the-guard`, `a-word-is-stored-to-the-device`, `a-word-is-stored-to-the-wrapper`, `the-arguments-are-written`,
`a-pointer-is-kept-in-memory`, `the-context-is-cleared-by-a-libcall`, `a-global-counts-the-loads`, `the-loads-are-counted-atomically`. The policy of the linked binary refuses:
`a-word-is-stored-to-the-device-in-the-binary`, `a-word-is-loaded-without-the-guard-in-the-binary`, `the-arguments-are-written-in-the-binary`, `a-secure-monitor-call`, `a-data-barrier`,
`an-instruction-barrier`, `the-counter-frequency-is-read`, `the-counter-is-read`, `a-system-register-is-written`, `a-translation-is-requested`, `the-cpu-waits-for-an-interrupt`, `a-hypervisor-call`. The stack
check refuses `a-frame-larger-than-the-stack-allows`.

**Defences with no seeded bug of their own.** A second line of defence that a first one makes unreachable at the shipped table (a line's own check of the room behind the room test of its caller), the width of
the check's mask (only its low sixteen bits are ever shown) and the vote check of the gate behind its zero test (the vote word of zeros is refused before it is asked for a bit). The host test calls each of the
first and the last on its own; the middle one changes nothing observable.

## D. The pages of the cases

The pages the host model prints for its fixtures: **not the unit's pages**. The fixture's values are made up, except the five words boot 29 found (`MA0=0.ON SA0=0.ON CR0=0X4000.ON SE0=0X80004000.OFF
VT0=0X810223D0`, OBSERVED, one unit), which the fixture reuses. Each excerpt is a run of lines of the page of its scenario (`--scenario <name>` of the host test) in order, and the test checks it so.
The full nominal page is in [the main document](SP11-PAYLOAD-INPSNAP2.md), section 2.

**`gateoff`: a wrapper clock that reads stopped.** `MA0` reads `0X80000000` (CLK_OFF set, no hardware gating bit): the wrapper's version word is not read.

<!-- gateoff-lines -->
```
PAYLOAD INPSNAP2 GATE MA0=0X80000000.OFF SA0=0.ON CR0=0X4000.ON K=B12C
PAYLOAD INPSNAP2 NEXT QUP
PAYLOAD INPSNAP2 QUP GATED OFF
PAYLOAD INPSNAP2 END LOADS=43 FAULTS=0 SKIPS=0 BLK=0X10 CUTS=0 LINES=21 STOP=NONE
```
<!-- /gateoff-lines -->

**`gateerr`: a vote word of zeros.** `VT0` reads 0: a window of zeros would show every branch as running, so the gate cannot trust the three clock words: `GATED ERR`, not `GATED OFF`.

<!-- gateerr-lines -->
```
PAYLOAD INPSNAP2 GATE MA0=0.ON SA0=0.ON CR0=0X4000.ON K=3886
PAYLOAD INPSNAP2 GATE SE0=0X80004000.OFF VT0=0 GV=1 K=80E5
PAYLOAD INPSNAP2 NEXT QUP
PAYLOAD INPSNAP2 QUP GATED ERR
PAYLOAD INPSNAP2 END LOADS=43 FAULTS=0 SKIPS=0 BLK=0X10 CUTS=0 LINES=21 STOP=NONE
```
<!-- /gateerr-lines -->

**`hwvote`: a hardware-gated AHB clock whose vote bit is clear.** `MA0` reads `0X80000002` (CLK_OFF set, hardware gating bit set: `.HW`) and bit 6 of `VT0` is clear (`0X81022390`): the clock is not running.

<!-- hwvote-lines -->
```
PAYLOAD INPSNAP2 GATE MA0=0X80000002.HW SA0=0.ON CR0=0X4000.ON K=47EE
PAYLOAD INPSNAP2 GATE SE0=0X80004000.OFF VT0=0X81022390 GV=1 K=2ED7
PAYLOAD INPSNAP2 NEXT QUP
PAYLOAD INPSNAP2 QUP GATED OFF
PAYLOAD INPSNAP2 END LOADS=43 FAULTS=0 SKIPS=0 BLK=0X10 CUTS=0 LINES=21 STOP=NONE
```
<!-- /hwvote-lines -->

**`stop`: an all-ones word.** The divider reads `0XFFFFFFFF`: the page ends after its line, the rest of the line prints `SKIP`, nothing after it is read or printed, and `END` names the key and the blocks not read whole.

<!-- stop-lines -->
```
PAYLOAD INPSNAP2 RCG DFS=0 DIV=0XFFFFFFFF CMD=SKIP CFG=SKIP K=1F79
PAYLOAD INPSNAP2 END LOADS=8 FAULTS=0 SKIPS=2 BLK=0X1E CUTS=0 LINES=8 STOP=DIV
```
<!-- /stop-lines -->

**`fault`: an abort in a level word.** The load of `LC2` aborts (`FAULT:6`): the rest of the level block prints `SKIP` (21 words), the other blocks, the wrapper's version included, go on.

<!-- fault-lines -->
```
PAYLOAD INPSNAP2 LVL LC0=0X2601 LC1=0X2602 LC2=FAULT:6 LC3=SKIP K=78C2
PAYLOAD INPSNAP2 LVL LN4=SKIP LN5=SKIP LN6=SKIP LN7=SKIP K=1455
PAYLOAD INPSNAP2 NEXT QUP
PAYLOAD INPSNAP2 QUP VER=0X20050000 K=60CA
PAYLOAD INPSNAP2 END LOADS=23 FAULTS=1 SKIPS=21 BLK=8 CUTS=0 LINES=21 STOP=NONE
```
<!-- /fault-lines -->

Two more fixtures print one line each: `el1` (below EL2: `SKIPPED_NOT_AT_EL2`, nothing read) and `noload32` (the runner gave no guarded load: `REFUSED_NO_LOAD32`, nothing read). A seventh, `dfs`, is the nominal page with
`DFS=7` (flag set, level 3), the page the host parser's round trip uses for a DFS clock.

## E. What the QEMU test shows

`tools/test-q1n1-sp11-payload-qemu-inpsnap2.py` runs the built binary behind the runner at EL2 under QEMU with the EDK2 firmware of the other payload tests, alone and after the `state` payload, and
re-derives the page's rules in its own code (the check with `binascii.crc_hqx`, the clock verdict, the wrapper's gate, the counters) from the words the page printed. With `SNAPINTOSH_DIR` set it also hands the
page the real binary printed to the host parser (`tools/sp11_inpsnap2_parse.py` of the Snapintosh tree), which must accept it and read the same words. It SKIPs, never passes, without QEMU or
the firmware (the parser test also SKIPs without that tree). What it shows: the binary loads and verifies behind the runner, runs at EL2, prints a page of the structure above and returns the runner's code. What it does **not** show: any word of the unit. On
QEMU's `virt` machine both windows lie in the firmware's flash, so every word is the flash's (arbitrary, and an all-ones word may end the page, which the test accepts as a stop page); an abort on a real bus
and the runner's guard on the Oryon core are not exercised either. Hardware: NOT RUN.
