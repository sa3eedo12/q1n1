<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `inputsnap`: the register table, the words Linux reads, and the reference copies

The register-level companion of [SP11-PAYLOAD-INPUTSNAP.md](SP11-PAYLOAD-INPUTSNAP.md), which has what the payload reads and why, the page, what every token means, the safety rules and the
tests. It is a document of its own so that both stay under the size limit of the documents of this tree. Evidence labels as there (VERIFIED is a pinned file; nothing here was ever read on
the unit by this payload: EXPERIMENTAL, hardware NOT RUN).

## The register table

Every word the payload reads, in page order. `U2/S10` rows are read in both engines, `X U2/X S10` rows in both late blocks; a row in a late block is a word no pinned driver reads
([Which words Linux reads](#which-words-linux-reads)); `Read in S2` is whether snapshot 2 reads it again (the SPI engine has no snapshot-2 reads, and the late words none).
The test `python3 tools/test-q1n1-sp11-payload-inputsnap.py` holds this table to `payloads/inputsnap-regs.h` row for row, and every citation to the ledger of the pinned copies.

| Block | Key | Offset | Word | Read in S2 | Source |
|---|---|---|---|---|---|
| GCC | `MA0` | `0x23000` | qupv3_wrap_0_m_ahb (gates U2) | yes | gcc:4955-4961 cb:63 |
| GCC | `SA0` | `0x23004` | qupv3_wrap_0_s_ahb (gates U2) | yes | gcc:4970-4976 |
| GCC | `CR0` | `0x23008` | qupv3_wrap0_core (gates U2) | yes | gcc:4350-4354 |
| GCC | `SE0` | `0x42274` | qupv3_wrap0_s2 (uart2) (gates U2) | yes | gcc:4435-4439 |
| GCC | `C20` | `0x23018` | qupv3_wrap0_core_2x | yes | gcc:4337-4341 |
| GCC | `MA1` | `0x23150` | qupv3_wrap_1_m_ahb (gates S10) | yes | gcc:4985-4991 |
| GCC | `SA1` | `0x23154` | qupv3_wrap_1_s_ahb (gates S10) | yes | gcc:5000-5006 |
| GCC | `CR1` | `0x23158` | qupv3_wrap1_core (gates S10) | yes | gcc:4556-4560 |
| GCC | `SE1` | `0x18274` | qupv3_wrap1_s2 (spi10) (gates S10) | yes | gcc:4641-4645 |
| GCC | `QS1` | `0x18280` | qupv3_wrap1_qspi_s2 (gates S10) | yes | gcc:4569-4573 |
| GCC | `C21` | `0x23168` | qupv3_wrap1_core_2x | yes | gcc:4543-4547 |
| GCC | `VT0` | `0x52020` | vote word of wrapper 0 | - | gcc:4337-4341 |
| GCC | `VT1` | `0x52008` | vote word of wrapper 1 | - | gcc:4543-4547 |
| GCC | `VT2` | `0x52028` | vote word of the QSPI clock | - | gcc:4569-4573 |
| GIC | `CTL` | `0x0` | GICD_CTLR | - | gic:13-14 gic:60-63 |
| GIC | `TYP` | `0x4` | GICD_TYPER | - | gic:13-14 |
| GIC | `E616` | `0x14c` | ISENABLER of INTID 616 | - | gic:22-25 gic3:456-469 |
| GIC | `P616` | `0x24c` | ISPENDR of INTID 616 | - | gic:22-25 gic3:456-469 |
| GIC | `C616` | `0xc98` | ICFGR of INTID 616 | - | gic:30 gicc:51-52 |
| GIC | `E834` | `0x168` | ISENABLER of INTID 834 | - | gic:22-25 gic3:456-469 |
| GIC | `P834` | `0x268` | ISPENDR of INTID 834 | - | gic:22-25 gic3:456-469 |
| GIC | `C834` | `0xcd0` | ICFGR of INTID 834 | - | gic:30 gicc:51-52 |
| GIC | `E240` | `0x11c` | ISENABLER of INTID 240 | - | gic:22-25 gic3:456-469 |
| GIC | `P240` | `0x21c` | ISPENDR of INTID 240 | - | gic:22-25 gic3:456-469 |
| GIC | `C240` | `0xc3c` | ICFGR of INTID 240 | - | gic:30 gicc:51-52 |
| U2/S10 | `FW` | `0x68` | FW_REVISION_RO: protocol in 15:8 | - | gse:87-92 gse:180-181 |
| U2/S10 | `IFD` | `0x64` | IF_DISABLE_RO | - | gse:87-92 |
| U2/S10 | `ST` | `0x40` | STATUS: M bit 0, S bit 12 | yes (U2) | gse:87-92 gse:168-169 |
| U2/S10 | `DMA` | `0x258` | DMA_MODE_EN | - | gse:96 |
| U2/S10 | `TXF` | `0x800` | TX_FIFO_STATUS: count in 27:0 | yes (U2) | gse:115-120 gse:272 |
| U2/S10 | `RXF` | `0x804` | RX_FIFO_STATUS: count in 24:0 | yes (U2) | gse:115-120 gse:278 |
| U2/S10 | `MIS` | `0x610` | M_IRQ_STATUS | yes (U2) | gse:99-100 |
| U2/S10 | `SIS` | `0x640` | S_IRQ_STATUS | yes (U2) | gse:108-109 |
| U2/S10 | `IOS` | `0x908` | IOS: IO2 data in is bit 1 | yes (U2) | gse:115-120 gse:281 |
| U2/S10 | `MIE` | `0x614` | M_IRQ_EN | - | gse:99-100 |
| U2/S10 | `SIE` | `0x644` | S_IRQ_EN | - | gse:108-109 |
| U2 | `IOM` | `0x240` | UART IO_MACRO_CTRL | - | gser:37-47 |
| U2 | `TCF` | `0x25c` | UART TX_TRANS_CFG | - | gser:37-47 |
| U2 | `RCF` | `0x280` | UART RX_TRANS_CFG | - | gser:37-47 |
| U2 | `TPA` | `0x2a4` | UART TX_PARITY_CFG | - | gser:37-47 |
| U2 | `RPA` | `0x2a8` | UART RX_PARITY_CFG | - | gser:37-47 |
| U2/S10 | `HW0` | `0xe24` | HW_PARAM_0 | - | gse:152-154 |
| U2/S10 | `HW1` | `0xe28` | HW_PARAM_1 | - | gse:152-154 |
| TLMM | `F8` | `0x8000` | gpio8 CFG | - | pin:32-35 pin:12 |
| TLMM | `L8` | `0x8004` | gpio8 IN_OUT | - | pin:32-35 pin:12 |
| TLMM | `F9` | `0x9000` | gpio9 CFG | - | pin:32-35 pin:12 |
| TLMM | `L9` | `0x9004` | gpio9 IN_OUT | - | pin:32-35 pin:12 |
| TLMM | `F10` | `0xa000` | gpio10 CFG | - | pin:32-35 pin:12 |
| TLMM | `L10` | `0xa004` | gpio10 IN_OUT | - | pin:32-35 pin:12 |
| TLMM | `F11` | `0xb000` | gpio11 CFG | - | pin:32-35 pin:12 |
| TLMM | `L11` | `0xb004` | gpio11 IN_OUT | - | pin:32-35 pin:12 |
| TLMM | `F91` | `0x5b000` | gpio91 CFG | - | pin:32-35 pin:12 |
| TLMM | `L91` | `0x5b004` | gpio91 IN_OUT | yes | pin:32-35 pin:12 |
| TLMM | `N91` | `0x5b008` | gpio91 INTR_CFG | - | pin:32-35 |
| TLMM | `S91` | `0x5b00c` | gpio91 INTR_STATUS | - | pin:32-35 |
| TLMM | `F40` | `0x28000` | gpio40 CFG | - | pin:32-35 pin:12 |
| TLMM | `L40` | `0x28004` | gpio40 IN_OUT | - | pin:32-35 pin:12 |
| TLMM | `F41` | `0x29000` | gpio41 CFG | - | pin:32-35 pin:12 |
| TLMM | `L41` | `0x29004` | gpio41 IN_OUT | - | pin:32-35 pin:12 |
| TLMM | `F42` | `0x2a000` | gpio42 CFG | - | pin:32-35 pin:12 |
| TLMM | `L42` | `0x2a004` | gpio42 IN_OUT | - | pin:32-35 pin:12 |
| TLMM | `F43` | `0x2b000` | gpio43 CFG | - | pin:32-35 pin:12 |
| TLMM | `L43` | `0x2b004` | gpio43 IN_OUT | - | pin:32-35 pin:12 |
| TLMM | `F51` | `0x33000` | gpio51 CFG | - | pin:32-35 pin:12 |
| TLMM | `L51` | `0x33004` | gpio51 IN_OUT | yes | pin:32-35 pin:12 |
| TLMM | `N51` | `0x33008` | gpio51 INTR_CFG | - | pin:32-35 |
| TLMM | `S51` | `0x3300c` | gpio51 INTR_STATUS | - | pin:32-35 |
| TLMM | `F48` | `0x30000` | gpio48 CFG | - | pin:32-35 pin:12 |
| TLMM | `L48` | `0x30004` | gpio48 IN_OUT | - | pin:32-35 pin:12 |
| TLMM | `F64` | `0x40000` | gpio64 CFG | - | pin:32-35 pin:12 |
| TLMM | `L64` | `0x40004` | gpio64 IN_OUT | - | pin:32-35 pin:12 |
| TLMM | `F2` | `0x2000` | gpio2 CFG | - | pin:32-35 pin:12 |
| TLMM | `L2` | `0x2004` | gpio2 IN_OUT | - | pin:32-35 pin:12 |
| X U2/X S10 | `CM` | `0x48` | SER_M_CLK_CFG | - | gse:87-92 |
| X U2/X S10 | `CS` | `0x4c` | SER_S_CLK_CFG | - | gse:87-92 |
| X U2/X S10 | `CK` | `0x7c` | CLK_SEL | - | gse:94 |
| X U2/X S10 | `CC` | `0x60` | CLK_CTRL_RO | - | gse:87-92 |
| X U2 | `TWL` | `0x268` | UART TX_WORD_LEN | - | gser:37-47 |
| X U2 | `TSB` | `0x26c` | UART TX_STOP_BIT_LEN | - | gser:37-47 |
| X U2 | `RWL` | `0x28c` | UART RX_WORD_LEN | - | gser:37-47 |
| X U2 | `STL` | `0x294` | UART RX_STALE_CNT | - | gser:37-47 |
| X U2 | `MRF` | `0x2ac` | UART MANUAL_RFR | - | gser:37-47 |
| X U2 | `TWM` | `0x80c` | TX_WATERMARK | - | gse:115-120 |
| X U2 | `RWM` | `0x810` | RX_WATERMARK | - | gse:115-120 |
| X U2 | `RFW` | `0x814` | RX_RFR_WATERMARK | - | gse:115-120 |
| X U2/X S10 | `DIF` | `0xe20` | DMA_IF_EN_RO | - | gse:152-154 |
| X GIC | `G616` | `0xcc` | IGROUPR of INTID 616 | - | gic:22-25 gic3:456-469 |
| X GIC | `R616` | `0x7340` | IROUTER of INTID 616 (64-bit) | - | gic:42 gic3:976-977 |
| X GIC | `G834` | `0xe8` | IGROUPR of INTID 834 | - | gic:22-25 gic3:456-469 |
| X GIC | `R834` | `0x7a10` | IROUTER of INTID 834 (64-bit) | - | gic:42 gic3:976-977 |
| X GIC | `G240` | `0x9c` | IGROUPR of INTID 240 | - | gic:22-25 gic3:456-469 |
| X GIC | `R240` | `0x6780` | IROUTER of INTID 240 (64-bit) | - | gic:42 gic3:976-977 |

## Which words Linux reads

Snapshots 1 and 2 read only words a pinned Linux driver reads; the 24 words of the late blocks are the ones none of the pinned UART, SPI, GENI core and interrupt-controller drivers reads
(UV7 in the main document: only those files were scanned, and a word none of them reads is not thereby safe, it is read last). `tools/test-q1n1-sp11-payload-inputsnap-refs.py` holds this table
to the pinned copies: each read at its line, each write at its line, and no read of a late word anywhere in those files. `<n>` stands for the three INTIDs or the pins of the register table.
The two engines are one GENI block: a read by either engine's driver counts for both (INFERRED from the shared layout of `geni-se.h`), so the SPI engine's `DMA`, `TXF`, `SIS`, `IOS` and
`SIE` rest on the UART driver's reads alone, and the UART engine's `IFD` on the SPI driver's.

| Words | Linux reads them | Pinned lines |
| --- | --- | --- |
| `MA0` `SA0` `CR0` `SE0` `C20` `MA1` `SA1` `CR1` `SE1` `QS1` `C21` | yes: a branch clock's halt word, its CBCR, is read when a clock is enabled | cbc:52 cbc:175-178 |
| `VT0` `VT1` `VT2` | yes: `clk_is_enabled_regmap` reads the enable register, which for these clocks is the vote word | clkr:22-37 |
| `CTL` | yes | gic3:162 |
| `TYP` | yes | gic3:2003 |
| `E<n>` `P<n>` | yes: `gic_peek_irq` | gic3:571-579 |
| `C<n>` | yes: when it configures an interrupt | gicc:62 |
| `FW` | yes: `geni_se_read_proto`, and both drivers | gse:375-379 gser:1343-1350 spi:645 |
| `IFD` | yes, by the SPI driver | spi:684 |
| `ST` | yes | gser:314-319 spi:1102 |
| `DMA` | yes: the UART interrupt handler | gser:1237-1241 |
| `TXF` | yes, by the UART driver | gser:792 |
| `RXF` `MIS` `SIS` | yes | gser:401-407 spi:788 spi:290-291 |
| `MIE` | yes | gser:720 spi:290-291 |
| `SIE` | yes, by the UART driver | gser:952 |
| `IOS` | yes: it is `CTS` | gser:243-245 |
| `IOM` | yes | gser:1363 |
| `TCF` `RCF` `TPA` `RPA` | yes | gser:1507-1510 |
| `HW0` `HW1` | yes: the FIFO depths | gse:495 spi:663 gse:541 |
| `F<n>` `L<n>` `N<n>` `S<n>` | yes: the pin controller driver | msm:211 msm:960 msm:853 msm:1348 |
| `CM` `CS` `CK` | **no**: the UART driver writes them | gser:1477-1480 |
| `CC` `DIF` | **no**: none of the pinned drivers reads or writes them | none |
| `TWL` `TSB` `RWL` | **no**: written | gser:1580-1582 |
| `STL` | **no**: written | gser:1361 |
| `MRF` | **no**: written | gser:267 |
| `TWM` | **no**: written | gser:605 |
| `RWM` `RFW` | **no**: written by the GENI core | gsec:372-373 |
| `G<n>` | **no**: the GIC driver writes IGROUPR | gic3:940 |
| `R<n>` | **no**: the GIC driver writes IROUTER | gic3:976-977 |

## Fetching the reference copies

The Snapintosh fork keeps `hamoa.dtsi` (`d5bb1f7c`), `gcc-x1e80100.c` (`f1c3779c`), `clk-branch.h` (`bac7dcf5`), `x1-microsoft-denali.dtsi` (`afbea2d7`) and `clk-branch.c`
(`d29259eb`, unpinned in the stick log) in `build/sp11-stick-log/refs/`; the test finds them from `SNAPINTOSH_DIR` or `INPUTSNAP_SNAP_REFS_DIR`. The other files are fetched at the same Linux
revision into `build/inputsnap-refs/` of this tree (or the directory `INPUTSNAP_REFS_DIR` names), each checked against its SHA-256:

```sh
mkdir -p build/inputsnap-refs && cd build/inputsnap-refs
curl -fsSLO https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/include/linux/soc/qcom/geni-se.h
curl -fsSLO https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/drivers/tty/serial/qcom_geni_serial.c
curl -fsSLO https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/include/linux/irqchip/arm-gic-v3.h
curl -fsSLO https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/drivers/irqchip/irq-gic-common.c
curl -fsSLO https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/drivers/irqchip/irq-gic-v3.c
curl -fsSLO https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/drivers/pinctrl/qcom/pinctrl-x1e80100.c
curl -fsSLO https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/drivers/pinctrl/qcom/pinctrl-msm.c
curl -fsSLO https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/drivers/pinctrl/qcom/pinctrl-msm.h
curl -fsSLO https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/drivers/spi/spi-geni-qcom.c
curl -fsSLO https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/drivers/soc/qcom/qcom-geni-se.c
curl -fsSLO https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/drivers/clk/qcom/clk-regmap.c
```

| File | SHA-256 |
| --- | --- |
| `geni-se.h` | `6aab274a8a269605887d426b71022ad018d5b9439f4e5fdfc980041a457c322d` |
| `qcom_geni_serial.c` | `b37708d4d4a71d33e49b771065c10986d412eb18397ba251c4025b55bd4c2d2e` |
| `arm-gic-v3.h` | `b11308e0281508b648d648cd652bce38a1fba774dbd47ed51de613a8533a3d13` |
| `irq-gic-common.c` | `3e322d8067549bb33adb59c893f49e7665957b1f6613ae53bb3403fb3029c3f1` |
| `irq-gic-v3.c` | `8e2a7ce97bf52a1ade7a7ce89d75399b03aa2c96a4101710605434fb83b60dad` |
| `pinctrl-x1e80100.c` | `fd70c0b9013800a4016351a08b4d86aaefaa75e88758f9a02fde380e84642259` |
| `pinctrl-msm.c` | `a593e9d2facdf4b07fb15d467ad374ab36ffd83eb97b74e43f177540992c4984` |
| `pinctrl-msm.h` | `02d034432dd718dab883d1e9e5e3f5124387753af723e7c7839675dbf29427bb` |
| `spi-geni-qcom.c` | `5ea2354f2efd520f16c3aceeae1b1225fedeeb622ea84060756e7ef65722bda4` |
| `qcom-geni-se.c` | `f8f7fc2a68e1ac8c927ac7d37c9d901c9aef75ef78f4ccc668ebe0a0ba71825e` |
| `clk-regmap.c` | `2438f057d67c3cd0229e710494dcf0a381bc69021591fe9cb89219734b8e633d` |
| `hamoa.dtsi` (Snapintosh refs) | `d5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0` |
| `gcc-x1e80100.c` (Snapintosh refs) | `f1c3779c7bc273dfe170ea2ff4d40f975083ee149e3b02a4f42d5939596eb775` |
| `clk-branch.h` (Snapintosh refs) | `bac7dcf51a0da5b27eaa0d4dc276f540fec80013bd4862cfbbc115a50161ef72` |
| `x1-microsoft-denali.dtsi` (Snapintosh refs) | `afbea2d7b48c1725b34a742b4c34432015ac237e6c390e94458551fb4213a239` |
| `clk-branch.c` (Snapintosh refs, unpinned) | `d29259eb77a5d1d6a07adf4aa835588f8e04d1fa3c14be2b7d4162cce737abfa` |
