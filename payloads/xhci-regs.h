/* SPDX-License-Identifier: MIT */
/* Hardware register definitions, limits and the vocabulary of the page for the payload "xhci" (payloads/xhci.c; docs/SP11-PAYLOAD-XHCI.md):
 * where the controllers are, which registers the payload reads, the few it may store to and the groups it may store them in, the layout of
 * an arena, the time and line budgets, and the names it prints. Definitions only. Evidence labels as in the payload: VERIFIED is a pinned
 * source or q1n1's own driver, OBSERVED a run on the unit (S0, S0b, boot 5, boots 8 and 9). */
#pragma once
#include <stdint.h>

/* Budgets. The line limit and the load limit are the ABI's (40 lines, 4096 loads per call), the latter with a margin. The host test builds with a
 * smaller XHCI_S1_LINE_CAP to exercise what the payload does when the lines run out; the shipped binaries use 40. */
#ifndef XHCI_S1_LINE_CAP
#define XHCI_S1_LINE_CAP 40u
#endif
#define LINE_CAP XHCI_S1_LINE_CAP
#define CLOSING_LINES 2u                /* the verdict and the end line are never crowded out by the lines before them */
#define ATTEMPT_LINES_MIN 6u            /* what an eligible attempt always keeps: its five announcements and its result line; an SMMU report is printed only if it leaves them */
#ifndef XHCI_S1_LOAD_CAP
#define XHCI_S1_LOAD_CAP 3800u
#endif
#define LOAD_CAP XHCI_S1_LOAD_CAP
#define WAIT_BEFORE_WRITE_S 8u
#define WATCH_S 30u
#define WATCH_STEP_MS 250u
#define WATCH_CHANGE_LINES 4u
#define POLL_US 1000u
#define POLL_SLOW_US 10000u             /* a wait of more than POLL_FAST_WINDOW_US polls this often after it: HCRST and CNR may take a second */
#define POLL_FAST_WINDOW_US 100000u
#define T_HALT_US 50000u                /* the specification gives the xHC 16 ms to halt */
#define T_RESET_US 1000000u             /* Linux waits up to 10 s for a reset (INFERRED, from memory): one second here, so that a slow reset is not a verdict */
#define T_CNR_US 1000000u
#define T_RUN_US 50000u
#define T_EVENT_US 200000u
#define EVENTS_MAX 16u
#define SCRATCH_MAX 32u
#define PAGE 4096u
#define STACK_KEPT (24u * 1024u)        /* the payload's own frames and the runner's ops keep this much of the stack */
#define CACHE_STEP 16u
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
#define COUNTER_STUCK_READS 2000000u
#define MAP_DESCRIPTORS_MAX 1024u
#define MAP_STRIDE_MAX 4096u
#define SMR_SCANNED_MAX 256u
#define PORTS_WATCHED 2u
#define ARENAS 4u

enum { STORE_OK, STORE_BITS, STORE_NOT_ARMED, STORE_DEAD, STORE_RANGE, STORE_BAD_REG };
enum { V_NONE, V_OK, V_TIMEOUT, V_HSE, V_BAD, V_REFUSED };
enum { STG_ARENA, STG_RESET, STG_PROGRAM, STG_RUN, STG_NOOP, STG_HALT };
/* Why a stage stopped. Fixed-size name tables, not pointer tables: a pointer in .rodata would need a load-address relocation. */
enum { W_NONE, W_HALT, W_HCRST, W_CNR, W_HCH, W_HELD, W_EVENT, W_READ, W_CLOCK, W_STORE, W_HSE, W_HCE, W_CODE, W_POINTER, W_CYCLE, W_BUDGET, W_LINES,
       W_REDIRECT };
static const char stage_name[6][8] = {"ARENA", "RESET", "PROGRAM", "RUN", "NOOP", "HALT"};
static const char verdict_name[6][20] = {"NONE", "NOOP_OK", "NOOP_TIMEOUT", "NOOP_HSE", "NOOP_BAD_COMPLETION", "REFUSED"};
static const char why_name[18][9] = {"", "HALT", "HCRST", "CNR", "HCH", "NOT_HELD", "EVENT", "READ", "CLOCK", "STORE", "HSE", "HCE", "CODE", "POINTER",
                                     "CYCLE", "BUDGET", "LINES", "REDIRECT"};
static const char arena_name[ARENAS + 1][6] = {"", "FW", "STACK", "LOW", "HIGH"};
enum { AR_OK, AR_NO_MAP, AR_NOT_FREE, AR_NO_AC64, AR_TOO_BIG, AR_SMALL_STACK, AR_NOT_APPLICABLE };
static const char arena_why[7][12] = {"OK", "NO_MAP", "NOT_FREE", "NO_AC64", "TOO_BIG", "SMALL_STACK", "N_A"};

#ifndef XHCI_S1_CONTROLLER
#error "XHCI_S1_CONTROLLER must be 0 (usb_1_ss0) or 1 (usb_1_ss1): the manifest names one file per controller"
#endif
#if XHCI_S1_CONTROLLER != 0 && XHCI_S1_CONTROLLER != 1
#error "XHCI_S1_CONTROLLER must be 0 (usb_1_ss0) or 1 (usb_1_ss1)"
#endif

/* The windows: reg of usb_1_ss0, usb_1_ss1 and apps_smmu in the pinned Hamoa device tree (VERIFIED; S0 and S0b read all three at EL2 on the
 * unit, OBSERVED). The macros let the QEMU test aim the payload at a qemu-xhci (no DWC3 core, no SMMU: DWC3_ID 0 and SMMU_BASE 0 skip
 * them, a window base of 0 is absent); the shipped binaries use the defaults. */
#ifndef XHCI_S1_U0_BASE
#define XHCI_S1_U0_BASE UINT64_C(0x0a600000)
#endif
#ifndef XHCI_S1_U1_BASE
#define XHCI_S1_U1_BASE UINT64_C(0x0a800000)
#endif
#ifndef XHCI_S1_WINDOW
#define XHCI_S1_WINDOW 0xfc100u
#endif
#ifndef XHCI_S1_SMMU_BASE
#define XHCI_S1_SMMU_BASE UINT64_C(0x15000000)
#endif
#ifndef XHCI_S1_SMMU_WINDOW
#define XHCI_S1_SMMU_WINDOW 0x100000u
#endif
/* What both controllers read on the unit: GSNPSID 0x33313130, CAPLENGTH 0x20, HCIVERSION 0x0110 (OBSERVED, S0 and S0b). */
#ifndef XHCI_S1_DWC3_ID
#define XHCI_S1_DWC3_ID 0x33313130u
#endif
#ifndef XHCI_S1_CAPLENGTH
#define XHCI_S1_CAPLENGTH 0x20u
#endif
#ifndef XHCI_S1_HCIVERSION
#define XHCI_S1_HCIVERSION 0x0110u
#endif
/* The iommus stream of usb_1_ss0 and usb_1_ss1 in the pinned hamoa.dtsi (VERIFIED). */
#ifndef XHCI_S1_STREAM_ID
#define XHCI_S1_STREAM_ID (XHCI_S1_CONTROLLER ? 0x1460u : 0x1420u)
#endif
/* Arena 1 (usb_1_ss0 only): the firmware's own xHCI memory as S0 found it, which the stream reached before ExitBootServices (OBSERVED in
 * S0's boot: DCBAAP 0xCF412000, event ring 0xCF414CB8, segment table 0xCF415240). Another boot may have put it elsewhere, so the memory
 * map must still call the whole range free (boot services data or conventional) or the arena is skipped by name. */
#define ARENA1_BASE UINT64_C(0xCF412000)
#define ARENA1_PAGES 4u
/* Arena 4: the first page of the 30 GiB bank. EL2's own stage 1 maps it write-back and `AT S1E2W` accepted every probe of a 672 MiB placement in it, and 13 of 13
 * digests of data copied in read back (OBSERVED, el2mem and the memhash dry run, boots 8 to 10: docs/SP11-MONITOR-PORT.md and docs/SP11-STICK-WRAPPER.md of the
 * Snapintosh tree). Whether the xHC's DMA reaches it is UNKNOWN (SC2). It is the last attempt: a fault page there would be the answer. */
#define ARENA4_BASE UINT64_C(0x880000000)

enum { WIN_U0, WIN_U1, WIN_SMMU, WINDOWS };
static const struct {
    uint64_t base;
    uint32_t size;
} windows[WINDOWS] = {{XHCI_S1_U0_BASE, XHCI_S1_WINDOW}, {XHCI_S1_U1_BASE, XHCI_S1_WINDOW}, {XHCI_S1_SMMU_BASE, XHCI_S1_SMMU_WINDOW}};
#define TARGET ((unsigned)XHCI_S1_CONTROLLER)
#define OTHER (1u - TARGET)

/* xHCI 1.2: capability registers from the window base, operational ones from base + CAPLENGTH, interrupter 0 from base + RTSOFF + 0x20,
 * doorbell 0 at base + DBOFF (VERIFIED against q1n1's platform/uefi/xhci.c, which drives the A16's identical DWC3 xHC). HCSPARAMS1: slots
 * 7:0, interrupters 18:8, ports 31:24. HCSPARAMS2: scratchpad count high 25:21, low 31:27. HCCPARAMS1: AC64 bit 0, CSZ bit 2. */
enum { CAP_CAP0 = 0x00, CAP_HCSPARAMS1 = 0x04, CAP_HCSPARAMS2 = 0x08, CAP_HCCPARAMS1 = 0x10, CAP_DBOFF = 0x14, CAP_RTSOFF = 0x18 };
enum { OP_USBCMD = 0x00, OP_USBSTS = 0x04, OP_PAGESIZE = 0x08, OP_CRCR = 0x18, OP_DCBAAP = 0x30, OP_CONFIG = 0x38 };
enum { IR_IMAN = 0x00, IR_ERSTSZ = 0x08, IR_ERSTBA = 0x10, IR_ERDP = 0x18, IR0 = 0x20 };
#define OP_PORTSC(n) (0x400u + 0x10u * ((n) - 1u))
enum { CMD_RS = 1u << 0, CMD_HCRST = 1u << 1 };
enum { STS_HCH = 1u << 0, STS_HSE = 1u << 2, STS_EINT = 1u << 3, STS_PCD = 1u << 4, STS_CNR = 1u << 11, STS_HCE = 1u << 12 };
enum { ERDP_EHB = 1u << 3, IMAN_IP = 1u << 0, CRCR_RCS = 1u << 0 };
/* TRB types (xHCI 1.2 section 6.4.6): Link 6, No Op Command 23, Command Completion Event 33, Port Status Change Event 34. */
enum { TRB_LINK = 6, TRB_NOOP_CMD = 23, TRB_CMD_COMPLETION = 33, TRB_PORT_STATUS = 34, TRB_BYTES = 16, CC_SUCCESS = 1 };
/* DWC3 global registers (core.h of the pinned Linux files, VERIFIED): read only. They start at 0xc100 (GSBUSCFG0): no register the payload stores to
 * may lie at or above STORE_LIMIT, whatever DBOFF and RTSOFF say. */
enum { DWC3_GSTS = 0xc118, DWC3_GSNPSID = 0xc120, DWC3_GBUSERRADDR0 = 0xc130, DWC3_GBUSERRADDR1 = 0xc134 };
#define STORE_LIMIT 0xc100u
/* SMMUv2 (arm-smmu.h, VERIFIED; sGFAR is the architecture's): read only. Context bank n's page is (NUMPAGE + n) * PAGESIZE from the window. */
enum { SMMU_ID0 = 0x20, SMMU_ID1 = 0x24, SMMU_GFAR = 0x40, SMMU_GFSR = 0x48, SMMU_GFSYNR0 = 0x50, CB_FSR = 0x58, CB_FAR = 0x60, CB_FSYNR0 = 0x68 };
#define SMMU_SMR(n) (0x800u + 4u * (n))
#define SMMU_S2CR(n) (0xc00u + 4u * (n))

/* The structures of one arena, 64-byte aligned and none across a 64 KiB boundary (Table 6-1), all in its first page; the scratchpad
 * buffers are the whole pages after it. DCBAA at 0 holds (slots + 1) * 8 bytes: up to 71 slots fit below OFF_SPARR (the unit has 64). */
enum { OFF_DCBAA = 0x000, OFF_SPARR = 0x240, OFF_CMD = 0x400, OFF_ERST = 0x500, OFF_EVENT = 0x600, CMD_TRBS = 16, EVENT_TRBS = 64, SLOTS_FIT = 71 };

/* Write groups, opened one by one by announce(). G_STOP is no group: a halt is allowed once any is open. */
enum { G_STOP = 0u, G_ARENA = 1u, G_RESET = 2u, G_PROGRAM = 4u, G_RUN = 8u, G_NOOP = 16u };
/* The registers the payload may store to, the whole list, and the groups each may be stored in (ERDP twice: programmed, then handed back). */
enum { SR_USBCMD, SR_CRCR_LO, SR_CRCR_HI, SR_DCBAAP_LO, SR_DCBAAP_HI, SR_CONFIG, SR_ERSTSZ, SR_ERSTBA_LO, SR_ERSTBA_HI, SR_ERDP_LO, SR_ERDP_HI,
       SR_IMAN, SR_DB0, SR_COUNT };
static const uint8_t reg_groups[SR_COUNT] = {0, G_PROGRAM, G_PROGRAM, G_PROGRAM, G_PROGRAM, G_PROGRAM, G_PROGRAM, G_PROGRAM, G_PROGRAM,
                                             G_PROGRAM | G_NOOP, G_PROGRAM | G_NOOP, G_NOOP, G_NOOP};
/* Where each of them is: from the operational registers (0), from interrupter 0 (1) or the doorbell array (2), plus an offset. */
static const struct {
    uint8_t from, off;
} reg_map[SR_COUNT] = {{0, OP_USBCMD}, {0, OP_CRCR}, {0, OP_CRCR + 4}, {0, OP_DCBAAP}, {0, OP_DCBAAP + 4}, {0, OP_CONFIG}, {1, IR_ERSTSZ},
                       {1, IR_ERSTBA}, {1, IR_ERSTBA + 4}, {1, IR_ERDP}, {1, IR_ERDP + 4}, {1, IR_IMAN}, {2, 0}};
