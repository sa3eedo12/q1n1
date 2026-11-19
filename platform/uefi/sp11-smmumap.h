/* SPDX-License-Identifier: MIT */
/* The payload runner's one page-table write (docs/SP11-PAYLOAD-SMMUMAP.md): once, at EL2, after the first payload's own hash check
 * and before it is called (and only when every payload of the chain verified), map the
 * 4 KiB page 0x15400000 (register page 0 of the PCIe SMMUv3) in UEFI's EL2 stage 1 by writing ONE level-3 descriptor,
 * so that the unchanged `smmuprobe` payload can ask what the SMMU does with the internal SSD's stream.
 *
 * Why the runner and not a payload: a payload has no store, no TLBI and no MSR (its binary is checked against that), and
 * the monitor owns no EL2 stage 1. The first question the S1 boot (nvmesnap + smmuprobe, 2026-11-18) could not answer
 * is not the SMMU's but a mapping gap: `AT S1E2R` of the page gave a level-3 translation fault (FST 0x7), so the tables
 * have a level-3 table there and no entry for the page, and nothing was accessed.
 *
 * Opt-in twice over, in the style of sp11-payload.h. Q1N1_SP11_SMMUMAP (default 0) needs Q1N1_SP11_PAYLOAD=1; with the
 * gate at 0 this header and its two sources compile to nothing, and the runner's other files are what they were, byte
 * for byte (tools/test-q1n1-sp11-payload-smmumap.py proves it against the pinned runner). The logic is pure: every
 * effect goes through q1n1_smmumap_env, so the native tests run it against a modelled set of translation tables.
 *
 * The one write is one 64-bit descriptor in firmware RAM (a level-3 table slot that is zero); nothing is written to a
 * device. A refusal leaves no descriptor in place (CHECK_FAILED wrote one and put the zero back, STORES=2; a put-back that
 * fails is UNSAFE). Every guarded load the step makes (the walks, the scan, the slot read once more) is made only into a page
 * that the UEFI memory map calls RAM, proven before the load (load_ram in sp11-smmumap.c is the one call of env->read64).
 *
 * Evidence: EXPERIMENTAL throughout; hardware NOT RUN. */
#pragma once
#include "sp11-payload.h"

/* The gate Q1N1_SP11_SMMUMAP (default 0, and its #error without Q1N1_SP11_PAYLOAD) is defined in sp11-payload.h: the
 * runner's own header and run loop need it before this file can be included. */
#if Q1N1_SP11_SMMUMAP

/* The page that is mapped: the PCIe SMMUv3's register page 0. Linux hamoa.dtsi `pcie_smmu: iommu@15400000`, `reg = <0
 * 0x15400000 0 0x80000>`, status "reserved" with the comment "Controlled by Gunyah." (the pinned copy, lines 8544-8556:
 * VERIFIED as the platform address); the IORT of the unit names the same base (docs/SP11-PAYLOAD-SMMUPROBE.md, INFERRED from
 * the offline parse). That EL2's stage 1 has no entry for it: OBSERVED once (boot 22, smmuprobe `MAP SMMU=FAULT=0X7:TRANS_L3`). */
#define Q1N1_SMMUMAP_PAGE_PA UINT64_C(0x15400000)
/* Where the attributes come from: the page of segment 6's root-port configuration space, which nvmesnap and smmuprobe
 * already read at EL2 (ECAM base 0x70000000: the unit's MCFG, OBSERVED on two boots; AT S1E2R says it is a Device page
 * there, `MAP RP=DEVICE.OS.NS1`, boot 22). Its descriptor is the template: Device, read/write at EL2, XN, access flag set. */
#define Q1N1_SMMUMAP_TEMPLATE_PA UINT64_C(0x70000000)
/* The EL2 stage-1 root the S1 survey measured: TTBR0_EL2 0xA7F2E000 on every boot that printed it (boots 4, 5, 7 and the
 * M2 survey of Snapintosh docs/SP11-EL2-ENTRY.md; the same value at the de-VHE flip). A different value is a different
 * table than the one this logic was reviewed against, so nothing is written. */
#define Q1N1_SMMUMAP_TTBR0_EL2 UINT64_C(0xA7F2E000)
/* The wait of the NEXT line, as the payloads do it (el2mem's idiom): the line is drawn, the counter runs for this many
 * seconds, then the store. */
#define Q1N1_SMMUMAP_WAIT_S 8u

/* What the runner knows of the translation regime, read once (sp11-smmumap-el2.c: MRS at EL2). */
struct q1n1_smmumap_regs {
    uint64_t ttbr0, tcr, mair, sctlr, hcr;
};

/* Everything the logic does to the machine. Plain function pointers: there is one platform, main.c's. */
struct q1n1_smmumap_env {
    void (*emit)(const char *line);                         /* one finished line, as the runner's own */
    uint64_t (*counter)(void);
    uint64_t freq;                                          /* counter ticks per second */
    void (*regs)(struct q1n1_smmumap_regs *out);
    int (*read64)(uint64_t pa, uint64_t *value);            /* guarded 64-bit load of firmware RAM (only called for a page the map calls RAM); non-zero: it aborted */
    int (*store64)(uint64_t pa, uint64_t value);            /* THE store: one guarded 64-bit store; non-zero: it aborted */
    int (*at)(uint64_t va, int write, uint64_t *par);       /* AT S1E2R or S1E2W, ISB, MRS PAR_EL1; makes no access at va */
    void (*clean)(uint64_t va);                             /* DC CVAC of the line at va */
    void (*dsb)(void);                                      /* DSB ISH */
    void (*tlbi)(uint64_t va);                              /* TLBI VALE2IS for the 4 KiB page at va */
    void (*isb)(void);
    /* The UEFI memory map the runner kept (descriptors of map_stride bytes, EFI layout): the logic proves the page of every table word
     * it loads (the root, each table of the walks, the level-3 table before its slot, the scan, the slot read once more) to be RAM
     * by this map before the load, and refuses (TABLE_NOT_RAM) otherwise, so that no device is read or written by the step's own
     * loads and stores. A NULL or unusable map refuses. */
    const uint8_t *map;
    uint64_t map_size, map_stride;
    /* After the chain: main.c's poll of a pending asynchronous SError (returns 1 when it found one; `still` says one is pending
     * after it), and a read of ISR_EL1.A that takes and clears nothing (sp11-smmumap-el2.c). Either may be NULL. */
    int (*serror_poll)(uint64_t *syndrome, int *still);
    int (*serror_pending)(void);
};

/* A page this service may map: a name for the log, the page, the page whose descriptor gives the attributes. The list
 * is the allow-list; any other page is refused (SPEC). */
struct q1n1_smmumap_spec {
    const char *name;
    uint64_t page_pa, template_pa;
};
extern const struct q1n1_smmumap_spec q1n1_smmumap_specs[];
extern const unsigned q1n1_smmumap_spec_count;

/* Why a run did not map, or UNSAFE. Each has a name (q1n1_smmumap_reason_name) printed as `PAYLOAD SMMUMAP REFUSED=<NAME>`. */
enum {
    Q1N1_SMMUMAP_R_NONE = 0,
    Q1N1_SMMUMAP_R_NO_COUNTER,          /* the NEXT line's wait cannot be made: no counter */
    Q1N1_SMMUMAP_R_COUNTER_UNUSABLE,    /* the counter stands still or goes back */
    Q1N1_SMMUMAP_R_SPIN_BOUND,          /* the counter moves but the wait did not end in the bound */
    Q1N1_SMMUMAP_R_SPEC,                /* the page asked for is not on the list */
    Q1N1_SMMUMAP_R_TTBR0_UNPINNED,      /* TTBR0_EL2 is not the root the survey measured */
    Q1N1_SMMUMAP_R_REGIME,              /* MMU off, big-endian walks, E2H, a granule that is not 4 KiB, a T0SZ outside 16 to 39 */
    Q1N1_SMMUMAP_R_WALK_FAULT,          /* a read of a table descriptor aborted */
    Q1N1_SMMUMAP_R_NO_L3_TABLE,         /* the walk does not end at a level-3 table: a hole or a block above */
    Q1N1_SMMUMAP_R_UPPER_FLAGS,         /* a table descriptor above carries NSTable, APTable, UXNTable or PXNTable */
    Q1N1_SMMUMAP_R_TABLE_ADDRESS,       /* a table address is beyond the physical address size */
    Q1N1_SMMUMAP_R_TABLE_SHARED,        /* the level-3 table is also a table of another level on the path to the page or to the template,
                                         * or an entry of a higher table of the path points at it */
    Q1N1_SMMUMAP_R_TABLE_NOT_RAM,       /* a table page the step is about to load from (the root, a table of the walk to the page or to the template,
                                         * the level-3 table before its slot) is not inside one descriptor of the memory map that says RAM:
                                         * refused before the load */
    Q1N1_SMMUMAP_R_SCAN_FAULT,          /* a read of the level-3 table or of a table of the path, for the evidence line, aborted */
    Q1N1_SMMUMAP_R_AT_DISAGREES,        /* the AT instruction does not say what the walk says */
    Q1N1_SMMUMAP_R_ENTRY_VALID,         /* the page's entry is already valid: not overwritten */
    Q1N1_SMMUMAP_R_ENTRY_NOT_ZERO,      /* the entry is invalid but not zero */
    Q1N1_SMMUMAP_R_TEMPLATE_UNMAPPED,   /* the template page has no valid leaf */
    Q1N1_SMMUMAP_R_TEMPLATE_NOT_DEVICE, /* its attribute index is not Device-nGnRnE or Device-nGnRE in MAIR_EL2 */
    Q1N1_SMMUMAP_R_TEMPLATE_NOT_USABLE, /* its access flag is clear, it is read-only at EL2, or it can execute */
    Q1N1_SMMUMAP_R_TABLE_NOT_WRITABLE,  /* AT S1E2W of the table page faults, or maps another page */
    Q1N1_SMMUMAP_R_DESCRIPTOR,          /* the descriptor would not be a 4 KiB page descriptor of the one page */
    Q1N1_SMMUMAP_R_STORE_FAULT,         /* the guarded store aborted: nothing was written */
    Q1N1_SMMUMAP_R_CHECK_FAILED,        /* after the store the AT check failed: the zero was put back */
    Q1N1_SMMUMAP_R_ROLLBACK_FAILED,     /* ... and it could not be put back, or the page still translates: UNSAFE */
    Q1N1_SMMUMAP_R_COUNT
};
enum {
    Q1N1_SMMUMAP_MAPPED = 0,    /* the descriptor is in place and the AT check agrees */
    Q1N1_SMMUMAP_REFUSED,       /* nothing is in place (a refused step, or a descriptor that was put back) */
    Q1N1_SMMUMAP_UNSAFE,        /* a descriptor may be in place and unchecked: the chain must not run */
};
struct q1n1_smmumap_result {
    int status, reason;
    unsigned stores;            /* 64-bit stores made, a rollback's included */
    uint64_t desc, slot;        /* the descriptor written and where (0 when none was made) */
    int serror_before;          /* ISR_EL1.A when the page had been mapped, before any payload ran; 0 when it was not read */
};
const char *q1n1_smmumap_reason_name(int reason);

/* The pure parts, for the tests and the doc checks. */
#define Q1N1_SMMUMAP_ADDR UINT64_C(0x0000fffffffff000)             /* output address bits [47:12] */
#define Q1N1_SMMUMAP_ATTR_LOW UINT64_C(0xffc)                      /* bits [11:2]: AttrIndx, NS, AP, SH, AF, nG */
#define Q1N1_SMMUMAP_ATTR_HIGH (UINT64_C(3) << 53)                 /* bits [54:53]: UXN (XN at EL2) and PXN */
uint64_t q1n1_smmumap_descriptor(uint64_t page_pa, uint64_t template_desc);
int q1n1_smmumap_descriptor_ok(uint64_t desc, uint64_t page_pa);
int q1n1_smmumap_template_check(uint64_t mair, uint64_t desc);      /* 0 or a Q1N1_SMMUMAP_R_TEMPLATE_* reason */
/* RAM in the sense of the payloads (nvmesnap, smmuprobe, usbsmmu): loader, boot services, runtime services, conventional and ACPI
 * reclaim memory, EFI types 1 to 7 and 9. Reserved, unusable, ACPI NVS and MMIO descriptors are somebody else's. */
int q1n1_smmumap_ram_type(int type);
/* The EFI type of the one descriptor that holds [pa, pa + bytes): -1 when none does, -2 when the map cannot be read safely (no map, a
 * stride below 40 or not a multiple of 8, a size that is not whole descriptors, more than 1024 of them) or the range is empty or wraps.
 * A descriptor that overlaps the range and is not RAM decides it, so a map that disagrees with itself is never trusted; a malformed
 * descriptor is skipped, as the payloads do. A type above 0xFFFF (no EFI type is) is answered as 0xFFFF, so that no type is -1 or -2.
 * `attr`, when not NULL, receives the attribute word (offset 32) of the descriptor whose type is answered, 0 for -1 and -2. */
int q1n1_smmumap_map_type(const uint8_t *map, uint64_t size, uint64_t stride, uint64_t pa, uint64_t bytes, uint64_t *attr);
/* What `TYPE=` prints for the two answers that are not an EFI type. */
#define Q1N1_SMMUMAP_TYPE_NOT_IN_MAP 0xffu
#define Q1N1_SMMUMAP_TYPE_MAP_UNUSABLE 0xfeu

/* Maps the one page. Prints the lines of docs/SP11-PAYLOAD-SMMUMAP.md, ends with `PAYLOAD SMMUMAP DONE`, and returns the
 * status. `result` may be NULL. The page is q1n1_smmumap_specs[0]. */
int q1n1_smmumap_run(const struct q1n1_smmumap_env *env, struct q1n1_smmumap_result *result);
/* The same for a page of the caller's choosing: refused (SPEC) unless it is on the list. */
int q1n1_smmumap_page(const struct q1n1_smmumap_env *env, const struct q1n1_smmumap_spec *spec,
                      struct q1n1_smmumap_result *result);
/* After the chain: when the page was mapped, polls once for an asynchronous SError that a payload of the chain (or anything since the step
 * ended) may have left pending, and prints one line, `PAYLOAD SMMUMAP SERROR=...`. The poll CONSUMES a pending SError (main.c). Nothing
 * is printed when the page was not mapped. */
void q1n1_smmumap_after_chain(const struct q1n1_smmumap_env *env, const struct q1n1_smmumap_result *result);

/* sp11-smmumap-el2.c, EL2 only: fills regs, at, clean, dsb, tlbi, isb and serror_pending with the instructions. The caller supplies
 * the rest. */
void q1n1_smmumap_el2_ops(struct q1n1_smmumap_env *env);

#endif /* Q1N1_SP11_SMMUMAP */
