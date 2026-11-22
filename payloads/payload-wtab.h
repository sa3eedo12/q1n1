/* SPDX-License-Identifier: MIT */
/* What a payload needs to use the write table (docs/SP11-PAYLOAD-WTAB.md): the runner's ops, found through the typed view of the arguments, so
 * that no integer is ever turned into a pointer in the payload's code. Header only and static inline, like payload-util.h.
 *
 * A payload with a table:
 *   - includes the generated header of its table (tools/sp11_wtab.py emit-c): `wtab_<name>`, WTAB_ROWS and one WROW_<tag> index per row;
 *   - opens it once, with the address of that constant and nothing else;
 *   - asks for each row by a literal index, in table order, and treats any non-zero answer as the end of the run (the runner has already undone
 *     what it changed and printed why; its reads of the table's windows are refused from then on);
 *   - never names an address or a value, and has no store but to its own stack: the policy tooling (tools/sp11_payload_wtab_audit.py) lints the base
 *     of every store and the index of every row, and the bytes are reviewed and pinned by the manifest (docs/SP11-PAYLOAD-WTAB.md, what this does not establish). */
#pragma once
#include "payload-util.h"
#include "sp11-payload-wtab-abi.h"

/* The ops, or 0 when this runner has no write table (the gate Q1N1_SP11_WTAB is off and args.reserved[0] is zero) or hands something else. */
static inline const struct q1n1_payload_wtab_ops *pl_wtab_ops(const struct q1n1_payload_args *a)
{
    const struct q1n1_payload_args_wtab *view = (const struct q1n1_payload_args_wtab *)a;
    const struct q1n1_payload_wtab_ops *ops = view->wtab;
    if (!ops || ops->magic != Q1N1_WTAB_OPS_MAGIC || ops->version != Q1N1_WTAB_TABLE_VERSION || ops->size < sizeof *ops || !ops->open ||
        !ops->row || !ops->unwind)
        return 0;
    return ops;
}
