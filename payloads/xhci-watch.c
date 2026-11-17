/* SPDX-License-Identifier: MIT */
/* Payload "xhci", the plug watch (docs/SP11-PAYLOAD-XHCI.md; xhci-priv.h lists the parts): thirty seconds in which the operator connects the
 * Mac's USB-C cable, during which the PORTSC of both controllers are read every WATCH_STEP_MS and each change is printed. Reads only: no
 * store of any kind, and nothing here opens a write group. */
#include "xhci-priv.h"

/* ---- The plug watch: reads only ----------------------------------------------------------------------------------------------------- */

/* Lines that may be printed without taking any from what must follow: `reserve` lines are kept for the later groups. */
int room(const struct ctx *c, unsigned reserve)
{
    return c->lines + 1 + reserve <= LINE_CAP;
}

/* 30 s, a sample of every port of both controllers every WATCH_STEP_MS, one line per change (the first WATCH_CHANGE_LINES), and a last line
 * that names the ports that changed. A port that cannot be read ends the sampling of its controller. A counter that stands still ends the watch (the
 * run then ends at its first wait, as it does for any counter that does not run) and one that runs backwards does too. */
void watch_run(struct ctx *c, unsigned reserve)
{
    uint32_t prev[2][PORTS_WATCHED], changed = 0, changes = 0, faulted = 0, usable[2], printed = 0, announced = 0, same = 0;
    uint64_t step = (uint64_t)WATCH_STEP_MS * c->hz / 1000u, total = (uint64_t)WATCH_S * c->hz, next = 0, now, start = c->a->ops.counter(), last = start;
    struct pl_line line;
    for (unsigned win = 0; win < 2; win++) {
        usable[win] = c->x[win].ports != 0 && windows[win].base != 0;
        for (unsigned p = 0; p < PORTS_WATCHED; p++) prev[win][p] = c->x[win].portsc[p];
    }
    say(c, "WATCH 30 S: CONNECT THE MAC USB-C CABLE TO THE FREE PORT NOW");
    pl_begin(&line);
    pl_text(&line, PREFIX "BASE");
    for (unsigned win = 0; win < 2; win++)
        for (unsigned p = 0; p < PORTS_WATCHED && usable[win] && p < c->x[win].ports; p++) {
            pl_text(&line, win ? " U1P" : " U0P");
            put_dec(&line, p + 1);
            pl_text(&line, "=");
            pl_hex(c->a, &line, prev[win][p]);
        }
    emit(c, &line);
    while ((now = c->a->ops.counter()) >= start && now - start < total) {
        if (now == last) {
            if (++same >= COUNTER_STUCK_READS) break;
        } else {
            last = now;
            same = 0;
        }
        now -= start;
        if (now >= next) {
            next += step;
            for (unsigned win = 0; win < 2; win++) {
                for (unsigned p = 0; p < PORTS_WATCHED && usable[win] && p < c->x[win].ports; p++) {
                    uint32_t value = 0;
                    if (rd32(c, win, c->x[win].op + OP_PORTSC(p + 1), &value, "PORTSC")) {
                        usable[win] = 0;
                        faulted |= 1u << win;
                        break;
                    }
                    if (value == prev[win][p]) continue;
                    changed |= 1u << (win * PORTS_WATCHED + p);
                    changes++;
                    if (printed < WATCH_CHANGE_LINES && room(c, reserve)) {
                        say(c, "CHG T=%d.%d %s%d FROM %x TO %P", U(now * 10 / c->hz / 10), U(now * 10 / c->hz % 10), win ? "U1P" : "U0P", U(p + 1),
                            U(prev[win][p]), U(value));
                        printed++;
                    }
                    prev[win][p] = value;
                }
            }
        }
        if (announced < 2 && now >= total * (announced + 1) / 3) {
            if (room(c, reserve)) say(c, announced ? "WATCH 10 S LEFT" : "WATCH 20 S LEFT");
            announced++;
        }
    }
    pl_begin(&line);
    pl_text(&line, PREFIX "WATCH DONE CHANGED=");
    if (!changed) pl_text(&line, "NONE");
    for (unsigned bit = 0; bit < 2 * PORTS_WATCHED; bit++) {
        if (!(changed >> bit & 1u)) continue;
        if (line.buf[line.len - 1] != '=') pl_text(&line, ".");
        pl_text(&line, bit / PORTS_WATCHED ? "U1P" : "U0P");
        put_dec(&line, bit % PORTS_WATCHED + 1);
    }
    pl_text(&line, " N=");
    put_dec(&line, changes);
    if (faulted) pl_text(&line, faulted == 3 ? " FAULT=BOTH" : faulted == 1 ? " FAULT=U0" : " FAULT=U1");
    emit(c, &line);
}
