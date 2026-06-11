/*
 * demo_inject.c — a harmless demonstration dylib for Phase 1 testing.
 *
 * Its ONLY effect is one line on stderr from a constructor that runs when the
 * dynamic linker loads it. We use it to prove the DYLD_INSERT_LIBRARIES
 * injection path: the monitor flags the *attempt* at exec time from the
 * process environment, independently of whether this code ultimately loads
 * (Apple's library validation may reject it — which is itself the point:
 * even a blocked injection is logged).
 *
 * Not a cheat, not a hook — it touches nothing in the host process.
 */
#include <stdio.h>

__attribute__((constructor))
static void vanguard_demo_ctor(void) {
    fprintf(stderr, "[vanguard-demo-dylib] constructor ran (injected)\n");
}
