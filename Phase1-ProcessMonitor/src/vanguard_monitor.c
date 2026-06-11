/*
 * vanguard_monitor.c
 * ------------------------------------------------------------------------
 * Vanguard-for-macOS  ·  Phase 1: System-Wide Process Monitor
 *
 * A proof-of-concept endpoint monitor built on Apple's Endpoint Security
 * (ES) framework. It demonstrates that a *userland* process, granted a
 * single Apple-issued entitlement, can observe security-relevant kernel
 * events system-wide -- without a kernel extension and without ring-0
 * access. This is the macOS answer to "how do you watch for cheats /
 * tampering without a kernel-level anti-cheat driver like Windows Vanguard?"
 *
 * What this file watches for, and why each matters for anti-cheat / EDR:
 *
 *   1. Process lifecycle (exec / fork / exit)
 *        Baseline telemetry. You cannot reason about tampering if you do
 *        not know what is running. Every exec also carries the binary's
 *        code-signing identity, so we can tell an Apple-signed/notarized
 *        binary from an unsigned local build at the moment it launches.
 *
 *   2. task-port acquisition (get_task / get_task_read / _inspect / _name)
 *        This is the macOS equivalent of Windows OpenProcess(). A process
 *        that obtains another process's *task port* can read and write its
 *        memory -- the foundation of almost every memory cheat, debugger
 *        attach, and code-injection technique. If something grabs the task
 *        port of the protected ("target") process, that is the single most
 *        important event an anti-cheat can see.
 *
 *   3. dylib injection via DYLD_INSERT_LIBRARIES
 *        The classic macOS code-injection vector (the DLL-injection
 *        analogue). We inspect the *environment* of every exec and raise an
 *        alert when a process is launched with DYLD_INSERT_LIBRARIES (or the
 *        related DYLD_* search-path overrides) set, which forces the dynamic
 *        linker to load attacker-controlled code into the new process.
 *
 * Design choice: this monitor subscribes ONLY to NOTIFY events, never AUTH
 * events. NOTIFY events are delivered after the fact and require no reply,
 * so this tool can never block, slow, or deadlock the system -- it is a
 * passive sensor. A production anti-cheat could upgrade specific events to
 * AUTH (e.g. AUTH_GET_TASK) to actively *deny* task-port access to the
 * protected process; the hooks are noted inline below.
 *
 * ------------------------------------------------------------------------
 * Entitlement / runtime requirements (see Phase1-ProcessMonitor/README.md):
 *   - Entitlement:  com.apple.developer.endpoint-security.client
 *   - Must run as root (sudo).
 *   - The binary must be code-signed with the entitlement above.
 *   - On stock macOS, that entitlement is only honored if Apple has granted
 *     it to your provisioning profile. For local research you instead
 *     disable SIP + AMFI enforcement (documented in the README) so a
 *     self-signed entitled binary is accepted.
 * ------------------------------------------------------------------------
 */

#include <EndpointSecurity/EndpointSecurity.h> /* es_* API: the whole point  */
#include <bsm/libbsm.h>                         /* audit_token_to_pid()       */
#include <dispatch/dispatch.h>                  /* dispatch_main(), queues    */

/*
 * Code-signing flags. These constants live in xnu's <sys/codesign.h>
 * (osfmk/kern/cs_blobs.h), a kernel header Apple does NOT ship in the public
 * macOS SDK -- so we cannot #include it. The values are stable kernel ABI, so
 * we define the few we use here. Guarded with #ifndef in case a future SDK
 * exposes them.
 */
#ifndef CS_VALID
#define CS_VALID          0x00000001  /* signature currently valid           */
#endif
#ifndef CS_ADHOC
#define CS_ADHOC          0x00000002  /* ad-hoc signed (no Team ID)           */
#endif
#ifndef CS_GET_TASK_ALLOW
#define CS_GET_TASK_ALLOW 0x00000004  /* allows its task port to be handed out*/
#endif

#include <CommonCrypto/CommonCrypto.h>  /* CC_SHA256_CTX, CC_SHA256_Update -- part of macOS SDK, no extra link flags */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * LOCK-FREE SPSC RING BUFFER
 * -------------------------------------------------------------------------
 *
 * WHY: ES NOTIFY callbacks are delivered on a kernel-managed queue. The ES
 * subsystem has a finite internal event queue; if a callback takes too long
 * to return, the kernel's delivery pipeline stalls and events are dropped
 * by the kernel itself (visible as a sequence-number gap). Logging, hashing,
 * and file I/O can all block on I/O or scheduling and must therefore NOT
 * happen on the ES callback thread. The ring buffer decouples the two:
 *
 *   ES callback (producer)  --[ring buffer]-->  consumer thread
 *
 * The producer fills a slot and returns to the kernel immediately. The
 * consumer does all the slow work (fprintf, SHA-256 update, rename-write).
 *
 * Single-Producer Single-Consumer (SPSC) means we never need a mutex in
 * the hot path -- the atomic head/tail indices are sufficient for
 * correctness on the TSO memory model (and on ARM with the acquire/release
 * ordering we use below).
 */

#define RING_CAPACITY 1024u   /* must be a power of 2 */
#define RING_MASK     (RING_CAPACITY - 1u)

/*
 * vg_event_t: the small, flat snapshot of an event that the producer copies
 * into the ring. We copy -- never hold a pointer into the es_message_t --
 * because ES frees the message immediately after the callback returns.
 */
typedef struct {
    char     timestamp[40];
    char     severity[8];       /* "INFO ", "WATCH", "ALERT" */
    char     event_type[32];    /* "EXEC", "FORK", "EXIT", "GET_TASK", … */
    pid_t    pid;
    pid_t    ppid;
    char     path[1024];
    uint32_t signing_flags;
    char     team_id[20];
    char     signing_id[256];
    char     inject_var[256];   /* DYLD_INSERT_LIBRARIES=… or "" */
} vg_event_t;

typedef struct {
    vg_event_t      slots[RING_CAPACITY];
    atomic_size_t   head;   /* producer writes here; consumer reads */
    atomic_size_t   tail;   /* consumer frees here; producer checks */
    atomic_size_t   dropped;
} vg_ring_t;

static vg_ring_t g_ring;

/*
 * ring_push: called from the ES callback (producer). Returns false and
 * increments g_ring.dropped if the buffer is full -- we NEVER block.
 */
static bool ring_push(const vg_event_t *ev) {
    size_t head = atomic_load_explicit(&g_ring.head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&g_ring.tail, memory_order_acquire);

    if ((head - tail) >= RING_CAPACITY) {
        atomic_fetch_add_explicit(&g_ring.dropped, 1, memory_order_relaxed);
        return false;
    }

    g_ring.slots[head & RING_MASK] = *ev;

    /* Release: make the slot contents visible before the head bump. */
    atomic_store_explicit(&g_ring.head, head + 1, memory_order_release);
    return true;
}

/*
 * ring_pop: called from the consumer thread. Returns false when empty.
 */
static bool ring_pop(vg_event_t *out) {
    size_t tail = atomic_load_explicit(&g_ring.tail, memory_order_relaxed);
    size_t head = atomic_load_explicit(&g_ring.head, memory_order_acquire);

    if (tail == head)
        return false;

    *out = g_ring.slots[tail & RING_MASK];

    /* Release: allow the producer to see the slot as free. */
    atomic_store_explicit(&g_ring.tail, tail + 1, memory_order_release);
    return true;
}

/* ---- Global state -------------------------------------------------------
 * Kept tiny on purpose. g_client is the live ES connection; g_target_name
 * is an optional process name (basename substring) we treat as the
 * "protected" process -- any task-port access to it is escalated to ALERT.
 */
static es_client_t *g_client       = NULL;
static char         g_target_name[256] = {0};
static pthread_t    g_consumer_tid;
static volatile int g_stop_consumer = 0;

/* ---- Tiny logging helpers ----------------------------------------------- */

/* Severity tags so a human (or a log scraper) can grep the stream quickly. */
#define SEV_INFO  "INFO "
#define SEV_WATCH "WATCH"
#define SEV_ALERT "ALERT"

/*
 * ES strings are es_string_token_t: a {const char *data; size_t length}
 * pair that is NOT guaranteed to be NUL-terminated. Never pass .data to a
 * normal C string function; always honor .length. This helper prints one
 * safely, substituting "(null)" for empty/absent tokens.
 */
static const char *tok(es_string_token_t t, char *buf, size_t buflen) {
    if (t.data == NULL || t.length == 0) {
        snprintf(buf, buflen, "(none)");
        return buf;
    }
    size_t n = t.length < (buflen - 1) ? t.length : (buflen - 1);
    memcpy(buf, t.data, n);
    buf[n] = '\0';
    return buf;
}

/* Format the ES message timestamp (struct timespec, wall-clock) as ISO-8601
 * with millisecond precision, e.g. 2026-06-11T10:55:21.314Z-ish (local). */
static const char *iso_time(struct timespec ts, char *buf, size_t buflen) {
    struct tm tm_buf;
    localtime_r(&ts.tv_sec, &tm_buf);
    char base[64];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    snprintf(buf, buflen, "%s.%03ld", base, ts.tv_nsec / 1000000);
    return buf;
}

/* Decode the code-signing posture of a process into a short human string.
 * codesigning_flags is a bitmask of the kernel CS_* flags. We surface the
 * few that matter for trust decisions; an unsigned or invalid binary
 * touching the protected process is far more suspicious than an
 * Apple-platform binary doing the same. */
static const char *signing_summary(const es_process_t *p, char *buf, size_t buflen) {
    char team[64], sid[128];
    tok(p->team_id, team, sizeof(team));
    tok(p->signing_id, sid, sizeof(sid));

    const uint32_t f = p->codesigning_flags;
    /* These CS_* flags come from <sys/codesign.h>:
     *   CS_VALID:          signature currently valid.
     *   CS_ADHOC:          self-signed ad-hoc (no Team ID) -- local builds.
     *   CS_GET_TASK_ALLOW: binary opted in to having its task port handed
     *                      out (i.e. it allows being debugged) -- directly
     *                      relevant to the task-port event class below.
     * is_platform_binary is a dedicated bool meaning "signed by Apple as
     * part of the OS", so we read it instead of a flag. */
    snprintf(buf, buflen,
             "%s%s%s%s team=%s id=%s",
             (f & CS_VALID)          ? "valid "          : "INVALID ",
             p->is_platform_binary   ? "platform "       : "",
             (f & CS_ADHOC)          ? "adhoc "          : "",
             (f & CS_GET_TASK_ALLOW) ? "get-task-allow " : "",
             team, sid);
    return buf;
}

/* Case-insensitive "does the path end with / contain our target name?"
 * Used to decide whether a get_task target is the protected process. */
static bool path_is_target(es_string_token_t path) {
    if (g_target_name[0] == '\0' || path.data == NULL || path.length == 0)
        return false;
    char pbuf[1024];
    tok(path, pbuf, sizeof(pbuf));
    /* substring match keeps the CLI simple: pass a name, not a full path */
    return strcasestr(pbuf, g_target_name) != NULL;
}

/* -------------------------------------------------------------------------
 * SHA-256 TELEMETRY HASH
 * -------------------------------------------------------------------------
 *
 * A running SHA-256 accumulator over every processed event provides a
 * cryptographic bind between the Phase-1 event stream and Phase-2 (Secure
 * Enclave / App Attest). Phase 2 can read the current digest from
 * /tmp/vanguard_telemetry.hash and verify that the stream it received is
 * the same stream the monitor produced -- without needing to replay all
 * events.
 *
 * We maintain a global CC_SHA256_CTX (g_telemetry_ctx) and update it for
 * each event. To read the current digest without finalising the running
 * context (which would close it), we copy the context, finalise the copy,
 * and base64-encode the 32-byte result.
 *
 * Atomic write discipline: write to .tmp then rename() so Phase 2 can
 * never observe a partial file.
 */

#define TELEMETRY_HASH_PATH     "/tmp/vanguard_telemetry.hash"
#define TELEMETRY_HASH_TMP_PATH "/tmp/vanguard_telemetry.hash.tmp"

static CC_SHA256_CTX g_telemetry_ctx;

/*
 * base64_encode_32: encode exactly 32 bytes to standard base64.
 * Output is always 44 characters (32 bytes -> ceil(32/3)*4 = 44) with
 * standard alphabet; no line breaks; NUL-terminated.
 * `out` must be at least 45 bytes.
 */
static void base64_encode_32(const unsigned char *in, char *out) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /* 32 bytes = 10 full 3-byte groups (30 bytes → 40 chars) + 2 remainder bytes (→ 4 chars) = 44 chars */
    size_t i = 0, o = 0;
    for (; i + 2 < 32; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[o++] = tbl[(v >> 18) & 0x3f];
        out[o++] = tbl[(v >> 12) & 0x3f];
        out[o++] = tbl[(v >>  6) & 0x3f];
        out[o++] = tbl[(v      ) & 0x3f];
    }
    /* i == 30, 2 remaining bytes (in[30], in[31]) */
    {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8);
        out[o++] = tbl[(v >> 18) & 0x3f];
        out[o++] = tbl[(v >> 12) & 0x3f];
        out[o++] = tbl[(v >>  6) & 0x3f];
        out[o++] = '=';
    }
    out[o] = '\0';
}

/*
 * telemetry_update: called by the consumer thread for each event.
 * Feeds a canonical record into the running SHA-256 and atomically
 * refreshes /tmp/vanguard_telemetry.hash.
 */
static void telemetry_update(const vg_event_t *ev) {
    /* Canonical feed string: pipe-separated fields, newline-terminated.
     * inject_var is intentionally excluded from the canonical hash fields
     * to keep the format stable across event types that lack it. */
    char record[2048];
    int  rlen = snprintf(record, sizeof(record),
        "%s|%s|%s|%d|%d|%s|%u|%s|%s\n",
        ev->timestamp,
        ev->severity,
        ev->event_type,
        (int)ev->pid,
        (int)ev->ppid,
        ev->path,
        ev->signing_flags,
        ev->team_id,
        ev->signing_id);

    if (rlen <= 0 || (size_t)rlen >= sizeof(record))
        return;

    CC_SHA256_Update(&g_telemetry_ctx, record, (CC_LONG)rlen);

    /* Snapshot the current digest without closing the running context. */
    CC_SHA256_CTX snap = g_telemetry_ctx;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &snap);

    char b64[48];
    base64_encode_32(digest, b64);

    /* Atomic write: .tmp -> rename. */
    FILE *f = fopen(TELEMETRY_HASH_TMP_PATH, "w");
    if (!f) return;
    fprintf(f, "%s\n", b64);
    fclose(f);
    rename(TELEMETRY_HASH_TMP_PATH, TELEMETRY_HASH_PATH);
}

/* -------------------------------------------------------------------------
 * CONSUMER THREAD
 * -------------------------------------------------------------------------
 *
 * Spins on the ring buffer. Uses sched_yield() when empty -- acceptable
 * for a security daemon where latency matters more than CPU. (A condition
 * variable could replace the spin if power usage is a concern.)
 */

/*
 * emit_event: the actual logging that was previously done inline in the ES
 * callback. Now runs entirely on the consumer thread, safely decoupled from
 * the kernel delivery queue.
 */
static void emit_event(const vg_event_t *ev) {
    if (strcmp(ev->event_type, "EXEC") == 0 ||
        strcmp(ev->event_type, "EXEC+INJECT") == 0) {

        char signbuf[320];
        snprintf(signbuf, sizeof(signbuf),
                 "flags=0x%x team=%s id=%s",
                 ev->signing_flags, ev->team_id, ev->signing_id);

        if (strcmp(ev->event_type, "EXEC+INJECT") == 0) {
            fprintf(stdout,
                "[%s] " SEV_ALERT " EXEC+INJECT pid=%d ppid=%d path=%s"
                "  signing=[%s]  via=%s\n",
                ev->timestamp, ev->pid, ev->ppid, ev->path,
                signbuf, ev->inject_var);
        } else {
            fprintf(stdout,
                "[%s] " SEV_INFO  " EXEC        pid=%d ppid=%d path=%s"
                "  signing=[%s]%s%s\n",
                ev->timestamp, ev->pid, ev->ppid, ev->path,
                signbuf,
                ev->inject_var[0] ? "  dyld-env=" : "",
                ev->inject_var[0] ? ev->inject_var : "");
        }

    } else if (strcmp(ev->event_type, "FORK") == 0) {
        fprintf(stdout, "[%s] " SEV_INFO  " FORK        parent=%d child=%d path=%s\n",
                ev->timestamp, ev->ppid, ev->pid, ev->path);

    } else if (strcmp(ev->event_type, "EXIT") == 0) {
        fprintf(stdout, "[%s] " SEV_INFO  " EXIT        pid=%d status=%d path=%s\n",
                ev->timestamp, ev->pid, (int)ev->ppid /* status stored in ppid field */,
                ev->path);

    } else {
        /* GET_TASK / GET_TASK_READ / GET_TASK_INSPECT / GET_TASK_NAME */
        bool alert = (strcmp(ev->severity, SEV_ALERT) == 0);
        fprintf(stdout,
            "[%s] %s %-15s requester=%d(%s) target=%d  requester-signing=[flags=0x%x team=%s id=%s]%s\n",
            ev->timestamp, ev->severity, ev->event_type,
            ev->ppid, ev->path,   /* ppid = requester pid, path = requester path */
            ev->pid,              /* pid  = target pid                           */
            ev->signing_flags, ev->team_id, ev->signing_id,
            alert ? "  <== PROTECTED PROCESS" : "");
    }
}

static void *consumer_thread(void *arg) {
    (void)arg;
    vg_event_t ev;

    while (!g_stop_consumer) {
        if (ring_pop(&ev)) {
            emit_event(&ev);
            telemetry_update(&ev);
        } else {
            sched_yield();
        }
    }
    /* Drain remaining events before exiting. */
    while (ring_pop(&ev)) {
        emit_event(&ev);
        telemetry_update(&ev);
    }
    return NULL;
}

/* ---- Event handlers -----------------------------------------------------
 * One small function per event class. Each receives the immutable
 * es_message_t and pushes a snapshot into the ring buffer, then returns
 * immediately so the ES callback queue is not held.
 */

/* ES_EVENT_TYPE_NOTIFY_EXEC: a process image was replaced via execve().
 * This is where we (a) record what launched with full signing identity and
 * (b) scan the new process's environment for dylib-injection vectors. */
static void handle_exec(const es_message_t *msg) {
    const es_event_exec_t *ev = &msg->event.exec;

    vg_event_t vev = {0};
    iso_time(msg->time, vev.timestamp, sizeof(vev.timestamp));
    tok(ev->target->executable->path, vev.path, sizeof(vev.path));

    vev.pid  = audit_token_to_pid(ev->target->audit_token);
    vev.ppid = ev->target->ppid;
    vev.signing_flags = ev->target->codesigning_flags;
    tok(ev->target->team_id,   vev.team_id,   sizeof(vev.team_id));
    tok(ev->target->signing_id, vev.signing_id, sizeof(vev.signing_id));

    /* Inspect the launch environment. es_exec_env_count/es_exec_env walk the
     * envp[] captured at exec time. DYLD_INSERT_LIBRARIES forces dyld to load
     * arbitrary dylibs into the process before main() -- the macOS DLL
     * injection. The DYLD_*_PATH overrides can redirect library resolution
     * to attacker copies; we flag those too, at lower severity. */
    bool     injected = false;
    uint32_t env_count = es_exec_env_count(ev);
    for (uint32_t i = 0; i < env_count; i++) {
        es_string_token_t e = es_exec_env(ev, i);
        if (e.data == NULL) continue;
        if (e.length >= 21 && strncmp(e.data, "DYLD_INSERT_LIBRARIES", 21) == 0) {
            injected = true;
            tok(e, vev.inject_var, sizeof(vev.inject_var));
            break;
        }
        if (!injected && e.length >= 5 && strncmp(e.data, "DYLD_", 5) == 0) {
            tok(e, vev.inject_var, sizeof(vev.inject_var));
        }
    }

    strncpy(vev.severity,   injected ? SEV_ALERT : SEV_INFO,  sizeof(vev.severity) - 1);
    strncpy(vev.event_type, injected ? "EXEC+INJECT" : "EXEC", sizeof(vev.event_type) - 1);

    ring_push(&vev);
}

/* ES_EVENT_TYPE_NOTIFY_FORK: a process duplicated itself. Logged at INFO so
 * the process tree stays reconstructable (fork without a following exec is
 * how some loaders stage injected children). */
static void handle_fork(const es_message_t *msg) {
    const es_event_fork_t *ev = &msg->event.fork;

    vg_event_t vev = {0};
    iso_time(msg->time, vev.timestamp, sizeof(vev.timestamp));
    tok(ev->child->executable->path, vev.path, sizeof(vev.path));
    /* Store parent pid in ppid, child pid in pid -- emit_event reads both. */
    vev.ppid = audit_token_to_pid(msg->process->audit_token);
    vev.pid  = audit_token_to_pid(ev->child->audit_token);
    strncpy(vev.severity,   SEV_INFO, sizeof(vev.severity) - 1);
    strncpy(vev.event_type, "FORK",   sizeof(vev.event_type) - 1);

    ring_push(&vev);
}

/* ES_EVENT_TYPE_NOTIFY_EXIT: a process terminated. Closes the lifecycle so
 * pids can be aged out of any state table a real product would keep. */
static void handle_exit(const es_message_t *msg) {
    vg_event_t vev = {0};
    iso_time(msg->time, vev.timestamp, sizeof(vev.timestamp));
    tok(msg->process->executable->path, vev.path, sizeof(vev.path));
    vev.pid  = audit_token_to_pid(msg->process->audit_token);
    vev.ppid = (pid_t)msg->event.exit.stat; /* re-use ppid field for exit status */
    strncpy(vev.severity,   SEV_INFO, sizeof(vev.severity) - 1);
    strncpy(vev.event_type, "EXIT",   sizeof(vev.event_type) - 1);

    ring_push(&vev);
}

/* The four task-port events share a shape: an instigator (msg->process)
 * acquiring some flavor of port to a target (es_process_t *target). We
 * funnel them through one builder. `kind` names which port was requested:
 *
 *   GET_TASK         full control port  -> read AND write target memory
 *   GET_TASK_READ    read-only port     -> read target memory
 *   GET_TASK_INSPECT inspect port       -> sample/introspect target
 *   GET_TASK_NAME    name port          -> least powerful, info only
 *
 * GET_TASK is the dangerous one for anti-cheat: it is what a memory cheat or
 * a remote-code injector needs. We escalate to ALERT when the target is the
 * protected process; otherwise WATCH so the activity is still visible.
 */
static void handle_get_task_like(const es_message_t *msg,
                                 const es_process_t *target,
                                 const char *kind) {
    vg_event_t vev = {0};
    iso_time(msg->time, vev.timestamp, sizeof(vev.timestamp));

    /* requester info stored in path/ppid; target pid in vev.pid */
    tok(msg->process->executable->path, vev.path, sizeof(vev.path));
    vev.ppid = audit_token_to_pid(msg->process->audit_token); /* requester pid */
    vev.pid  = audit_token_to_pid(target->audit_token);        /* target pid    */
    vev.signing_flags = msg->process->codesigning_flags;
    tok(msg->process->team_id,   vev.team_id,   sizeof(vev.team_id));
    tok(msg->process->signing_id, vev.signing_id, sizeof(vev.signing_id));

    bool hits_target = path_is_target(target->executable->path);
    strncpy(vev.severity,   hits_target ? SEV_ALERT : SEV_WATCH, sizeof(vev.severity) - 1);
    strncpy(vev.event_type, kind,                                 sizeof(vev.event_type) - 1);

    ring_push(&vev);

    /* Production hook: subscribe to ES_EVENT_TYPE_AUTH_GET_TASK instead and,
     * when hits_target is true and the requester is not Apple-platform /
     * not on an allowlist, reply es_respond_auth_result(... ES_AUTH_RESULT_DENY)
     * to *prevent* the task port from ever being handed out. */
}

/* ---- The ES message pump ------------------------------------------------ */

/* Single entry point ES calls for every delivered message. We switch on the
 * event type and dispatch. Because we only subscribed to NOTIFY events, we
 * never have to call es_respond_*; returning is sufficient.
 *
 * All work beyond copying event data into the ring buffer happens on the
 * consumer thread -- this function returns as fast as possible. */
static void handle_message(const es_message_t *msg) {
    switch (msg->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:             handle_exec(msg); break;
        case ES_EVENT_TYPE_NOTIFY_FORK:             handle_fork(msg); break;
        case ES_EVENT_TYPE_NOTIFY_EXIT:             handle_exit(msg); break;
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            handle_get_task_like(msg, msg->event.get_task.target, "GET_TASK"); break;
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
            handle_get_task_like(msg, msg->event.get_task_read.target, "GET_TASK_READ"); break;
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
            handle_get_task_like(msg, msg->event.get_task_inspect.target, "GET_TASK_INSPECT"); break;
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
            handle_get_task_like(msg, msg->event.get_task_name.target, "GET_TASK_NAME"); break;
        default:
            /* We only subscribed to the above, so this is unreachable in
             * normal operation; kept for forward-compatibility. */
            break;
    }
}

/* ---- Lifecycle ---------------------------------------------------------- */

/* The event set we ask the kernel to deliver. Adding/removing a line here is
 * the entire surface for "watch more / watch less". */
static const es_event_type_t kSubscriptions[] = {
    ES_EVENT_TYPE_NOTIFY_EXEC,
    ES_EVENT_TYPE_NOTIFY_FORK,
    ES_EVENT_TYPE_NOTIFY_EXIT,
    ES_EVENT_TYPE_NOTIFY_GET_TASK,
    ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
    ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT,
    ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME,
};

/* Translate the es_new_client failure codes into actionable human text --
 * the most common first-run wall is NOT_ENTITLED / NOT_PERMITTED. */
static const char *new_client_error(es_new_client_result_t r) {
    switch (r) {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return "binary lacks com.apple.developer.endpoint-security.client "
                   "(sign with entitlements/vanguard.entitlements)";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return "not permitted: grant Full Disk Access (TCC) to this binary "
                   "in System Settings > Privacy & Security";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return "must run as root (use sudo)";
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            return "internal ES error";
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return "too many ES clients active on this system";
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            return "invalid argument to es_new_client";
        default:
            return "unknown es_new_client error";
    }
}

/* Tear the client down cleanly on Ctrl-C so the kernel stops queueing for us. */
static void shutdown_and_exit(int signo) {
    (void)signo;
    if (g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
        g_client = NULL;
    }
    /* Signal the consumer thread and wait for it to drain. */
    g_stop_consumer = 1;
    pthread_join(g_consumer_tid, NULL);

    size_t dropped = atomic_load_explicit(&g_ring.dropped, memory_order_relaxed);
    if (dropped > 0)
        fprintf(stdout, "[vanguard] warning: %zu events dropped (ring buffer full)\n", dropped);

    fprintf(stdout, "\n[vanguard] stopped.\n");
    fflush(stdout);
    _exit(0);
}

int main(int argc, char **argv) {
    /* Optional arg: the process name to treat as "protected". Any task-port
     * access whose target path contains this string is escalated to ALERT. */
    if (argc > 1) {
        strncpy(g_target_name, argv[1], sizeof(g_target_name) - 1);
    }

    /* Line-buffer stdout so events appear immediately even when piped. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    fprintf(stdout, "[vanguard] Phase 1 process monitor starting...\n");
    if (g_target_name[0])
        fprintf(stdout, "[vanguard] protecting target matching: \"%s\"\n", g_target_name);
    else
        fprintf(stdout, "[vanguard] no target specified; logging all task-port access\n");

    /* Initialise the ring buffer atomics (already zero from BSS; explicit for clarity). */
    atomic_init(&g_ring.head,    0);
    atomic_init(&g_ring.tail,    0);
    atomic_init(&g_ring.dropped, 0);

    /* Initialise the running SHA-256 telemetry accumulator. */
    CC_SHA256_Init(&g_telemetry_ctx);
    fprintf(stdout, "[vanguard] telemetry hash stream active -> %s\n", TELEMETRY_HASH_PATH);

    /* Start the consumer thread before opening the ES client so no event
     * can be produced before the consumer is ready. */
    if (pthread_create(&g_consumer_tid, NULL, consumer_thread, NULL) != 0) {
        fprintf(stderr, "[vanguard] pthread_create failed: %s\n", strerror(errno));
        return 1;
    }

    /*
     * STEP 1 -- create the ES client.
     *
     * es_new_client() opens our connection to the Endpoint Security
     * subsystem and registers the block the kernel will invoke for each
     * event. The block runs on an ES-managed serial queue, so handlers are
     * delivered one at a time (no locking needed for our stdout writes).
     *
     * This call is also the gate that enforces the entitlement, root, and
     * TCC requirements -- if any are missing it fails here with a specific
     * code we translate above.
     */
    es_new_client_result_t res = es_new_client(&g_client,
        ^(es_client_t *c __attribute__((unused)), const es_message_t *msg) {
            handle_message(msg);
        });

    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "[vanguard] es_new_client failed: %s\n", new_client_error(res));
        g_stop_consumer = 1;
        pthread_join(g_consumer_tid, NULL);
        return 1;
    }

    /*
     * STEP 2 -- subscribe to the event set.
     *
     * Until we subscribe, the client is connected but silent. es_subscribe()
     * tells the kernel which event types to deliver. Subscriptions are
     * additive and can be changed at runtime; here we set them once.
     */
    if (es_subscribe(g_client, kSubscriptions,
                     sizeof(kSubscriptions) / sizeof(kSubscriptions[0]))
        != ES_RETURN_SUCCESS) {
        fprintf(stderr, "[vanguard] es_subscribe failed\n");
        es_delete_client(g_client);
        g_stop_consumer = 1;
        pthread_join(g_consumer_tid, NULL);
        return 1;
    }

    fprintf(stdout, "[vanguard] subscribed to %zu event types. monitoring... (Ctrl-C to stop)\n",
            sizeof(kSubscriptions) / sizeof(kSubscriptions[0]));

    /* Clean shutdown on Ctrl-C / SIGTERM. */
    signal(SIGINT,  shutdown_and_exit);
    signal(SIGTERM, shutdown_and_exit);

    /*
     * STEP 3 -- run forever.
     *
     * dispatch_main() parks the main thread and lets the ES queue deliver
     * messages to our block. It never returns; shutdown happens via the
     * signal handler above.
     */
    dispatch_main();
    return 0; /* not reached */
}
