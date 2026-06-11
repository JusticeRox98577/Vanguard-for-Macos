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

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- Global state -------------------------------------------------------
 * Kept tiny on purpose. g_client is the live ES connection; g_target_name
 * is an optional process name (basename substring) we treat as the
 * "protected" process -- any task-port access to it is escalated to ALERT.
 */
static es_client_t *g_client = NULL;
static char         g_target_name[256] = {0};

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

/* ---- Event handlers -----------------------------------------------------
 * One small function per event class. Each receives the immutable
 * es_message_t. msg->process is always the *instigator* (who caused the
 * event); the event-specific union carries the subject (new process, task
 * target, etc.).
 */

/* ES_EVENT_TYPE_NOTIFY_EXEC: a process image was replaced via execve().
 * This is where we (a) record what launched with full signing identity and
 * (b) scan the new process's environment for dylib-injection vectors. */
static void handle_exec(const es_message_t *msg) {
    const es_event_exec_t *ev = &msg->event.exec;

    char tbuf[40], pathbuf[1024], signbuf[256];
    iso_time(msg->time, tbuf, sizeof(tbuf));
    tok(ev->target->executable->path, pathbuf, sizeof(pathbuf));
    signing_summary(ev->target, signbuf, sizeof(signbuf));

    pid_t pid  = audit_token_to_pid(ev->target->audit_token);
    pid_t ppid = ev->target->ppid;

    /* Inspect the launch environment. es_exec_env_count/es_exec_env walk the
     * envp[] captured at exec time. DYLD_INSERT_LIBRARIES forces dyld to load
     * arbitrary dylibs into the process before main() -- the macOS DLL
     * injection. The DYLD_*_PATH overrides can redirect library resolution
     * to attacker copies; we flag those too, at lower severity. */
    bool   injected = false;
    char   inject_detail[1024] = {0};
    uint32_t env_count = es_exec_env_count(ev);
    for (uint32_t i = 0; i < env_count; i++) {
        es_string_token_t e = es_exec_env(ev, i);
        if (e.data == NULL) continue;
        if (e.length >= 21 && strncmp(e.data, "DYLD_INSERT_LIBRARIES", 21) == 0) {
            injected = true;
            tok(e, inject_detail, sizeof(inject_detail));
            break; /* one is enough to alert */
        }
        if (!injected && e.length >= 5 && strncmp(e.data, "DYLD_", 5) == 0) {
            /* DYLD_LIBRARY_PATH / DYLD_FRAMEWORK_PATH / DYLD_FALLBACK_* etc. */
            tok(e, inject_detail, sizeof(inject_detail));
        }
    }

    if (injected) {
        fprintf(stdout,
            "[%s] " SEV_ALERT " EXEC+INJECT pid=%d ppid=%d path=%s  signing=[%s]  via=%s\n",
            tbuf, pid, ppid, pathbuf, signbuf, inject_detail);
    } else {
        fprintf(stdout,
            "[%s] " SEV_INFO  " EXEC        pid=%d ppid=%d path=%s  signing=[%s]%s%s\n",
            tbuf, pid, ppid, pathbuf, signbuf,
            inject_detail[0] ? "  dyld-env=" : "",
            inject_detail[0] ? inject_detail : "");
    }
}

/* ES_EVENT_TYPE_NOTIFY_FORK: a process duplicated itself. Logged at INFO so
 * the process tree stays reconstructable (fork without a following exec is
 * how some loaders stage injected children). */
static void handle_fork(const es_message_t *msg) {
    const es_event_fork_t *ev = &msg->event.fork;
    char tbuf[40], pathbuf[1024];
    iso_time(msg->time, tbuf, sizeof(tbuf));
    tok(ev->child->executable->path, pathbuf, sizeof(pathbuf));
    /* The parent is the instigator (msg->process); the child is ev->child. */
    fprintf(stdout, "[%s] " SEV_INFO  " FORK        parent=%d child=%d path=%s\n",
            tbuf, audit_token_to_pid(msg->process->audit_token),
            audit_token_to_pid(ev->child->audit_token), pathbuf);
}

/* ES_EVENT_TYPE_NOTIFY_EXIT: a process terminated. Closes the lifecycle so
 * pids can be aged out of any state table a real product would keep. */
static void handle_exit(const es_message_t *msg) {
    char tbuf[40], pathbuf[1024];
    iso_time(msg->time, tbuf, sizeof(tbuf));
    tok(msg->process->executable->path, pathbuf, sizeof(pathbuf));
    fprintf(stdout, "[%s] " SEV_INFO  " EXIT        pid=%d status=%d path=%s\n",
            tbuf, audit_token_to_pid(msg->process->audit_token),
            msg->event.exit.stat, pathbuf);
}

/* The four task-port events share a shape: an instigator (msg->process)
 * acquiring some flavor of port to a target (es_process_t *target). We
 * funnel them through one printer. `kind` names which port was requested:
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
    char tbuf[40], who[1024], tgt[1024], signbuf[256];
    iso_time(msg->time, tbuf, sizeof(tbuf));
    tok(msg->process->executable->path, who, sizeof(who));
    tok(target->executable->path, tgt, sizeof(tgt));
    signing_summary(msg->process, signbuf, sizeof(signbuf));

    bool hits_target = path_is_target(target->executable->path);
    const char *sev = hits_target ? SEV_ALERT : SEV_WATCH;

    fprintf(stdout,
        "[%s] %s %-15s requester=%d(%s) target=%d(%s)  requester-signing=[%s]%s\n",
        tbuf, sev, kind,
        audit_token_to_pid(msg->process->audit_token), who,
        audit_token_to_pid(target->audit_token), tgt,
        signbuf,
        hits_target ? "  <== PROTECTED PROCESS" : "");

    /* Production hook: subscribe to ES_EVENT_TYPE_AUTH_GET_TASK instead and,
     * when hits_target is true and the requester is not Apple-platform /
     * not on an allowlist, reply es_respond_auth_result(... ES_AUTH_RESULT_DENY)
     * to *prevent* the task port from ever being handed out. */
}

/* ---- The ES message pump ------------------------------------------------ */

/* Single entry point ES calls for every delivered message. We switch on the
 * event type and dispatch. Because we only subscribed to NOTIFY events, we
 * never have to call es_respond_*; returning is sufficient. */
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
