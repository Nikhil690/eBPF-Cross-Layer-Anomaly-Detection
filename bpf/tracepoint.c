//go:build ignore

#include "common.h"

/* ── Maps (TP-owned; corr_window_map + ring_events shared via Go) ── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u32);
    __type(value, struct cla_proc_state);
} proc_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);
    __type(value, struct cla_corr_record);
} corr_window_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ring_events SEC(".maps");

/* ── Tracepoint: sys_enter_connect ────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    /* ── Update per-PID proc_state ────────────────────────── */
    struct cla_proc_state *ps = bpf_map_lookup_elem(&proc_state_map, &pid);
    if (!ps) {
        struct cla_proc_state new_ps = {};
        new_ps.pid = pid;
        new_ps.uid = uid;
        new_ps.syscall_count = 1;
        bpf_get_current_comm(new_ps.comm, sizeof(new_ps.comm));
        bpf_map_update_elem(&proc_state_map, &pid, &new_ps, BPF_ANY);
        ps = bpf_map_lookup_elem(&proc_state_map, &pid);
        if (!ps) return 0;
    } else {
        __sync_fetch_and_add(&ps->syscall_count, 1);
    }

    /* ── Resolve fd → socket cookie ──────────────────────── */
    __u64 fd = ctx->args[0];            /* connect(sockfd, ...) */
    struct sock *sk = get_socket_from_fd(fd);
    if (!sk) return 0;

    __u64 cookie = get_socket_cookie_from_sk(sk);
    if (cookie == 0) return 0;

    /* ── Merge proc info into corr_window ────────────────── */
    struct cla_corr_record *rec = bpf_map_lookup_elem(&corr_window_map, &cookie);
    if (rec) {
        rec->layer_coverage |= LAYER_SYSCALL;
        rec->proc = *ps;
    } else {
        /* TC hasn't seen this cookie yet; create proc-only record */
        struct cla_corr_record new_rec = {};
        new_rec.cookie          = cookie;
        new_rec.window_start_ns = bpf_ktime_get_ns();
        new_rec.layer_coverage  = LAYER_SYSCALL;
        new_rec.proc            = *ps;
        bpf_map_update_elem(&corr_window_map, &cookie, &new_rec, BPF_ANY);
    }

    /* Emit every 10 connect calls per PID (burst detector) */
    if (ps->syscall_count % 10 == 0) {
        rec = bpf_map_lookup_elem(&corr_window_map, &cookie);
        if (rec) {
            struct cla_corr_record *e =
                bpf_ringbuf_reserve(&ring_events, sizeof(*e), 0);
            if (e) {
                *e = *rec;
                bpf_ringbuf_submit(e, 0);
            }
            bpf_map_delete_elem(&corr_window_map, &cookie);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
