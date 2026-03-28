#ifndef __COMMON_H
#define __COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* Constants not available via vmlinux.h */
#define ETH_P_IP      0x0800
#define IPPROTO_TCP   6
#define TC_ACT_OK     0

/* Layer coverage bitmask */
#define LAYER_XDP     (1 << 0)
#define LAYER_TC      (1 << 1)
#define LAYER_SYSCALL (1 << 2)
#define LAYER_UPROBE  (1 << 3)

/* ── Shared struct definitions (prefixed to avoid vmlinux clash) ── */

struct cla_flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
};

struct cla_flow_stats {
    __u64 pkt_count;
    __u64 byte_count;
    __u64 last_seen_ns;
    __u64 first_seen_ns;
    __u32 syn_count;
    __u32 rst_count;
    __u32 fin_count;
    __u32 tcp_flags_seen;
    __u64 iat_sum_ns;
};

struct cla_proc_state {
    __u32 pid;
    __u32 uid;
    char  comm[16];
    __u64 syscall_count;
    __u64 execve_count;
    __u64 mmap_count;
};

struct cla_corr_record {
    __u64 cookie;
    __u64 window_start_ns;
    struct cla_flow_stats  net;
    struct cla_proc_state  proc;
    __u8  layer_coverage;
    __u8  pad[7];
};

/* ── Helper: resolve fd → struct sock* ───────────────────── */

static __always_inline struct sock *get_socket_from_fd(__u64 fd_num)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return NULL;

    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) return NULL;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) return NULL;

    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array) return NULL;

    struct file *f;
    bpf_probe_read_kernel(&f, sizeof(f), fd_array + fd_num);
    if (!f) return NULL;

    struct socket *sock = BPF_CORE_READ(f, private_data);
    if (!sock) return NULL;

    return BPF_CORE_READ(sock, sk);
}

static __always_inline __u64 get_socket_cookie_from_sk(struct sock *sk)
{
    if (!sk) return 0;
    return BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
}

#endif /* __COMMON_H */
