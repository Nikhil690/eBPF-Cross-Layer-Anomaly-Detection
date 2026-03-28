//go:build ignore

#include "common.h"

/* ── Maps (XDP-owned) ─────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct cla_flow_key);
    __type(value, struct cla_flow_stats);
} flow_stats_map SEC(".maps");

/* ── Packet parser ────────────────────────────────────────── */

static __always_inline int parse_tcp(struct xdp_md *ctx,
                                     struct cla_flow_key *key,
                                     __u8 *flags)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return -1;
    if (ip->protocol != IPPROTO_TCP) return -1;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return -1;

    key->src_ip   = ip->saddr;
    key->dst_ip   = ip->daddr;
    key->src_port = tcp->source;
    key->dst_port = tcp->dest;
    key->proto    = ip->protocol;

    *flags = (tcp->syn << 1) | (tcp->rst << 2) |
             (tcp->fin << 3) | (tcp->psh << 4);
    return 0;
}

/* ── XDP program: accumulate per-flow stats ───────────────── */

SEC("xdp")
int xdp_flow_monitor(struct xdp_md *ctx)
{
    struct cla_flow_key key = {};
    __u8 flags = 0;

    if (parse_tcp(ctx, &key, &flags) < 0)
        return XDP_PASS;

    __u64 now     = bpf_ktime_get_ns();
    __u32 pkt_len = ctx->data_end - ctx->data;

    struct cla_flow_stats *s = bpf_map_lookup_elem(&flow_stats_map, &key);
    if (!s) {
        struct cla_flow_stats init = {
            .pkt_count     = 1,
            .byte_count    = pkt_len,
            .first_seen_ns = now,
            .last_seen_ns  = now,
            .syn_count     = (flags >> 1) & 1,
            .rst_count     = (flags >> 2) & 1,
            .fin_count     = (flags >> 3) & 1,
            .tcp_flags_seen = flags,
        };
        bpf_map_update_elem(&flow_stats_map, &key, &init, BPF_ANY);
    } else {
        __sync_fetch_and_add(&s->pkt_count, 1);
        __sync_fetch_and_add(&s->byte_count, pkt_len);
        if ((flags >> 1) & 1) __sync_fetch_and_add(&s->syn_count, 1);
        if ((flags >> 2) & 1) __sync_fetch_and_add(&s->rst_count, 1);
        if ((flags >> 3) & 1) __sync_fetch_and_add(&s->fin_count, 1);
        s->tcp_flags_seen |= flags;
        s->last_seen_ns = now;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
