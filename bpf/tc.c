//go:build ignore

#include "common.h"

/* ── Maps (TC-owned, flow_stats_map shared from XDP via Go) ── */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct cla_flow_key);
    __type(value, struct cla_flow_stats);
} flow_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct cla_flow_key);
    __type(value, __u64);
} cookie_map SEC(".maps");

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

/* ── TC ingress: correlate XDP flow_stats with socket cookie ── */

SEC("tc")
int tc_correlate(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

    /* Reverse egress key to match XDP ingress perspective:
     * XDP sees remote→local; TC egress sees local→remote.
     * Swap so both use remote=src, local=dst for map lookup. */
    struct cla_flow_key key = {
        .src_ip   = ip->daddr,
        .dst_ip   = ip->saddr,
        .src_port = tcp->dest,
        .dst_port = tcp->source,
        .proto    = ip->protocol,
    };

    __u64 cookie = bpf_get_socket_cookie(skb);
    if (cookie == 0)
        return TC_ACT_OK;

    /* Store 5-tuple → cookie mapping */
    bpf_map_update_elem(&cookie_map, &key, &cookie, BPF_ANY);

    /* Look up XDP-accumulated flow stats */
    struct cla_flow_stats *fs = bpf_map_lookup_elem(&flow_stats_map, &key);

    /* Look up / create correlation record */
    struct cla_corr_record *rec = bpf_map_lookup_elem(&corr_window_map, &cookie);
    if (!rec) {
        struct cla_corr_record new_rec = {};
        new_rec.cookie           = cookie;
        new_rec.window_start_ns  = bpf_ktime_get_ns();
        new_rec.layer_coverage   = LAYER_TC;
        if (fs) {
            new_rec.net = *fs;
            new_rec.layer_coverage |= LAYER_XDP;
        }
        bpf_map_update_elem(&corr_window_map, &cookie, &new_rec, BPF_ANY);
    } else {
        rec->layer_coverage |= LAYER_TC;
        if (fs) {
            rec->net = *fs;
            rec->layer_coverage |= LAYER_XDP;
        }
    }

    /* Check emission: 5 ms window elapsed or all MVP layers seen */
    rec = bpf_map_lookup_elem(&corr_window_map, &cookie);
    if (rec) {
        __u64 now = bpf_ktime_get_ns();
        __u8  want = LAYER_XDP | LAYER_TC | LAYER_SYSCALL;
        if ((now - rec->window_start_ns > 5000000) ||
            (rec->layer_coverage & want) == want) {
            struct cla_corr_record *e =
                bpf_ringbuf_reserve(&ring_events, sizeof(*e), 0);
            if (e) {
                *e = *rec;
                bpf_ringbuf_submit(e, 0);
            }
            bpf_map_delete_elem(&corr_window_map, &cookie);
        }
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
