// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * cs-public0 flow probe: read-only observation of first packets on Linux
 * interfaces (guest taps and the public bridge uplink).
 *
 * Every program returns TCX_NEXT: it never drops, redirects or modifies a
 * packet and does not terminate the TCX chain of other owners.
 *
 *   flow_guest_out  tcx_ingress on a guest tap  (traffic leaving the guest)
 *   flow_guest_in   tcx_egress  on a guest tap  (replies towards the guest)
 *   flow_uplink     tcx_egress  on the uplink   (traffic leaving after SNAT)
 *
 * Records (IPv4 TCP SYN without ACK) go to a bounded queue map; when it is
 * full the record is counted as lost, never blocking the packet path.
 * Per-interface counters feed the behaviour detectors in userspace.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef TCX_NEXT
#define TCX_NEXT -1
#endif

#define SIDE_GUEST 1
#define SIDE_UPLINK 2

/* Service port classes for fan-out detection (D3). Index 0 = other. */
#define SVC_OTHER 0
#define SVC_SSH 1
#define SVC_TELNET 2
#define SVC_SMTP 3
#define SVC_SMB 4
#define SVC_RDP 5
#define SVC_VNC 6
#define SVC_MAX 7

struct flow_record {
	__u64 ts_tai_ns;
	__u32 ifindex;
	__u32 saddr;	/* network byte order */
	__u32 daddr;	/* network byte order */
	__u32 seq;	/* host byte order */
	__u16 sport;	/* host byte order */
	__u16 dport;	/* host byte order */
	__u16 ip_id;	/* host byte order */
	__u8 ttl;
	__u8 side;
	__u32 pad[2];	/* explicit: no implicit tail padding (40 bytes) */
};
_Static_assert(sizeof(struct flow_record) == 40, "flow_record ABI");

/* DNS question capture for the guest DNS IOC detector (D7). Userspace parses
 * the name, compares it with the qualified domain catalog and discards it;
 * only catalog matches are retained. */
#define DNS_CAP 128

struct dns_record {
	__u64 ts_tai_ns;
	__u32 ifindex;
	__u32 saddr;	/* network byte order */
	__u32 daddr;	/* network byte order */
	__u16 sport;	/* host byte order */
	__u16 dport;	/* host byte order */
	__u16 len;	/* copied payload bytes */
	__u16 pad;
	__u8 payload[DNS_CAP];
	__u32 pad2;
};
_Static_assert(sizeof(struct dns_record) == 160, "dns_record ABI");

struct if_counters {
	__u64 packets_out;
	__u64 bytes_out;
	__u64 syn_out;
	__u64 udp_out;
	__u64 synack_in;
	__u64 rst_in;
	__u64 svc_syn[SVC_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 65536);
	__type(value, struct flow_record);
} flow_records SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct if_counters);
} flow_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 16384);
	__type(value, struct dns_record);
} flow_dns SEC(".maps");

/* [0] records lost on a full queue, [1] parse skipped (non-IPv4/short),
 * [2] DNS records lost on a full queue */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} flow_stats SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&flow_stats, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline struct if_counters *counters(__u32 ifindex)
{
	struct if_counters *c = bpf_map_lookup_elem(&flow_counters, &ifindex);

	if (!c) {
		struct if_counters zero;

		__builtin_memset(&zero, 0, sizeof(zero));
		bpf_map_update_elem(&flow_counters, &ifindex, &zero, BPF_NOEXIST);
		c = bpf_map_lookup_elem(&flow_counters, &ifindex);
	}
	return c;
}

static __always_inline __u32 svc_class(__u16 port)
{
	switch (port) {
	case 22: return SVC_SSH;
	case 23: return SVC_TELNET;
	case 25: return SVC_SMTP;
	case 445: return SVC_SMB;
	case 3389: return SVC_RDP;
	case 5900: return SVC_VNC;
	default: return SVC_OTHER;
	}
}

/* Returns a pointer to the IPv4 header or NULL. */
static __always_inline struct iphdr *ipv4(struct __sk_buff *skb, void **l4)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	__u32 ihl;

	if ((void *)(eth + 1) > end || eth->h_proto != bpf_htons(ETH_P_IP))
		return NULL;
	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > end || ip->version != 4)
		return NULL;
	ihl = ip->ihl * 4;
	if (ihl < sizeof(*ip))
		return NULL;
	/* Non-first fragments carry no transport header. */
	if (ip->frag_off & bpf_htons(0x1fff))
		return NULL;
	*l4 = (void *)ip + ihl;
	return ip;
}

static __always_inline void emit(struct iphdr *ip, struct tcphdr *tcp,
				 __u32 ifindex, __u8 side)
{
	struct flow_record rec;

	/* Zero every byte before passing the stack buffer to a helper. */
	__builtin_memset(&rec, 0, sizeof(rec));
	rec.ts_tai_ns = bpf_ktime_get_tai_ns();
	rec.ifindex = ifindex;
	rec.saddr = ip->saddr;
	rec.daddr = ip->daddr;
	rec.seq = bpf_ntohl(tcp->seq);
	rec.sport = bpf_ntohs(tcp->source);
	rec.dport = bpf_ntohs(tcp->dest);
	rec.ip_id = bpf_ntohs(ip->id);
	rec.ttl = ip->ttl;
	rec.side = side;

	if (bpf_map_push_elem(&flow_records, &rec, BPF_ANY))
		stat_inc(0);
}

static __always_inline void emit_dns(struct __sk_buff *skb, struct iphdr *ip, void *l4)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct udphdr *udp = l4;
	struct dns_record rec;
	__u32 off, n;

	if ((void *)(udp + 1) > end || udp->dest != bpf_htons(53))
		return;
	n = bpf_ntohs(udp->len);
	if (n <= sizeof(*udp) + 12)
		return;
	n -= sizeof(*udp);
	if (n > DNS_CAP)
		n = DNS_CAP;
	off = (__u32)((void *)(udp + 1) - data);
	__builtin_memset(&rec, 0, sizeof(rec));
	/* Hide n from the optimiser so the explicit range check survives: older
	 * verifiers (6.17) do not infer the lower bound and reject a possibly
	 * zero-sized bpf_skb_load_bytes(); newer ones (7.0) accept either form. */
	asm volatile("" : "+r"(n));
	if (n < 13 || n > DNS_CAP)
		return;
	if (bpf_skb_load_bytes(skb, off, rec.payload, n))
		return;
	rec.ts_tai_ns = bpf_ktime_get_tai_ns();
	rec.ifindex = skb->ifindex;
	rec.saddr = ip->saddr;
	rec.daddr = ip->daddr;
	rec.sport = bpf_ntohs(udp->source);
	rec.dport = 53;
	rec.len = n;
	if (bpf_map_push_elem(&flow_dns, &rec, BPF_ANY))
		stat_inc(2);
}

static __always_inline int observe_out(struct __sk_buff *skb, __u8 side)
{
	void *end = (void *)(long)skb->data_end;
	struct if_counters *c;
	struct tcphdr *tcp;
	struct iphdr *ip;
	void *l4;

	ip = ipv4(skb, &l4);
	if (!ip) {
		stat_inc(1);
		return TCX_NEXT;
	}
	c = side == SIDE_GUEST ? counters(skb->ifindex) : NULL;
	if (c) {
		__sync_fetch_and_add(&c->packets_out, 1);
		__sync_fetch_and_add(&c->bytes_out, skb->len);
	}
	if (ip->protocol == IPPROTO_UDP) {
		if (c)
			__sync_fetch_and_add(&c->udp_out, 1);
		if (side == SIDE_GUEST)
			emit_dns(skb, ip, l4);
		return TCX_NEXT;
	}
	if (ip->protocol != IPPROTO_TCP)
		return TCX_NEXT;
	tcp = l4;
	if ((void *)(tcp + 1) > end)
		return TCX_NEXT;
	if (!tcp->syn || tcp->ack)
		return TCX_NEXT;
	if (c) {
		__u32 svc = svc_class(bpf_ntohs(tcp->dest));

		__sync_fetch_and_add(&c->syn_out, 1);
		if (svc < SVC_MAX)
			__sync_fetch_and_add(&c->svc_syn[svc], 1);
	}
	emit(ip, tcp, skb->ifindex, side);
	return TCX_NEXT;
}

SEC("tc")
int flow_guest_out(struct __sk_buff *skb)
{
	return observe_out(skb, SIDE_GUEST);
}

SEC("tc")
int flow_uplink(struct __sk_buff *skb)
{
	return observe_out(skb, SIDE_UPLINK);
}

SEC("tc")
int flow_guest_in(struct __sk_buff *skb)
{
	void *end = (void *)(long)skb->data_end;
	struct if_counters *c;
	struct tcphdr *tcp;
	struct iphdr *ip;
	void *l4;

	ip = ipv4(skb, &l4);
	if (!ip || ip->protocol != IPPROTO_TCP)
		return TCX_NEXT;
	tcp = l4;
	if ((void *)(tcp + 1) > end)
		return TCX_NEXT;
	if (!(tcp->rst || (tcp->syn && tcp->ack)))
		return TCX_NEXT;
	c = counters(skb->ifindex);
	if (!c)
		return TCX_NEXT;
	if (tcp->rst)
		__sync_fetch_and_add(&c->rst_in, 1);
	else
		__sync_fetch_and_add(&c->synack_in, 1);
	return TCX_NEXT;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
