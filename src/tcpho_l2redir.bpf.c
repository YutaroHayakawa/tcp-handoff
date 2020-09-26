#include <stdint.h>
#include <stddef.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <tcpho/tcpho.h>

#define __inline __attribute__((always_inline))

#define assert_len(interest, end) ({ \
	if ((void *)(interest + 1) > data_end) { \
		return TC_ACT_SHOT; \
	} \
})

struct packet {
	struct ethhdr *eth;
	struct bpf_sock_tuple tuple;
};

struct mac_addr {
	uint8_t addr[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct mac_addr);
	__uint(max_entries, 256);
} ifindex_to_mac SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tcpho_l2redir_rule);
} tcpho_map SEC(".maps");

static __inline int
parse_tcp_v4(void *data, void *data_end, uint32_t *offset, struct packet *pkt)
{
	struct tcphdr *tcp;

	tcp = (struct tcphdr *)(data + *offset);
	assert_len(tcp, data_end);

	*offset += sizeof(*tcp);

	pkt->tuple.ipv4.sport = tcp->source;
	pkt->tuple.ipv4.dport = tcp->dest;

	return 0;
}

static __inline int
parse_ipv4(void *data, void *data_end, uint32_t *offset, struct packet *pkt)
{
	struct iphdr *ip;

	ip = (struct iphdr *)(data + *offset);
	assert_len(ip, data_end);

	*offset += sizeof(*ip);

	pkt->tuple.ipv4.saddr = ip->saddr;
	pkt->tuple.ipv4.daddr = ip->daddr;

	return parse_tcp_v4(data, data_end, offset, pkt);
}

static __inline int
parse_ethernet(void *data, void *data_end,  uint32_t *offset, struct packet *pkt)
{
	struct ethhdr *eth;

	eth = (struct ethhdr *)data;
	assert_len(eth, data_end);

	*offset += sizeof(*eth);
	pkt->eth = eth;

	switch (eth->h_proto) {
	case bpf_htons(ETH_P_IP):
		return parse_ipv4(data, data_end, offset, pkt);
	default:
		return -1;
	}
}

SEC("classifier") int
l2redir_main(struct __sk_buff *skb)
{
	int action;
	uint8_t *mymac;
	struct packet pkt;
  int ingress_ifindex;
	uint32_t offset = 0;
	struct bpf_sock *sk;
	struct tcpho_l2redir_rule *rule;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (parse_ethernet(data, data_end, &offset, &pkt)) {
		// Not a target packet or failed to parse. Pass it.
		action = TC_ACT_PIPE;
		goto end0;
	}

	sk = bpf_sk_lookup_tcp(skb, &pkt.tuple, sizeof(pkt.tuple.ipv4), -1, 0);
	if (sk == NULL) {
		// Socket didn't match. Pass it.
		action = TC_ACT_PIPE;
		goto end0;
	}

	rule = bpf_sk_storage_get(&tcpho_map, sk, NULL, 0);
	if (rule == NULL) {
		// Socket is not under handoff. Pass it.
		action = TC_ACT_PIPE;
		goto end1;
	}

	if (rule->state == TCPHO_STATE_BLOCKING) {
		// This socket is blocking. Drop it.
		action = TC_ACT_SHOT;
		goto end1;
	}

	if (rule->state == TCPHO_STATE_FORWARDING) {
    ingress_ifindex = skb->ingress_ifindex;
		mymac = bpf_map_lookup_elem(&ifindex_to_mac, &ingress_ifindex);
		if (mymac == NULL) {
			action = TC_ACT_PIPE;
			goto end1;
		}

		// This socket is forwarding. Redirect it.
		__builtin_memcpy(pkt.eth->h_dest, rule->to, ETH_ALEN);
		__builtin_memcpy(pkt.eth->h_source, mymac, ETH_ALEN);
		action = bpf_redirect(skb->ingress_ifindex, 0);

		goto end1;
	}

	// Impossible. Drop it.
	action = TC_ACT_SHOT;

end1:
	bpf_sk_release(sk);
end0:
	return action;
}
