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

#include <tcpho/tcpho_l2sw.h>

#define __inline __attribute__((always_inline))

#define assert_len(interest, end) ({ \
	if ((void *)(interest + 1) > data_end) { \
		return TC_ACT_SHOT; \
	} \
})

uint8_t mymac[ETH_ALEN] = {0};

struct packet {
	struct ethhdr *eth;
	struct bpf_sock_tuple tuple;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tcpho_l2info);
} tcp_handoff_map SEC(".maps");

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
	struct packet pkt;
	uint32_t offset = 0;
	struct bpf_sock *sk;
	struct tcpho_l2info *ho_info;
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

	ho_info = bpf_sk_storage_get(&tcp_handoff_map, sk, NULL, 0);
	if (ho_info == NULL) {
		// Socket is not under handoff. Pass it.
		action = TC_ACT_PIPE;
		goto end1;
	}

	if (ho_info->state == TCPHO_STATE_BLOCKING) {
		// This socket is blocking. Drop it.
		action = TC_ACT_SHOT;
		goto end1;
	}

	if (ho_info->state == TCPHO_STATE_FORWARDING) {
		// This socket is forwarding. Redirect it.
		__builtin_memcpy(pkt.eth->h_dest, ho_info->to, ETH_ALEN);
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
