#pragma once

enum tcpho_state {
	TCP_HO_STATE_BLOCKING,
	TCP_HO_STATE_FORWARDING,
	TCP_HO_STATE_MAX
};

struct tcpho_l2info {
	uint32_t state;
	uint8_t to[6];
};

struct tcpho_l2sw_add_attr {
	int sock;
	uint8_t dmac[6];
};

struct tcpho_l2sw_mod_attr {
	uint32_t cur_state;
	uint32_t new_state;
};

struct tcpho_l2sw_del_attr {
	int sock;
};

struct tcpho_l2sw_driver {
	int (*add)(struct tcpho_l2sw_driver *,
			struct tcpho_l2sw_add_attr *);
	int (*mod)(struct tcpho_l2sw_driver *,
			struct tcpho_l2sw_mod_attr *);
	int (*del)(struct tcpho_l2sw_driver *,
			struct tcpho_l2sw_del_attr *);
};

int tcpho_l2sw_add_rule(struct tcpho_l2sw_driver *, struct tcpho_l2sw_add_attr *);
int tcpho_l2sw_modify_rule(struct tcpho_l2sw_driver *, struct tcpho_l2sw_mod_attr *);
int tcpho_l2sw_delete_rule(struct tcpho_l2sw_driver *, struct tcpho_l2sw_del_attr *);
