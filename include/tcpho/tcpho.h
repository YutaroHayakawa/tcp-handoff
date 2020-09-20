#pragma once

enum tcpho_state {
	TCPHO_STATE_BLOCKING,
	TCPHO_STATE_FORWARDING,
	TCPHO_STATE_MAX
};

enum tcpho_errors {
	// Use Linux errno for general errors
	LIBTCPHO_ERRNO_START = 4000,
	LIBTCPHO_ERRNO_LIBBPF, // libbpf error
	LIBTCPHO_ERRNO_TCCMD, // tc command error
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
	int sock;
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

int tcpho_l2redir_driver_create(struct tcpho_l2sw_driver **, char *);
int tcpho_l2redir_driver_destroy(struct tcpho_l2sw_driver *);
int tcpho_l2sw_add_rule(struct tcpho_l2sw_driver *, struct tcpho_l2sw_add_attr *);
int tcpho_l2sw_modify_rule(struct tcpho_l2sw_driver *, struct tcpho_l2sw_mod_attr *);
int tcpho_l2sw_delete_rule(struct tcpho_l2sw_driver *, struct tcpho_l2sw_del_attr *);
