#pragma once

#define TCPHO_PINNED_PREFIX "/sys/fs/bpf/tcpho"
#define TCPHO_L2REDIR_PROG_PATH TCPHO_PINNED_PREFIX "/l2redir_prog"
#define TCPHO_L2REDIR_MAP_PATH TCPHO_PINNED_PREFIX "/l2redir_map"

struct tcpho_l2redir_driver;

enum tcpho_state {
	TCPHO_STATE_BLOCKING,
	TCPHO_STATE_FORWARDING,
	TCPHO_STATE_MAX
};

struct tcpho_l2redir_rule {
	uint32_t state;
	uint8_t to[6];
};

int tcpho_l2redir_open(struct tcpho_l2redir_driver **);
int tcpho_l2redir_add_rule(struct tcpho_l2redir_driver *, int, uint8_t *, enum tcpho_state);
int tcpho_l2redir_modify_rule(struct tcpho_l2redir_driver *, int, enum tcpho_state);
void tcpho_l2redir_close(struct tcpho_l2redir_driver *);
