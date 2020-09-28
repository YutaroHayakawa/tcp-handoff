#pragma once

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

struct tcpho_tcp_state {
  uint32_t seq;
  uint32_t ack;
  uint64_t sendq_len;
  uint64_t unsentq_len;
  uint64_t recvq_len;
  uint32_t self_addr;
  uint32_t self_port;
  uint32_t peer_addr;
  uint32_t peer_port;
  uint32_t mss;
  uint32_t send_wscale;
  uint32_t recv_wscale;
  uint32_t timestamp;
  uint32_t snd_wl1;
  uint32_t snd_wnd;
  uint32_t max_window;
  uint32_t rcv_wnd;
  uint32_t rcv_wup;
  uint8_t *sendq;
  uint8_t *recvq;
};

int tcpho_l2redir_open(struct tcpho_l2redir_driver **);
int tcpho_l2redir_add_rule(struct tcpho_l2redir_driver *, int, uint8_t *, enum tcpho_state);
int tcpho_l2redir_modify_rule(struct tcpho_l2redir_driver *, int, enum tcpho_state);
void tcpho_l2redir_close(struct tcpho_l2redir_driver *);

int tcpho_tcp_export(int sock, struct tcpho_tcp_state *state);
int tcpho_tcp_import(int sock, struct tcpho_tcp_state *state);
