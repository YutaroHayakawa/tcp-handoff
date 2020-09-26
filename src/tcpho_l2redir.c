#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <linux/if_ether.h>

#include <bpf/bpf.h>

#include "tcpho.h"

#define PIN_PATH "/sys/fs/bpf/tcpho/l2redir"
#define PINNED_MAP_PATH PIN_PATH "/tcpho_map"

#define __unused __attribute__((unused))

struct tcpho_l2redir_driver {
	int map_fd;
};

int 
tcpho_l2redir_open(struct tcpho_l2redir_driver **driverp)
{
	int map_fd;
	struct tcpho_l2redir_driver *driver;

	if (driverp == NULL) {
		return EINVAL;
	}

	driver = malloc(sizeof(*driver));
	if (driver == NULL) {
		return errno;
	}

	map_fd = bpf_obj_get(PINNED_MAP_PATH);
	if (map_fd == -1) {
		return errno;
	}

	driver->map_fd = map_fd;

	*driverp = driver;

	return 0;
}

int
tcpho_l2redir_add_rule(struct tcpho_l2redir_driver *driver,
		int sock, uint8_t *to, enum tcpho_state state)
{
	struct tcpho_l2redir_rule rule;

  if (sock < 0 || to == NULL || state >= TCPHO_STATE_MAX) {
    return EINVAL;
  }

	rule.state = state;
	memcpy(rule.to, to, 6);

	return bpf_map_update_elem(driver->map_fd, &sock, &rule, 0);
}

int
tcpho_l2redir_modify_rule(struct tcpho_l2redir_driver *driver,
    int sock, enum tcpho_state state)
{
	int error;
	struct tcpho_l2redir_rule rule;

	/*
	 * Fetch and modify. Assume there is no concurrent writer
	 */
	error = bpf_map_lookup_elem(driver->map_fd, &sock, &rule);
	if (error == -1) {
		return errno;
	}

	rule.state = state;

	return bpf_map_update_elem(driver->map_fd, &sock, &rule, 0);
}

void
tcpho_l2redir_close(struct tcpho_l2redir_driver *driver)
{
	if (driver == NULL) {
		return;
	}

	close(driver->map_fd);
	free(driver);
}
