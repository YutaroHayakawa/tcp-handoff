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
#include <tcpho/tcpho_l2sw.h>

#include "tcpho_l2redir.skel.h"

#define PINNED_PROG_PATH "/sys/fs/bpf/tcpho_l2redir"
#define __unused __attribute__((unused))

const char *attach_command_template =
	"tc qdisc add dev %s clsact && "
	"tc filter add dev %s ingress bpf direct-action pinned " PINNED_PROG_PATH;

const char *detach_command_template = "tc qdisc del dev %s clsact";

static int
attach_to_tc(char *ifname)
{
	int error = 0;
	char *command;

	// TODO: Need the validation of the input ifname

	error = asprintf(&command, attach_command_template, ifname, ifname);
	if (error == -1) {
		return errno;
	}

	error = system(command);
	if (error != 0) {
		error = errno;
		goto err0;
	}

err0:
	free(command);
	return error;
}

static int
detach_from_tc(char *ifname)
{
	int error = 0;
	char *command;

	error = asprintf(&command, detach_command_template, ifname);
	if (error == -1) {
		return errno;
	}

	error = system(command);
	if (error != 0) {
		error = errno;
		goto err0;
	}

err0:
	free(command);
	return error;
}

enum tcpho_errors {
	// Use Linux errno for general errors
	LIBTCP_HO_ERRNO_START = 4000,
	LIBTCP_HO_ERRNO_LIBBPF, // libbpf error
	LIBTCP_HO_ERRNO_TCCMD, // tc command error
};

struct tcpho_l2redir_driver {
	char *attached_iface;
	struct tcpho_l2sw_driver base;
	struct tcpho_l2redir_bpf *bpf;
};

int
tcpho_l2redir_add_rule(struct tcpho_l2sw_driver *_driver,
		struct tcpho_l2sw_add_attr *attr)
{
	int map_fd;
	struct tcpho_l2info info;
	struct tcpho_l2redir_driver *driver =
		(struct tcpho_l2redir_driver *)_driver;

	map_fd = bpf_map__fd(driver->bpf->maps.tcp_handoff_map);

	info.state = TCPHO_STATE_BLOCKING;
	memcpy(info.to, attr->dmac, 6);

	return bpf_map_update_elem(map_fd, &attr->sock, &info, 0);
}

int
tcpho_l2redir_modify_rule(struct tcpho_l2sw_driver *_driver,
		struct tcpho_l2sw_mod_attr *attr)
{
	int error, map_fd;
	struct tcpho_l2info info;
	struct tcpho_l2redir_driver *driver =
		(struct tcpho_l2redir_driver *)_driver;

	map_fd = bpf_map__fd(driver->bpf->maps.tcp_handoff_map);

	/*
	 * Fetch and modify. Assume there is no concurrent writer
	 */
	error = bpf_map_lookup_elem(map_fd, &attr->sock, &info);
	if (error == -1) {
		return errno;
	}

	info.state = TCPHO_STATE_FORWARDING;

	return bpf_map_update_elem(map_fd, &attr->sock, &info, 0);
}

int
tcpho_l2redir_delete_rule(__unused struct tcpho_l2sw_driver *_driver,
		__unused struct tcpho_l2sw_del_attr *attr)
{
	/*
	 * Socket local storage will be deleted with socket.
	 * We don't have to delete it explicitely.
	 */
	return 0;
}

int
tcpho_l2redir_driver_create(struct tcpho_l2redir_driver **driverp, char *iface)
{
	int error;
	char *attached_iface;
	struct tcpho_l2redir_bpf *bpf;
	struct tcpho_l2redir_driver *driver;

	if (driverp == NULL) {
		return EINVAL;
	}

	attached_iface = strdup(iface);
	if (attached_iface == NULL) {
		return ENOMEM;
	}

	driver = malloc(sizeof(*driver));
	if (driver == NULL) {
		error = ENOMEM;
		goto err0;
	}

	bpf = tcpho_l2redir_bpf__open_and_load();
	if (bpf == NULL) {
		error = LIBTCP_HO_ERRNO_LIBBPF;
		goto err1;
	}

	error = bpf_program__pin(bpf->progs.l2redir_main, PINNED_PROG_PATH);
	if (error != 0) {
		error = LIBTCP_HO_ERRNO_LIBBPF;
		goto err2;
	}

	error = attach_to_tc(iface);
	if (error != 0) {
		error = LIBTCP_HO_ERRNO_TCCMD;
		goto err3;
	}

	driver->base.add = tcpho_l2redir_add_rule;
	driver->base.mod = tcpho_l2redir_modify_rule;
	driver->base.del = tcpho_l2redir_delete_rule;
	driver->attached_iface = attached_iface;
	driver->bpf = bpf;

	*driverp = driver;

	return 0;

err3:
	error = bpf_program__unpin(bpf->progs.l2redir_main, PINNED_PROG_PATH);
	assert(error == 0);
err2:
	tcpho_l2redir_bpf__destroy(bpf);
err1:
	free(driver);
err0:
	free(attached_iface);
	return error;
}

int
tcpho_l2redir_driver_destroy(struct tcpho_l2redir_driver *driver)
{
	int error;

	if (driver == NULL) {
		return EINVAL;
	}

	error = detach_from_tc(driver->attached_iface);
	if (error != 0) {
		return LIBTCP_HO_ERRNO_TCCMD;
	}

	error = bpf_program__unpin(driver->bpf->progs.l2redir_main, PINNED_PROG_PATH);
	if (error != 0) {
		return LIBTCP_HO_ERRNO_LIBBPF;
	}

	tcpho_l2redir_bpf__destroy(driver->bpf);

	free(driver->attached_iface);

	free(driver);

	return 0;
}
