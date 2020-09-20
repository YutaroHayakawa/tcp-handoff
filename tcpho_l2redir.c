#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <linux/if_ether.h>

#include <tcpho/tcpho_l2sw.h>

#include "tcpho_l2redir.skel.h"

#define PINNED_PROG_PATH "/sys/fs/bpf/tcpho_l2redir"

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
