#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "tcp_ho_redirect.skel.h"

const char *attach_command_template =
	"tc qdisc add dev %s clsact && "
	"tc filter add dev %s ingress bpf direct-action pinned /sys/fs/bpf/tcp_ho_redirect_%d";

const char *detach_command_template = "tc qdisc del dev %s clsact";

static int
attach_to_tc(pid_t pid, char *ifname, char *path)
{
	int error = 0;
	char *command;

	error = asprintf(&command, attach_command_template, ifname, ifname, pid);
	if (error == -1) {
		fprintf(stderr, "Failed to create TC command string\n");
		return -1;
	}

	error = system(command);
	if (error == -1) {
		fprintf(stderr, "Failed to exec TC command\n");
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
		fprintf(stderr, "Failed to create TC command string\n");
		return -1;
	}

	error = system(command);
	if (error == -1) {
		fprintf(stderr, "Failed to exec TC command\n");
		goto err0;
	}

err0:
	free(command);
	return error;
}

int
main(void)
{
	int error;
	pid_t pid;
	char *path;
	struct tcp_ho_redirect_bpf *obj;

	pid = getpid();

	obj = tcp_ho_redirect_bpf__open_and_load();
	if (obj == NULL) {
		fprintf(stderr, "Cannot load bpf program %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	error = asprintf(&path, "/sys/fs/bpf/tcp_ho_redirect_%d", pid);
	if (error == -1) {
		fprintf(stderr, "Failed to create path string\n");
		return EXIT_FAILURE;
	}

	error = bpf_program__pin(obj->progs.redirect_main, path);
	if (error != 0) {
		fprintf(stderr, "Failed to pin bpf program\n");
		return EXIT_FAILURE;
	}

	error = attach_to_tc(pid, "eth1", path);
	if (error == -1) {
		fprintf(stderr, "Failed to attach bpf program\n");
		return EXIT_FAILURE;
	}

	error = detach_from_tc("eth1");
	if (error == -1) {
		fprintf(stderr, "Failed to dettach bpf program\n");
		return EXIT_FAILURE;
	}

	error = bpf_program__unpin(obj->progs.redirect_main, path);
	if (error != 0) {
		fprintf(stderr, "Failed to unpin bpf program\n");
		return EXIT_FAILURE;
	}

	free(path);

	tcp_ho_redirect_bpf__destroy(obj);

	return EXIT_SUCCESS;
}
