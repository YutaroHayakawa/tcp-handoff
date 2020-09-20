CLANG=clang
BPFTOOL=bpftool

CFLAGS= \
	-g \
	-Wall \
	-Wextra \
	-I include

BPF_CFLAGS= \
	-g \
	-O3 \
	-Wall \
	-Wextra \
	-I include \
	-target bpf

LDFLAGS= \
	-lbpf
	

TARGETS = libtcpho.a tcpho_l2redir.skel.h

libtcpho.a: tcpho_l2sw.o tcpho_l2redir.o
	ar -crs $@ $^

tcpho_l2redir.o: tcpho_l2redir.skel.h

tcpho_l2redir.skel.h: tcpho_l2redir.bpf.o
	$(BPFTOOL) gen skeleton $^ > tcpho_l2redir.skel.h

tcpho_l2redir.bpf.o: tcpho_l2redir.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $^

clean:
	- rm -rf $(TARGETS) *.o
