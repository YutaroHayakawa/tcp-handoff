CLANG=clang
BPFTOOL=bpftool

CFLAGS= \
	-g \
	-Wall \
	-Wextra \
	-I ../include

BPF_CFLAGS= \
	-g \
	-O3 \
	-Wall \
	-Wextra \
	-I ../include \
	-target bpf

LDFLAGS= \
	-lbpf

TARGETS = libtcpho.a

libtcpho.a: tcpho_l2redir.o
	ar -crs $@ $^

tcpho_l2redir.bpf.o: tcpho_l2redir.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $^

install: libtcpho.a tcpho_l2redir.bpf.o
	install -D libtcpho.a /usr/local/lib/libtcpho.a
	install -D tcpho_l2redir.bpf.o /var/lib/tcpho/tcpho_l2redir.bpf.o
	install -D tcpho.h /usr/local/include/tcpho/tcpho.h

clean:
	- rm -rf $(TARGETS) *.o
