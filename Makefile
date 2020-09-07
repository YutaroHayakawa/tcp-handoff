CLANG=clang
BPFTOOL=bpftool

TARGETS = test tcp_ho_redirect.skel.h tcp_ho_redirect.bpf.o

test: tcp_ho_redirect.skel.h
	$(CC) -o $@ -g -Wall test.c -lbpf

tcp_ho_redirect.skel.h: tcp_ho_redirect.bpf.o
	$(BPFTOOL) gen skeleton tcp_ho_redirect.bpf.o > tcp_ho_redirect.skel.h

tcp_ho_redirect.bpf.o: tcp_ho_redirect.bpf.c
	$(CLANG) -target bpf -Wall -O3 -g -c $^

clean:
	- rm -rf $(TARGETS)
