CC= gcc
OPT= -O -Wall -I/usr/local/ssl/include -L/usr/local/ssl/lib# -g
DEFS=-DNO_SHARED_LIBS=1 -DLINUX # -DFOO # -DBIGTRACE # -DDEBUG #-DSTATS
LIBS=-liplogin2 -lhlcrypt -lcrypto -lwrap -ldl -lconffile -lvarlist -ldiv 
LDFLAGS=-L.

ACC_OPT=-fPIC -O -Wall -shared -Wl,-soname,acclib_test.1.0 -Wl,--version-script,lib.scr

IPTSRCDIR=iptables
IPTINCDIR=$(IPTSRCDIR)/include

CFLAGS = $(OPT) $(DEFS) -I$(IPTINCDIR) -I. -I/usr/local/include

IPTLIBDIR=/usr/lib/iptables
IPTLDLIB=$(IPTSRCDIR)/libiptc/libiptc.a $(IPTSRCDIR)/extensions/libext.a
IPTFLAGS=-I$(IPTINCDIR) -DIPT_LIB_DIR=\"$(IPTLIBDIR)\" -rdynamic
IPT=$(IPTFLAGS) $(IPTLDLIB)

IPLOGIN2_OBJS=main.o engine.o find_interface.o misc.o filterchains.o filterchains2.o commands.o icmpping.o arpping.o config.o accounting.o trace.o mymalloc.o usernode.o
OBJS=$(IPLOGIN2_OBJS)

TARGETS=iplogin2 find_interface testipt acclib_test.so

IPLOGIN2_SRCS=main.c engine.c find_interface.c misc.c filterchains.c \
	filterchains2.c commands.c icmpping.c arpping.c config.c trace.c \
	mymalloc.c  usernode.c
SRCS=$(IPLOGIN2_SRCS) testipt.c acclib_test.c

all: $(TARGETS)

clean:
	rm -f $(TARGETS) $(OBJS) *.o acclib_test.so *~ core

rclean:
	rm -f $(TARGETS) $(PROGS) *.o acclib_test.so *~ core
	(cd $(IPTSRCDIR); make distclean)

iplogin2: $(IPLOGIN2_OBJS) $(IPTSRCDIR)/libiptc/libiptc.a
	$(CC) --static -Os $(CFLAGS) -o iplogin2 $(IPLOGIN2_OBJS) $(IPT) $(LDFLAGS) $(LIBS)
	strip iplogin2

$(IPTSRCDIR)/libiptc/libiptc.a:
	(cd $(IPTSRCDIR); make BINDIR=/usr/sbin LIBDIR=/usr/lib MANDIR=/usr/man NO_SHARED_LIBS=1)

find_interface: find_interface.c
	$(CC) $(CFLAGS) -DTEST_NETLINK -o find_interface find_interface.c

acclib_test.so:	acclib_test.o
	${CC} ${ACC_OPT} acclib_test.o -o acclib_test.so

testipt: testipt.c filterchains2.o
	$(CC) $(CFLAGS) -o testipt testipt.c filterchains2.o $(IPT) $(LDFLAGS) $(LIBS)

install: iplogin2
	cat INSTALL

depend:
	makedepend -- $(CFLAGS) -- $(SRCS)

# DO NOT DELETE

main.o: /usr/include/stdio.h /usr/include/features.h /usr/include/sys/cdefs.h
main.o: /usr/include/gnu/stubs.h
main.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
main.o: /usr/include/bits/types.h /usr/include/bits/pthreadtypes.h
main.o: /usr/include/bits/sched.h /usr/include/libio.h
main.o: /usr/include/_G_config.h /usr/include/wchar.h
main.o: /usr/include/bits/wchar.h /usr/include/gconv.h
main.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
main.o: /usr/include/bits/stdio_lim.h /usr/include/stdlib.h
main.o: /usr/include/sys/types.h /usr/include/time.h /usr/include/endian.h
main.o: /usr/include/bits/endian.h /usr/include/sys/select.h
main.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
main.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
main.o: /usr/include/alloca.h /usr/include/string.h /usr/include/syslog.h
main.o: /usr/include/sys/syslog.h /usr/include/signal.h
main.o: /usr/include/bits/signum.h /usr/include/bits/siginfo.h
main.o: /usr/include/bits/wordsize.h /usr/include/bits/sigaction.h
main.o: /usr/include/bits/sigcontext.h /usr/include/asm/sigcontext.h
main.o: /usr/include/bits/sigstack.h /usr/include/bits/sigthread.h
main.o: /usr/include/arpa/inet.h /usr/include/netinet/in.h
main.o: /usr/include/stdint.h /usr/include/bits/socket.h
main.o: /usr/include/limits.h /usr/include/bits/posix1_lim.h
main.o: /usr/include/bits/local_lim.h /usr/include/linux/limits.h
main.o: /usr/include/bits/posix2_lim.h /usr/include/bits/sockaddr.h
main.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
main.o: /usr/include/bits/in.h /usr/include/bits/byteswap.h
main.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
main.o: /usr/include/bits/confname.h /usr/include/getopt.h /usr/include/pwd.h
main.o: /usr/include/sys/socket.h /usr/include/sys/uio.h
main.o: /usr/include/bits/uio.h /usr/include/netdb.h /usr/include/rpc/netdb.h
main.o: /usr/include/bits/netdb.h /usr/local/include/conffile.h
main.o: /usr/local/include/varlist.h usernode.h /usr/include/linux/if_arp.h
main.o: /usr/include/linux/netdevice.h /usr/include/linux/if.h
main.o: /usr/include/linux/types.h /usr/include/linux/posix_types.h
main.o: /usr/include/linux/stddef.h /usr/include/asm/posix_types.h
main.o: /usr/include/asm/types.h /usr/include/linux/socket.h
main.o: /usr/include/linux/if_ether.h /usr/include/linux/if_packet.h
main.o: /usr/include/asm/atomic.h /usr/include/linux/config.h
main.o: /usr/include/linux/autoconf.h /usr/include/asm/cache.h
main.o: /usr/include/asm/byteorder.h
main.o: /usr/include/linux/byteorder/little_endian.h
main.o: /usr/include/linux/byteorder/swab.h
main.o: /usr/include/linux/byteorder/generic.h /usr/local/include/iplogin2.h
main.o: engine.h config.h trace.h accounting.h
engine.o: /usr/include/tcpd.h /usr/include/sys/time.h /usr/include/features.h
engine.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
engine.o: /usr/include/bits/types.h
engine.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
engine.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
engine.o: /usr/include/time.h /usr/include/bits/time.h
engine.o: /usr/include/sys/select.h /usr/include/bits/select.h
engine.o: /usr/include/bits/sigset.h /usr/include/sys/timeb.h
engine.o: /usr/include/string.h /usr/include/stdlib.h
engine.o: /usr/include/sys/types.h /usr/include/endian.h
engine.o: /usr/include/bits/endian.h /usr/include/sys/sysmacros.h
engine.o: /usr/include/alloca.h /usr/include/signal.h
engine.o: /usr/include/bits/signum.h /usr/include/bits/siginfo.h
engine.o: /usr/include/bits/wordsize.h /usr/include/bits/sigaction.h
engine.o: /usr/include/bits/sigcontext.h /usr/include/asm/sigcontext.h
engine.o: /usr/include/bits/sigstack.h /usr/include/bits/sigthread.h
engine.o: /usr/include/syslog.h /usr/include/sys/syslog.h
engine.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
engine.o: /usr/include/errno.h /usr/include/bits/errno.h
engine.o: /usr/include/linux/errno.h /usr/include/asm/errno.h
engine.o: /usr/include/arpa/inet.h /usr/include/netinet/in.h
engine.o: /usr/include/stdint.h /usr/include/bits/wchar.h
engine.o: /usr/include/bits/socket.h /usr/include/limits.h
engine.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
engine.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
engine.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
engine.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
engine.o: /usr/include/bits/byteswap.h /usr/include/sys/socket.h
engine.o: /usr/include/sys/uio.h /usr/include/bits/uio.h
engine.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
engine.o: /usr/include/bits/confname.h /usr/include/getopt.h
engine.o: /usr/include/stdio.h /usr/include/libio.h /usr/include/_G_config.h
engine.o: /usr/include/wchar.h /usr/include/gconv.h
engine.o: /usr/include/bits/stdio_lim.h /usr/include/sys/ioctl.h
engine.o: /usr/include/bits/ioctls.h /usr/include/asm/ioctls.h
engine.o: /usr/include/asm/ioctl.h /usr/include/bits/ioctl-types.h
engine.o: /usr/include/sys/ttydefaults.h /usr/local/include/hlcrypt.h
engine.o: /usr/include/openssl/sha.h /usr/include/crypt.h
engine.o: /usr/local/include/varlist.h /usr/local/include/conffile.h
engine.o: /usr/local/include/divlib.h socketnode.h commands.h usernode.h
engine.o: /usr/include/linux/if_arp.h /usr/include/linux/netdevice.h
engine.o: /usr/include/linux/if.h /usr/include/linux/types.h
engine.o: /usr/include/linux/posix_types.h /usr/include/linux/stddef.h
engine.o: /usr/include/asm/posix_types.h /usr/include/asm/types.h
engine.o: /usr/include/linux/socket.h /usr/include/linux/if_ether.h
engine.o: /usr/include/linux/if_packet.h /usr/include/asm/atomic.h
engine.o: /usr/include/linux/config.h /usr/include/linux/autoconf.h
engine.o: /usr/include/asm/cache.h /usr/include/asm/byteorder.h
engine.o: /usr/include/linux/byteorder/little_endian.h
engine.o: /usr/include/linux/byteorder/swab.h
engine.o: /usr/include/linux/byteorder/generic.h
engine.o: /usr/local/include/iplogin2.h filterchains.h arpping.h
engine.o: /usr/include/linux/sockios.h icmpping.h mymalloc.h accounting.h
engine.o: misc.h config.h engine.h trace.h
find_interface.o: /usr/include/stdio.h /usr/include/features.h
find_interface.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
find_interface.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
find_interface.o: /usr/include/bits/types.h /usr/include/bits/pthreadtypes.h
find_interface.o: /usr/include/bits/sched.h /usr/include/libio.h
find_interface.o: /usr/include/_G_config.h /usr/include/wchar.h
find_interface.o: /usr/include/bits/wchar.h /usr/include/gconv.h
find_interface.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
find_interface.o: /usr/include/bits/stdio_lim.h /usr/include/stdlib.h
find_interface.o: /usr/include/sys/types.h /usr/include/time.h
find_interface.o: /usr/include/endian.h /usr/include/bits/endian.h
find_interface.o: /usr/include/sys/select.h /usr/include/bits/select.h
find_interface.o: /usr/include/bits/sigset.h /usr/include/bits/time.h
find_interface.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
find_interface.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
find_interface.o: /usr/include/bits/confname.h /usr/include/getopt.h
find_interface.o: /usr/include/string.h /usr/include/netinet/in.h
find_interface.o: /usr/include/stdint.h /usr/include/bits/wordsize.h
find_interface.o: /usr/include/bits/socket.h /usr/include/limits.h
find_interface.o: /usr/include/bits/posix1_lim.h
find_interface.o: /usr/include/bits/local_lim.h /usr/include/linux/limits.h
find_interface.o: /usr/include/bits/posix2_lim.h /usr/include/bits/sockaddr.h
find_interface.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
find_interface.o: /usr/include/bits/in.h /usr/include/bits/byteswap.h
find_interface.o: /usr/include/asm/types.h /usr/include/linux/netlink.h
find_interface.o: /usr/include/linux/rtnetlink.h /usr/include/sys/socket.h
find_interface.o: /usr/include/sys/uio.h /usr/include/bits/uio.h
find_interface.o: /usr/include/arpa/inet.h /usr/include/errno.h
find_interface.o: /usr/include/bits/errno.h /usr/include/linux/errno.h
find_interface.o: /usr/include/asm/errno.h /usr/include/netdb.h
find_interface.o: /usr/include/rpc/netdb.h /usr/include/bits/netdb.h
find_interface.o: /usr/include/syslog.h /usr/include/sys/syslog.h
find_interface.o: /usr/include/sys/ioctl.h /usr/include/bits/ioctls.h
find_interface.o: /usr/include/asm/ioctls.h /usr/include/asm/ioctl.h
find_interface.o: /usr/include/bits/ioctl-types.h
find_interface.o: /usr/include/sys/ttydefaults.h usernode.h
find_interface.o: /usr/include/linux/if_arp.h /usr/include/linux/netdevice.h
find_interface.o: /usr/include/linux/if.h /usr/include/linux/types.h
find_interface.o: /usr/include/linux/posix_types.h
find_interface.o: /usr/include/linux/stddef.h /usr/include/asm/posix_types.h
find_interface.o: /usr/include/linux/socket.h /usr/include/linux/if_ether.h
find_interface.o: /usr/include/linux/if_packet.h /usr/include/asm/atomic.h
find_interface.o: /usr/include/linux/config.h /usr/include/linux/autoconf.h
find_interface.o: /usr/include/asm/cache.h /usr/include/asm/byteorder.h
find_interface.o: /usr/include/linux/byteorder/little_endian.h
find_interface.o: /usr/include/linux/byteorder/swab.h
find_interface.o: /usr/include/linux/byteorder/generic.h
find_interface.o: /usr/local/include/iplogin2.h /usr/local/include/varlist.h
misc.o: /usr/include/stdlib.h /usr/include/features.h
misc.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
misc.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
misc.o: /usr/include/sys/types.h /usr/include/bits/types.h
misc.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
misc.o: /usr/include/time.h /usr/include/endian.h /usr/include/bits/endian.h
misc.o: /usr/include/sys/select.h /usr/include/bits/select.h
misc.o: /usr/include/bits/sigset.h /usr/include/bits/time.h
misc.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
misc.o: /usr/include/sys/wait.h /usr/include/signal.h
misc.o: /usr/include/bits/signum.h /usr/include/bits/siginfo.h
misc.o: /usr/include/bits/wordsize.h /usr/include/bits/sigaction.h
misc.o: /usr/include/bits/sigcontext.h /usr/include/asm/sigcontext.h
misc.o: /usr/include/bits/sigstack.h /usr/include/bits/sigthread.h
misc.o: /usr/include/sys/resource.h /usr/include/bits/resource.h
misc.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h
misc.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
misc.o: /usr/include/bits/confname.h /usr/include/getopt.h
misc.o: /usr/include/stdio.h /usr/include/libio.h /usr/include/_G_config.h
misc.o: /usr/include/wchar.h /usr/include/bits/wchar.h /usr/include/gconv.h
misc.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
misc.o: /usr/include/bits/stdio_lim.h /usr/include/string.h
misc.o: /usr/include/syslog.h /usr/include/sys/syslog.h config.h
misc.o: /usr/include/netinet/in.h /usr/include/stdint.h
misc.o: /usr/include/bits/socket.h /usr/include/limits.h
misc.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
misc.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
misc.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
misc.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
misc.o: /usr/include/bits/byteswap.h
filterchains.o: /usr/include/string.h /usr/include/features.h
filterchains.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
filterchains.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
filterchains.o: /usr/include/stdio.h /usr/include/bits/types.h
filterchains.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
filterchains.o: /usr/include/libio.h /usr/include/_G_config.h
filterchains.o: /usr/include/wchar.h /usr/include/bits/wchar.h
filterchains.o: /usr/include/gconv.h
filterchains.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
filterchains.o: /usr/include/bits/stdio_lim.h /usr/include/arpa/inet.h
filterchains.o: /usr/include/netinet/in.h /usr/include/stdint.h
filterchains.o: /usr/include/bits/wordsize.h /usr/include/bits/socket.h
filterchains.o: /usr/include/limits.h /usr/include/bits/posix1_lim.h
filterchains.o: /usr/include/bits/local_lim.h /usr/include/linux/limits.h
filterchains.o: /usr/include/bits/posix2_lim.h /usr/include/sys/types.h
filterchains.o: /usr/include/time.h /usr/include/endian.h
filterchains.o: /usr/include/bits/endian.h /usr/include/sys/select.h
filterchains.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
filterchains.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
filterchains.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
filterchains.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
filterchains.o: /usr/include/bits/byteswap.h /usr/include/syslog.h
filterchains.o: /usr/include/sys/syslog.h /usr/local/include/varlist.h
filterchains.o: filterchains.h filterchains2.h ./iptables/include/iptables.h
filterchains.o: ./iptables/include/iptables_common.h
filterchains.o: ./iptables/include/libiptc/libiptc.h
filterchains.o: ./iptables/include/libiptc/ipt_kernel_headers.h
filterchains.o: /usr/include/netinet/ip.h /usr/include/netinet/ip_icmp.h
filterchains.o: /usr/include/netinet/tcp.h /usr/include/netinet/udp.h
filterchains.o: /usr/include/net/if.h /usr/include/sys/socket.h
filterchains.o: /usr/include/sys/uio.h /usr/include/bits/uio.h
filterchains.o: /usr/include/linux/netfilter_ipv4/ip_tables.h
filterchains.o: /usr/include/linux/netfilter_ipv4.h
filterchains.o: /usr/include/linux/config.h /usr/include/linux/autoconf.h
filterchains.o: /usr/include/linux/netfilter.h
filterchains2.o: /usr/include/string.h /usr/include/features.h
filterchains2.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
filterchains2.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
filterchains2.o: /usr/include/netdb.h /usr/include/netinet/in.h
filterchains2.o: /usr/include/stdint.h /usr/include/bits/wchar.h
filterchains2.o: /usr/include/bits/wordsize.h /usr/include/bits/types.h
filterchains2.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
filterchains2.o: /usr/include/bits/socket.h /usr/include/limits.h
filterchains2.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
filterchains2.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
filterchains2.o: /usr/include/sys/types.h /usr/include/time.h
filterchains2.o: /usr/include/endian.h /usr/include/bits/endian.h
filterchains2.o: /usr/include/sys/select.h /usr/include/bits/select.h
filterchains2.o: /usr/include/bits/sigset.h /usr/include/bits/time.h
filterchains2.o: /usr/include/sys/sysmacros.h /usr/include/bits/sockaddr.h
filterchains2.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
filterchains2.o: /usr/include/bits/in.h /usr/include/bits/byteswap.h
filterchains2.o: /usr/include/rpc/netdb.h /usr/include/bits/netdb.h
filterchains2.o: /usr/include/errno.h /usr/include/bits/errno.h
filterchains2.o: /usr/include/linux/errno.h /usr/include/asm/errno.h
filterchains2.o: /usr/include/stdio.h /usr/include/libio.h
filterchains2.o: /usr/include/_G_config.h /usr/include/wchar.h
filterchains2.o: /usr/include/gconv.h
filterchains2.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
filterchains2.o: /usr/include/bits/stdio_lim.h /usr/include/stdlib.h
filterchains2.o: /usr/include/alloca.h /usr/include/dlfcn.h
filterchains2.o: /usr/include/bits/dlfcn.h /usr/include/ctype.h
filterchains2.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
filterchains2.o: /usr/include/bits/confname.h /usr/include/getopt.h
filterchains2.o: ./iptables/include/iptables.h
filterchains2.o: ./iptables/include/iptables_common.h
filterchains2.o: ./iptables/include/libiptc/libiptc.h
filterchains2.o: ./iptables/include/libiptc/ipt_kernel_headers.h
filterchains2.o: /usr/include/netinet/ip.h /usr/include/netinet/ip_icmp.h
filterchains2.o: /usr/include/netinet/tcp.h /usr/include/netinet/udp.h
filterchains2.o: /usr/include/net/if.h /usr/include/sys/socket.h
filterchains2.o: /usr/include/sys/uio.h /usr/include/bits/uio.h
filterchains2.o: /usr/include/linux/netfilter_ipv4/ip_tables.h
filterchains2.o: /usr/include/linux/netfilter_ipv4.h
filterchains2.o: /usr/include/linux/config.h /usr/include/linux/autoconf.h
filterchains2.o: /usr/include/linux/netfilter.h /usr/include/fcntl.h
filterchains2.o: /usr/include/bits/fcntl.h /usr/include/sys/wait.h
filterchains2.o: /usr/include/signal.h /usr/include/bits/signum.h
filterchains2.o: /usr/include/bits/siginfo.h /usr/include/bits/sigaction.h
filterchains2.o: /usr/include/bits/sigcontext.h /usr/include/asm/sigcontext.h
filterchains2.o: /usr/include/bits/sigstack.h /usr/include/bits/sigthread.h
filterchains2.o: /usr/include/sys/resource.h /usr/include/bits/resource.h
filterchains2.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h
filterchains2.o: /usr/include/arpa/inet.h /usr/include/syslog.h
filterchains2.o: /usr/include/sys/syslog.h
commands.o: /usr/include/syslog.h /usr/include/sys/syslog.h
commands.o: /usr/include/features.h /usr/include/sys/cdefs.h
commands.o: /usr/include/gnu/stubs.h
commands.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
commands.o: /usr/include/stdio.h
commands.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
commands.o: /usr/include/bits/types.h /usr/include/bits/pthreadtypes.h
commands.o: /usr/include/bits/sched.h /usr/include/libio.h
commands.o: /usr/include/_G_config.h /usr/include/wchar.h
commands.o: /usr/include/bits/wchar.h /usr/include/gconv.h
commands.o: /usr/include/bits/stdio_lim.h /usr/include/stdlib.h
commands.o: /usr/include/sys/types.h /usr/include/time.h
commands.o: /usr/include/endian.h /usr/include/bits/endian.h
commands.o: /usr/include/sys/select.h /usr/include/bits/select.h
commands.o: /usr/include/bits/sigset.h /usr/include/bits/time.h
commands.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
commands.o: /usr/include/string.h /usr/include/unistd.h
commands.o: /usr/include/bits/posix_opt.h /usr/include/bits/confname.h
commands.o: /usr/include/getopt.h /usr/include/errno.h
commands.o: /usr/include/bits/errno.h /usr/include/linux/errno.h
commands.o: /usr/include/asm/errno.h /usr/include/netinet/in.h
commands.o: /usr/include/stdint.h /usr/include/bits/wordsize.h
commands.o: /usr/include/bits/socket.h /usr/include/limits.h
commands.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
commands.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
commands.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
commands.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
commands.o: /usr/include/bits/byteswap.h /usr/include/arpa/inet.h
commands.o: /usr/local/include/varlist.h /usr/local/include/hlcrypt.h
commands.o: /usr/include/openssl/sha.h /usr/include/crypt.h
commands.o: /usr/local/include/conffile.h /usr/local/include/divlib.h
commands.o: usernode.h /usr/include/linux/if_arp.h
commands.o: /usr/include/linux/netdevice.h /usr/include/linux/if.h
commands.o: /usr/include/linux/types.h /usr/include/linux/posix_types.h
commands.o: /usr/include/linux/stddef.h /usr/include/asm/posix_types.h
commands.o: /usr/include/asm/types.h /usr/include/linux/socket.h
commands.o: /usr/include/linux/if_ether.h /usr/include/linux/if_packet.h
commands.o: /usr/include/asm/atomic.h /usr/include/linux/config.h
commands.o: /usr/include/linux/autoconf.h /usr/include/asm/cache.h
commands.o: /usr/include/asm/byteorder.h
commands.o: /usr/include/linux/byteorder/little_endian.h
commands.o: /usr/include/linux/byteorder/swab.h
commands.o: /usr/include/linux/byteorder/generic.h
commands.o: /usr/local/include/iplogin2.h filterchains.h find_interface.h
commands.o: misc.h config.h mymalloc.h accounting.h
icmpping.o: /usr/include/netinet/ip.h /usr/include/features.h
icmpping.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
icmpping.o: /usr/include/sys/types.h /usr/include/bits/types.h
icmpping.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
icmpping.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
icmpping.o: /usr/include/time.h /usr/include/endian.h
icmpping.o: /usr/include/bits/endian.h /usr/include/sys/select.h
icmpping.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
icmpping.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
icmpping.o: /usr/include/netinet/in.h /usr/include/stdint.h
icmpping.o: /usr/include/bits/wchar.h /usr/include/bits/wordsize.h
icmpping.o: /usr/include/bits/socket.h /usr/include/limits.h
icmpping.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
icmpping.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
icmpping.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
icmpping.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
icmpping.o: /usr/include/bits/byteswap.h /usr/include/netinet/ip_icmp.h
icmpping.o: /usr/include/sys/socket.h /usr/include/sys/uio.h
icmpping.o: /usr/include/bits/uio.h /usr/include/syslog.h
icmpping.o: /usr/include/sys/syslog.h
icmpping.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
icmpping.o: /usr/include/errno.h /usr/include/bits/errno.h
icmpping.o: /usr/include/linux/errno.h /usr/include/asm/errno.h
icmpping.o: /usr/include/stdlib.h /usr/include/alloca.h /usr/include/stdio.h
icmpping.o: /usr/include/libio.h /usr/include/_G_config.h
icmpping.o: /usr/include/wchar.h /usr/include/gconv.h
icmpping.o: /usr/include/bits/stdio_lim.h /usr/include/arpa/inet.h
icmpping.o: /usr/include/string.h socketnode.h usernode.h
icmpping.o: /usr/include/linux/if_arp.h /usr/include/linux/netdevice.h
icmpping.o: /usr/include/linux/if.h /usr/include/linux/types.h
icmpping.o: /usr/include/linux/posix_types.h /usr/include/linux/stddef.h
icmpping.o: /usr/include/asm/posix_types.h /usr/include/asm/types.h
icmpping.o: /usr/include/linux/socket.h /usr/include/linux/if_ether.h
icmpping.o: /usr/include/linux/if_packet.h /usr/include/asm/atomic.h
icmpping.o: /usr/include/linux/config.h /usr/include/linux/autoconf.h
icmpping.o: /usr/include/asm/cache.h /usr/include/asm/byteorder.h
icmpping.o: /usr/include/linux/byteorder/little_endian.h
icmpping.o: /usr/include/linux/byteorder/swab.h
icmpping.o: /usr/include/linux/byteorder/generic.h
icmpping.o: /usr/local/include/iplogin2.h /usr/local/include/varlist.h
icmpping.o: mymalloc.h trace.h
arpping.o: /usr/include/syslog.h /usr/include/sys/syslog.h
arpping.o: /usr/include/features.h /usr/include/sys/cdefs.h
arpping.o: /usr/include/gnu/stubs.h
arpping.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
arpping.o: /usr/include/stdlib.h
arpping.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
arpping.o: /usr/include/sys/types.h /usr/include/bits/types.h
arpping.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
arpping.o: /usr/include/time.h /usr/include/endian.h
arpping.o: /usr/include/bits/endian.h /usr/include/sys/select.h
arpping.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
arpping.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
arpping.o: /usr/include/alloca.h /usr/include/stdio.h /usr/include/libio.h
arpping.o: /usr/include/_G_config.h /usr/include/wchar.h
arpping.o: /usr/include/bits/wchar.h /usr/include/gconv.h
arpping.o: /usr/include/bits/stdio_lim.h /usr/include/sys/time.h
arpping.o: /usr/include/sys/socket.h /usr/include/sys/uio.h
arpping.o: /usr/include/bits/uio.h /usr/include/bits/socket.h
arpping.o: /usr/include/limits.h /usr/include/bits/wordsize.h
arpping.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
arpping.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
arpping.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
arpping.o: /usr/include/asm/sockios.h /usr/include/netinet/in.h
arpping.o: /usr/include/stdint.h /usr/include/bits/in.h
arpping.o: /usr/include/bits/byteswap.h /usr/include/linux/sockios.h
arpping.o: /usr/include/linux/if.h /usr/include/linux/types.h
arpping.o: /usr/include/linux/posix_types.h /usr/include/linux/stddef.h
arpping.o: /usr/include/asm/posix_types.h /usr/include/asm/types.h
arpping.o: /usr/include/linux/socket.h /usr/include/linux/if_arp.h
arpping.o: /usr/include/linux/netdevice.h /usr/include/linux/if_ether.h
arpping.o: /usr/include/linux/if_packet.h /usr/include/asm/atomic.h
arpping.o: /usr/include/linux/config.h /usr/include/linux/autoconf.h
arpping.o: /usr/include/asm/cache.h /usr/include/asm/byteorder.h
arpping.o: /usr/include/linux/byteorder/little_endian.h
arpping.o: /usr/include/linux/byteorder/swab.h
arpping.o: /usr/include/linux/byteorder/generic.h /usr/include/arpa/inet.h
arpping.o: /usr/include/string.h usernode.h /usr/local/include/iplogin2.h
arpping.o: /usr/local/include/varlist.h socketnode.h mymalloc.h trace.h
config.o: /usr/include/stdio.h /usr/include/features.h
config.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
config.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
config.o: /usr/include/bits/types.h /usr/include/bits/pthreadtypes.h
config.o: /usr/include/bits/sched.h /usr/include/libio.h
config.o: /usr/include/_G_config.h /usr/include/wchar.h
config.o: /usr/include/bits/wchar.h /usr/include/gconv.h
config.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
config.o: /usr/include/bits/stdio_lim.h /usr/include/string.h
config.o: /usr/include/arpa/inet.h /usr/include/netinet/in.h
config.o: /usr/include/stdint.h /usr/include/bits/wordsize.h
config.o: /usr/include/bits/socket.h /usr/include/limits.h
config.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
config.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
config.o: /usr/include/sys/types.h /usr/include/time.h /usr/include/endian.h
config.o: /usr/include/bits/endian.h /usr/include/sys/select.h
config.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
config.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
config.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
config.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
config.o: /usr/include/bits/byteswap.h config.h
trace.o: /usr/include/stdio.h /usr/include/features.h
trace.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
trace.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
trace.o: /usr/include/bits/types.h /usr/include/bits/pthreadtypes.h
trace.o: /usr/include/bits/sched.h /usr/include/libio.h
trace.o: /usr/include/_G_config.h /usr/include/wchar.h
trace.o: /usr/include/bits/wchar.h /usr/include/gconv.h
trace.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
trace.o: /usr/include/bits/stdio_lim.h /usr/include/sys/timeb.h
trace.o: /usr/include/time.h /usr/local/include/conffile.h
trace.o: /usr/local/include/varlist.h
mymalloc.o: /usr/include/stdlib.h /usr/include/features.h
mymalloc.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
mymalloc.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
mymalloc.o: /usr/include/sys/types.h /usr/include/bits/types.h
mymalloc.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
mymalloc.o: /usr/include/time.h /usr/include/endian.h
mymalloc.o: /usr/include/bits/endian.h /usr/include/sys/select.h
mymalloc.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
mymalloc.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
mymalloc.o: /usr/include/alloca.h /usr/include/stdio.h /usr/include/libio.h
mymalloc.o: /usr/include/_G_config.h /usr/include/wchar.h
mymalloc.o: /usr/include/bits/wchar.h /usr/include/gconv.h
mymalloc.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
mymalloc.o: /usr/include/bits/stdio_lim.h /usr/include/syslog.h
mymalloc.o: /usr/include/sys/syslog.h
usernode.o: /usr/include/stdlib.h /usr/include/features.h
usernode.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
usernode.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
usernode.o: /usr/include/sys/types.h /usr/include/bits/types.h
usernode.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
usernode.o: /usr/include/time.h /usr/include/endian.h
usernode.o: /usr/include/bits/endian.h /usr/include/sys/select.h
usernode.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
usernode.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
usernode.o: /usr/include/alloca.h /usr/include/stdio.h /usr/include/libio.h
usernode.o: /usr/include/_G_config.h /usr/include/wchar.h
usernode.o: /usr/include/bits/wchar.h /usr/include/gconv.h
usernode.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
usernode.o: /usr/include/bits/stdio_lim.h /usr/include/syslog.h
usernode.o: /usr/include/sys/syslog.h /usr/include/string.h
usernode.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
usernode.o: /usr/include/bits/confname.h /usr/include/getopt.h
usernode.o: /usr/include/arpa/inet.h /usr/include/netinet/in.h
usernode.o: /usr/include/stdint.h /usr/include/bits/wordsize.h
usernode.o: /usr/include/bits/socket.h /usr/include/limits.h
usernode.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
usernode.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
usernode.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
usernode.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
usernode.o: /usr/include/bits/byteswap.h /usr/include/sys/timeb.h usernode.h
usernode.o: /usr/include/linux/if_arp.h /usr/include/linux/netdevice.h
usernode.o: /usr/include/linux/if.h /usr/include/linux/types.h
usernode.o: /usr/include/linux/posix_types.h /usr/include/linux/stddef.h
usernode.o: /usr/include/asm/posix_types.h /usr/include/asm/types.h
usernode.o: /usr/include/linux/socket.h /usr/include/linux/if_ether.h
usernode.o: /usr/include/linux/if_packet.h /usr/include/asm/atomic.h
usernode.o: /usr/include/linux/config.h /usr/include/linux/autoconf.h
usernode.o: /usr/include/asm/cache.h /usr/include/asm/byteorder.h
usernode.o: /usr/include/linux/byteorder/little_endian.h
usernode.o: /usr/include/linux/byteorder/swab.h
usernode.o: /usr/include/linux/byteorder/generic.h
usernode.o: /usr/local/include/iplogin2.h /usr/local/include/varlist.h
usernode.o: accounting.h
testipt.o: /usr/include/stdio.h /usr/include/features.h
testipt.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
testipt.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
testipt.o: /usr/include/bits/types.h /usr/include/bits/pthreadtypes.h
testipt.o: /usr/include/bits/sched.h /usr/include/libio.h
testipt.o: /usr/include/_G_config.h /usr/include/wchar.h
testipt.o: /usr/include/bits/wchar.h /usr/include/gconv.h
testipt.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
testipt.o: /usr/include/bits/stdio_lim.h /usr/include/stdlib.h
testipt.o: /usr/include/sys/types.h /usr/include/time.h /usr/include/endian.h
testipt.o: /usr/include/bits/endian.h /usr/include/sys/select.h
testipt.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
testipt.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
testipt.o: /usr/include/alloca.h /usr/include/unistd.h
testipt.o: /usr/include/bits/posix_opt.h /usr/include/bits/confname.h
testipt.o: /usr/include/getopt.h /usr/include/sys/socket.h
testipt.o: /usr/include/sys/uio.h /usr/include/bits/uio.h
testipt.o: /usr/include/bits/socket.h /usr/include/limits.h
testipt.o: /usr/include/bits/wordsize.h /usr/include/bits/posix1_lim.h
testipt.o: /usr/include/bits/local_lim.h /usr/include/linux/limits.h
testipt.o: /usr/include/bits/posix2_lim.h /usr/include/bits/sockaddr.h
testipt.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
testipt.o: /usr/include/netinet/in.h /usr/include/stdint.h
testipt.o: /usr/include/bits/in.h /usr/include/bits/byteswap.h
testipt.o: /usr/include/arpa/inet.h /usr/include/netdb.h
testipt.o: /usr/include/rpc/netdb.h /usr/include/bits/netdb.h
testipt.o: /usr/include/fcntl.h /usr/include/bits/fcntl.h
testipt.o: ./iptables/include/iptables.h ./iptables/include/iptables_common.h
testipt.o: ./iptables/include/libiptc/libiptc.h
testipt.o: ./iptables/include/libiptc/ipt_kernel_headers.h
testipt.o: /usr/include/netinet/ip.h /usr/include/netinet/ip_icmp.h
testipt.o: /usr/include/netinet/tcp.h /usr/include/netinet/udp.h
testipt.o: /usr/include/net/if.h
testipt.o: /usr/include/linux/netfilter_ipv4/ip_tables.h
testipt.o: /usr/include/linux/netfilter_ipv4.h /usr/include/linux/config.h
testipt.o: /usr/include/linux/autoconf.h /usr/include/linux/netfilter.h
testipt.o: /usr/include/string.h /usr/local/include/varlist.h filterchains2.h
acclib_test.o: /usr/include/stdio.h /usr/include/features.h
acclib_test.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
acclib_test.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stddef.h
acclib_test.o: /usr/include/bits/types.h /usr/include/bits/pthreadtypes.h
acclib_test.o: /usr/include/bits/sched.h /usr/include/libio.h
acclib_test.o: /usr/include/_G_config.h /usr/include/wchar.h
acclib_test.o: /usr/include/bits/wchar.h /usr/include/gconv.h
acclib_test.o: /usr/lib/gcc-lib/i386-slackware-linux/2.95.2/include/stdarg.h
acclib_test.o: /usr/include/bits/stdio_lim.h accounting.h
