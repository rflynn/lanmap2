# ex: set ff=dos ts=8 noet:
# $Id$
#

CFLAGS = -W -Wall -pedantic -std=gnu99 -Wno-unused -Wno-unused-parameter -ggdb -O0 -pedantic -DDEBUG
LDFLAGS = -lpcap -lsqlite3
ALL = cap parse util logical linux_sll ieee802_3 llc arp ip csvread icmp symbol8781 cdp smb dns nbns ipv6 radius snmp ntp mssqlm rasadv ssdp dhcpv6 netbios rtsp bittorrent storm-botnet gnutella tcp tcp-fingerprint http ipp

cap: cap.o prot.o parse.o report.o util.o getopt.o logical.o linux_sll.o ieee802_3.o llc.o arp.o ipv4.o icmp.o icmp-fingerprint.o udp.o bootp.o ssdp.o nbdgm.o nbns.o smb.o tcp.o tcp-fingerprint.o http.o https.o tivoconn.o ipv6.o dns.o symbol8781.o cdp.o browse.o radius.o stp.o ipx.o lldp.o snmp.o ntp.o mcafee-rumor.o rtsp.o mssqlm.o rasadv.o dhcpv6.o netbios.o igmpv2.o bittorrent.o storm-botnet.o gnutella.o irc.o wsdd.o dce-rpc.o esp.o ipp.o

logical.o: logical.c logical.h prot.h
linux_sll.o: linux_sll.c linux_sll.h prot.h
ieee802_3.o: ieee802_3.c ieee802_3.h prot.h
llc.o: llc.c llc.h prot.h
arp.o: arp.c arp.h prot.h
ipv4.o: ipv4.c ipv4.h prot.h
icmp.o: icmp.c icmp.h prot.h
udp.o: udp.c udp.h prot.h
bootp.o: bootp.c bootp.h prot.h
ssdp.o: ssdp.c ssdp.h http.h http.c prot.h
nbdgm.o: nbdgm.c nbdgm.h prot.h
nbns.o: nbns.c nbns.h prot.h
tcp.o: tcp.c tcp.h prot.h
http.o: http.c http.h prot.h
https.o: https.c https.h prot.h
tivoconn.o: tivoconn.c tivoconn.h prot.h
ipv6.o: ipv6.c ipv6.h prot.h
dns.o: dns.c dns.h prot.h
smb.o: smb.c smb.h prot.h
symbol8781.o: symbol8781.c symbol8781.h prot.h
cdp.o: cdp.c cdp.h prot.h
browse.o: browse.c browse.h prot.h
radius.o: radius.c radius.h prot.h
stp.o: stp.c stp.h prot.h
ipx.o: ipx.c ipx.h prot.h
lldp.o: lldp.c lldp.h prot.h
snmp.o: snmp.c snmp.h prot.h
ntp.o: ntp.c ntp.h prot.h
mcafee-rumor.o: mcafee-rumor.c mcafee-rumor.h prot.h
rtsp.o: rtsp.c rtsp.h http.c http.h prot.h
mssqlm.o: mssqlm.c mssqlm.h prot.h
rasadv.o: rasadv.c rasadv.h prot.h
dhcpv6.o: dhcpv6.c dhcpv6.h prot.h
netbios.o: netbios.c netbios.h prot.h
bittorrent.o: bittorrent.c bittorrent.h prot.h
storm-botnet.o: storm-botnet.c storm-botnet.h prot.h
gnutella.o: gnutella.c gnutella.h prot.h
irc.o: irc.c irc.h prot.h
wsdd.o: wsdd.c wsdd.h prot.h
dce-rpc.o: dce-rpc.c dce-rpc.h prot.h
esp.o: esp.c esp.h prot.h
ipp.o: ipp.c ipp.h prot.h

all: $(ALL)

util: util.c util.h
	$(CC) $(CFLAGS) -DTEST -o util util.c

logical: logical.c logical.h ieee802_3.h ipv4.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o logical.o logical.c
	$(CC) $(CFLAGS) -o logical logical.o util.o

linux_sll: linux_sll.c linux_sll.h ieee802_3.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o linux_sll.o linux_sll.c
	$(CC) $(CFLAGS) -o linux_sll linux_sll.o util.o

ieee802_3: ieee802_3.c ieee802_3.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o ieee802_3.o ieee802_3.c
	$(CC) $(CFLAGS) -o ieee802_3 ieee802_3.o util.o

llc: llc.c llc.h ieee802_3.h util.c util.h
	$(RM) ieee802_3.o
	$(CC) $(CFLAGS) -c -o ieee802_3.o ieee802_3.c
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o llc.o llc.c
	$(CC) $(CFLAGS) -o llc llc.o util.o ieee802_3.o

arp: arp.c arp.h ieee802_3.h ipv4.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o arp.o arp.c
	$(CC) $(CFLAGS) -o arp arp.o util.o

ipv4: ipv4.c ipv4.h ieee802_3.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o ipv4.o ipv4.c
	$(CC) $(CFLAGS) -o ip ipv4.o util.o

tcp: tcp.c tcp.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o tcp.o tcp.c
	$(CC) $(CFLAGS) -o tcp tcp.o util.o

tcp-fingerprint: tcp.c tcp.h util.c util.h tcp-fingerprint.h tcp-fingerprint.c ipv4.c ipv4.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(RM) ipv4.o
	$(CC) $(CFLAGS) -c -o ipv4.o ipv4.c
	$(RM) tcp.o
	$(CC) $(CFLAGS) -c -o tcp.o tcp.c
	$(CC) $(CFLAGS) -c -DTEST -o tcp-fingerprint.o tcp-fingerprint.c
	$(CC) $(CFLAGS) -o tcp-fingerprint tcp-fingerprint.o tcp.o util.o ipv4.o

icmp: icmp.c icmp.h ieee802_3.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o icmp.o icmp.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o icmp icmp.o util.o

http: tcp.c tcp.h util.c util.h http.h http.c ipv4.c ipv4.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(RM) ipv4.o
	$(CC) $(CFLAGS) -c -o ipv4.o ipv4.c
	$(RM) tcp.o
	$(CC) $(CFLAGS) -c -o tcp.o tcp.c
	$(CC) $(CFLAGS) -c -DTEST -o http.o http.c
	$(CC) $(CFLAGS) -o http http.o tcp.o util.o ipv4.o

ssdp: ssdp.c ssdp.h http.h http.c util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(RM) http.o
	$(CC) $(CFLAGS) -c -o http.o http.c
	$(RM) ipv4.o
	$(CC) $(CFLAGS) -c -o ipv4.o ipv4.c
	$(RM) report.o
	$(CC) $(CFLAGS) -c -o report.o report.c -DTEST
	$(CC) $(CFLAGS) -c -DTEST -o ssdp.o ssdp.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o ssdp ssdp.o report.o util.o ipv4.o http.o

symbol8781: symbol8781.c symbol8781.h ieee802_3.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o symbol8781.o symbol8781.c
	$(CC) $(CFLAGS) -o symbol8781 symbol8781.o util.o

cdp: cdp.c cdp.h ieee802_3.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o cdp.o cdp.c
	$(CC) $(CFLAGS) -o cdp cdp.o util.o

smb: smb.c smb.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o smb.o smb.c
	$(CC) $(CFLAGS) -o smb smb.o util.o

browse: browse.c browse.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(RM) smb.o
	$(CC) $(CFLAGS) -c -o smb.o smb.c
	$(CC) $(CFLAGS) -c -DTEST -o browse.o browse.c
	$(CC) $(CFLAGS) -o browse browse.o util.o smb.o

dns: dns.c dns.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(RM) ipv4.o
	$(CC) $(CFLAGS) -c -o ipv4.o ipv4.c
	$(RM) ipv6.o
	$(CC) $(CFLAGS) -c -o ipv6.o ipv6.c
	$(RM) ieee802_3.o
	$(CC) $(CFLAGS) -c -o ieee802_3.o ieee802_3.c
	$(RM) report.o
	$(CC) $(CFLAGS) -c -o report.o report.c -DTEST
	$(CC) $(CFLAGS) -c -DTEST -o dns.o dns.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o dns dns.o ieee802_3.o report.o util.o ipv4.o ipv6.o

rtsp: rtsp.c rtsp.h util.c util.h http.c http.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(RM) ipv4.o
	$(CC) $(CFLAGS) -c -o ipv4.o ipv4.c
	$(RM) http.o
	$(CC) $(CFLAGS) -c -o http.o http.c
	$(RM) ieee802_3.o
	$(CC) $(CFLAGS) -c -o ieee802_3.o ieee802_3.c
	$(RM) report.o
	$(CC) $(CFLAGS) -c -o report.o report.c -DTEST
	$(CC) $(CFLAGS) -c -DTEST -o rtsp.o rtsp.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o rtsp rtsp.o ieee802_3.o report.o util.o ipv4.o http.o

nbns: nbns.c nbns.h nbdgm.o ipv4.o ipv6.o report.o util.c util.h
	$(RM) ieee802_3.o
	$(CC) $(CFLAGS) -c -o ieee802_3.o ieee802_3.c
	$(RM) dns.o
	$(CC) $(CFLAGS) -c -o dns.o dns.c
	$(RM) ipv4.o
	$(CC) $(CFLAGS) -c -o ipv4.o ipv4.c
	$(RM) ipv6.o
	$(CC) $(CFLAGS) -c -o ipv6.o ipv6.c
	$(RM) nbdgm.o
	$(CC) $(CFLAGS) -c -o nbdgm.o nbdgm.c
	$(RM) report.o
	$(CC) $(CFLAGS) -c -o report.o report.c -DTEST
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o nbns.o nbns.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o nbns nbns.o ieee802_3.o dns.o ipv4.o ipv6.o nbdgm.o report.o util.o

ipv6: ipv6.c ipv6.h ieee802_3.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(RM) report.o
	$(CC) $(CFLAGS) -c -o report.o report.c
	$(RM) ieee802_3.o
	$(CC) $(CFLAGS) -c -o ieee802_3.o ieee802_3.c
	$(CC) $(CFLAGS) -c -DTEST -o ipv6.o ipv6.c
	$(CC) $(CFLAGS) -lsqlite3 -o ipv6 ipv6.o ieee802_3.o report.o util.o

radius: radius.c radius.h ieee802_3.h util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o radius.o radius.c
	$(CC) $(CFLAGS) -o radius radius.o util.o

snmp: snmp.c snmp.h ieee802_3.h util.c util.h
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o snmp.o snmp.c
	$(CC) $(CFLAGS) -o snmp snmp.o util.o

ntp: ntp.c ntp.h ieee802_3.h util.c util.h
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o ntp.o ntp.c
	$(CC) $(CFLAGS) -o ntp ntp.o util.o

mssqlm: mssqlm.c mssqlm.h ieee802_3.h util.c util.h
	$(RM) mssqlm.o
	$(CC) $(CFLAGS) -c -DTEST -o mssqlm.o mssqlm.c
	$(RM) report.o
	$(CC) $(CFLAGS) -c -o report.o report.c -DTEST
	$(CC) $(CFLAGS) $(LDFLAGS) -o mssqlm mssqlm.o report.o ipv4.o util.o

rasadv: rasadv.c rasadv.h ieee802_3.h util.c util.h
	$(RM) rasadv.o
	$(CC) $(CFLAGS) -c -DTEST -o rasadv.o rasadv.c
	$(RM) report.o
	$(CC) $(CFLAGS) -c -o report.o report.c -DTEST
	$(CC) $(CFLAGS) $(LDFLAGS) -o rasadv rasadv.o report.o ipv4.o util.o

dhcpv6: dhcpv6.c dhcpv6.h ipv6.h ipv6.c util.c util.h
	$(RM) ieee802_3.o
	$(CC) $(CFLAGS) -c -o ieee802_3.o ieee802_3.c
	$(RM) ipv6.o
	$(CC) $(CFLAGS) -c -o ipv6.o ipv6.c
	$(RM) report.o
	$(CC) $(CFLAGS) -c -o report.o report.c -DTEST
	$(CC) $(CFLAGS) -c -DTEST -o dhcpv6.o dhcpv6.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o dhcpv6 dhcpv6.o ipv6.o util.o ieee802_3.o report.o

netbios: netbios.c netbios.h ieee802_3.c llc.h util.c util.h
	$(RM) ieee802_3.o
	$(CC) $(CFLAGS) -c -o ieee802_3.o ieee802_3.c
	$(RM) report.o
	$(CC) $(CFLAGS) -c -o report.o report.c -DTEST
	$(CC) $(CFLAGS) -c -DTEST -o netbios.o netbios.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o netbios netbios.o util.o ieee802_3.o report.o

bittorrent: bittorrent.c bittorrent.h tcp.h util.c util.h
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o bittorrent.o bittorrent.c
	$(CC) $(CFLAGS) -o bittorrent bittorrent.o util.o

storm-botnet: storm-botnet.c storm-botnet.h report.c report.o ipv4.h ipv4.c util.o
	$(CC) $(CFLAGS) -c -DTEST -o storm-botnet.o storm-botnet.c
	$(RM) report.o
	$(CC) $(CFLAGS) -c -DTEST -o report.o report.c
	$(RM) ipv4.o
	$(CC) $(CFLAGS) -c -o ipv4.o ipv4.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o storm-botnet storm-botnet.o util.o report.o ipv4.o

gnutella: gnutella.c gnutella.h http.h http.c util.c util.h
	$(RM) util.o
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(RM) http.o
	$(CC) $(CFLAGS) -c -o http.o http.c
	$(RM) ipv4.o
	$(CC) $(CFLAGS) -c -o ipv4.o ipv4.c
	$(RM) report.o
	$(CC) $(CFLAGS) -c -o report.o report.c -DTEST
	$(CC) $(CFLAGS) -c -DTEST -o gnutella.o gnutella.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o gnutella gnutella.o report.o util.o ipv4.o http.o

dce-rpc: dce-rpc.c dce-rpc.h tcp.h util.c util.h
	$(CC) $(CFLAGS) -c -o util.o util.c
	$(CC) $(CFLAGS) -c -DTEST -o dce-rpc.o dce-rpc.c
	$(CC) $(CFLAGS) -o dce-rpc dce-rpc.o util.o

csvread: csvread.c
	$(CC) $(CFLAGS) -c -DTEST -o csvread.o csvread.c
	$(CC) $(CFLAGS) -o csvread csvread.o

clean:
	$(RM) *.o $(ALL) cscope.out


