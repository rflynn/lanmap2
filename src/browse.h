/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008 Ryan Flynn
 * All rights reserved.
 */
/*
 * Microsoft BROWSE protocol
 *
 * References:
 *
 *  #1 
 *
 */

#ifndef BROWSE_H
#define BROWSE_H

#include "types.h"

#pragma pack(push, 1)
struct browse_flags {
      u32 domain_enum:1,
          local:1,
          _:7,
          win95:1,
          vms:1,
          osf:1,
          domain_master:1,
          master:1,
          backup:1,
          potential:1,
          nt_server:1,
          __:1,
          wfw:1,
          nt_workstation:1,
          xenix:1,
          dialin:1,
          print:1,
          member:1,
          novell:1,
          apple:1,
          time_source:1,
          backup_ctrl:1,
          domain_ctrl:1,
          sql_server:1,
          server:1,
          workstation:1;
};
#pragma pack(pop)
typedef struct browse_flags browse_flags;

/**
 * Microsoft Browse Protocol
 * TODO: figure out what the relation to SMB is, exactly.
 */
#pragma pack(push, 1)
struct browse {
  u8  cmd;
};
#pragma pack(pop)
typedef struct browse browse;

enum Cmd {
  Cmd_Host             = 0x01,
  Cmd_AnnounceReq      = 0x02,
  Cmd_4                = 0x04,
  Cmd_BrowserElectReq  = 0x08,
  Cmd_BackupBrowser    = 0x0b,
  Cmd_DomainWorkgroup  = 0x0c,
  Cmd_LocalMaster      = 0x0f
};

#pragma pack(push, 1)
struct browse_hostann {
  u8  updatecnt;
  u32 updateperiod;
  s8  hostname[16];
  u8  os_maj,
      os_min;
  browse_flags fl;
  u8  browser_maj,
      browser_min;
  u16 signature;
  s8  host_comment[1];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct electreq {
  u8  version,
      /* desire */
      nt:1,
      unused:1,
      wins:1,
      unused2:1,
      domain_master:1,
      browser_master:1,
      standby:1,
      backup:1,
      browser_maj,
      browser_min,
      /* os */
      unused3:2,
      nt_server:1,
      nt_workstation:1,
      unused4:3,
      wfw:1;
  u32 uptime,
      padding; /* ? */
  u8  name[1];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct backupbrowser {
  u8 name[1]; /* variable-length */
};
#pragma pack(pop)

#pragma pack(push, 1)
struct reqannounce {
  u8 _,
     name[1]; /* variable-length */
};
#pragma pack(pop)

#pragma pack(push, 1)
struct dom_wg {
  struct {
    u8  cnt;
    u32 period;
  } update;
  u8 workgroup[16],
     os_maj,
     os_min;
  browse_flags fl;
  u32 mystery;
  u8 master_name[1]; /* variable */
};
#pragma pack(pop)

/*
len=216
\xff\xff\xff\xff\xff\xff\x00\x00\xc0\xf5\xe2\xed\x08\x00E\x00\x00\xca\x90L\x00\x00\x80\x11\xc4\x80\x0a+a\x01\x0a+o\xff\x00\x8a\x00\x8a\x00\xb6\x13\\x11\x0e\xcd>\x0a+a\x01\x00\x8a\x00\xa0\x00\x00\x20EDEBFCEEEJEPFAFFCNDCFJDBFIEGFHAA\x00\x20FHEPFCELEHFCEPFFFACACACACACACABN\x00\xffSMB%\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00V\x00\x03\x00\x01\x00\x01\x00\x02\x00\x17\x00\MAILSLOT\BROWSE\x00\x09\x04\x9b\x09\x00\x00
linktype=1
parsed 802.3 len=216 bytes=14
parsed IPv4 len=202 bytes=20
test_ipv4 0x11=0x11 protocol=0x11
parsed UDP len=182 bytes=8
test_udp_port srcport=138 dstport=138
(zoff=1 zlen=1) (zoff=1 zlen=1) test_ipv6_udp udp(srcport=138 dstport=138) ipv6(addr=B6:5C13:110E:CD3E:A2B:6101:8A:A0 cmp=B6:5C13:110E:CD3E:A2B:6101:8A:A0)
parsed NB-Dgm len=174 bytes=82
do_parse len=60 buf=\x11\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00V\x00\x03\x00\x01\x00\x01\x00\x02\x00\x17\x00\MAILSLOT\BROWSE\x00\x09\x04\x9b\x09\x00\x00
smb.c smb_parse do_parse=55 bytes: \x11\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00V\x00\x03\x00\x01\x00\x01\x00\x02\x00\x17\x00\MAILSLOT\BROWSE\x00\x09
parsed SMB len=92 bytes=87
Logical id=45 type=1 bytes=216 when=0
802.3 src=00:00:c0:f5:e2:ed dst=ff:ff:ff:ff:ff:ff type=0x0800
IPv4 v=4 ihl=5 tos(prec=0 lodel=0 hithr=0 hirel=0 ect=0 ece=0) tlen=202 id=0x904c flag=0x0000(evil=0 dontfrag=0 morefrag=0 fragoff=0) ttl=128 prot=0x11 chksum=0xc480 10.43.97.1 -> 10.43.111.255
UDP srcport=138 dstport=138 length=182 chksum=0x135c
NB-Dgm msgtype=17 snt=14 frag(f=0 more=0) id=0xcd3e src=10.43.97.1:138 len=160 off=0 srcname="CARDIOPU-2Y1XFW" dstname="WORKGROUP"
rep_addr AddrUpd SQLITE_DONE
rep_addr 0.016 secs
SMB cmd=0x25() err=0 errcode=0 lckrd=0 rcvbufpst=0 casesens=0 canonpath=0 oplck=0 notify=0 reqresp=0
  TransReq wct=17 param(total=0 max=0 cnt=0 offset=0) data(total=6 max=0 cnt=6 offset=86) timeout=1000 name="\MAILSLOT\BROWSE"
  Trailing bytes=5 \x04\x9b\x09\x00\x00
*/

#pragma pack(push, 1)
struct cmd4 {
  u8 whoknows[4];
};
#pragma pack(pop)

#endif

