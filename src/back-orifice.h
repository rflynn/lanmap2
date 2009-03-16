/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2008-2009 Ryan Flynn
 * All rights reserved.
 */
/*
 * Back Orifice
 *
 * References:
 *
 *  #1 "The Back Orifice (BO) Protocol" [web page]
 *     <URL: http://www.magnux.com.br/~flaviovs/boproto.html>
 *    [Access Jan 12 2009]
 */

#ifndef BACKORIFICE_H
#define BACKORIFICE_H

#include "types.h"

/*
 * NOTE: protocol, including header is encrypted.
 * brute-forcing based on bo_hdr.magic is feasible, but without
 * any particular motivation i'm not doing it yet
 */

/**
 * @ref #1 
 */
#pragma pack(push, 1)
struct bo_hdr {
  u8  magic[8];     /* magic constant "*!*QWTY?" */
  u32 len,          /* LSB byte order */
      id;           /* used for packet ordering in UDP */
  u8  partial:1,    /* 0x80 */
      continued:1,  /* 0x40 */
      type:6,       /* 0x3F */
      data[1];      /* variable-length depending on 'type' */
  /* 1-byte CRC at end of message */
};
#pragma pack(pop)
typedef struct bo_hdr bo_hdr;

/**
 * @ref #1
 */
enum TYPE {
  TYPE_ERROR              = 0x00, /* Error (???) */
  TYPE_PING               = 0x01, /* "Ping" packet */
  TYPE_SYSREBOOT          = 0x02, /* System reboot */
  TYPE_SYSLOCKUP          = 0x03, /* System lock up */
  TYPE_SYSLISTPASSWORDS   = 0x04, /* List system passwords */
  TYPE_SYSVIEWCONSOLE     = 0x05, /* View console (???) */
  TYPE_SYSINFO            = 0x06, /* Get system information */
  TYPE_SYSLOGKEYS         = 0x07, /* Log pressed keys */
  TYPE_SYSENDKEYLOG       = 0x08, /* Send keypress log */
  TYPE_SYSDIALOGBOX       = 0x09, /* Show a dialog box (message box) */
  TYPE_REGISTRYDELETEVALUE= 0x0a, /* Delete an value from the registry */
  TYPE_REDIRADD           = 0x0b, /* Create TCP redirection (proxy) */
  TYPE_REDIRDEL           = 0x0c, /* Delete TCP redirection */
  TYPE_REDIRLIST          = 0x0d, /* List TCP redirections */
  TYPE_APPADD             = 0x0e, /* Start application */
  TYPE_APPDEL             = 0x0f, /* End application */
  TYPE_NETEXPORTADD       = 0x10, /* Export a share resource */
  TYPE_NETEXPORTDELETE    = 0x11, /* Cancel share export */
  TYPE_NETEXPORTLIST      = 0x12, /* Show export list */
  TYPE_PACKETRESEND       = 0x13, /* Resend packet (???) */
  TYPE_HTTPENABLE         = 0x14, /* Enable HTTP server */
  TYPE_HTTPDISABLE        = 0x15, /* Disable HTTP server */
  TYPE_RESOLVEHOST        = 0x16, /* Resolve host name */
  TYPE_FILEFREEZE         = 0x17, /* Compress a file */
  TYPE_FILEMELT           = 0x18, /* Uncompress a file */
  TYPE_PLUGINEXECUTE      = 0x19, /* Plug-in execute */
  TYPE_PROCESSLIST        = 0x20, /* Show active processes */
  TYPE_PROCESSKILL        = 0x21, /* Kill a process */
  TYPE_PROCESSSPAWN       = 0x22, /* Start a process */
  TYPE_REGISTRYCREATEKEY  = 0x23, /* Create a key in the registry */
  TYPE_REGISTRYSETVALUE   = 0x24, /* Set the value of a key in the registry */
  TYPE_REGISTRYDELETEKEY  = 0x25, /* Delete a key in the registry */
  TYPE_REGISTRYENUMKEYS   = 0x26, /* Enumerate registry keys */
  TYPE_REGISTRYENUMVALS   = 0x27, /* Enumerate registry values */
  TYPE_MMCAPFRAME         = 0x28, /* Capture static image (.BMP) from video capture dev */
  TYPE_MMCAPAVI           = 0x29, /* Capture video stream (.AVI) from video capture dev */
  TYPE_MMPLAYSOUND        = 0x2a, /* Play a sound file (.WAV) */
  TYPE_MMLISTCAPS         = 0x2b, /* Show available image/video capture devices */
  TYPE_MMCAPSCREEN        = 0x2c, /* Capture the screen to a file (.BMP) */
  TYPE_TCPFILESEND        = 0x2d, /* Start sending a file using TCP */
  TYPE_TCPFILERECEIVE     = 0x2e, /* Start receiving a file using TCP */
  TYPE_PLUGINLIST         = 0x2f, /* List (running) plug-ins */
  TYPE_PLUGINKILL         = 0x30, /* Kill plug-in */
  TYPE_DIRECTORYLIST      = 0x31, /* List directory */
  TYPE_FILEFIND           = 0x34, /* Find a file */
  TYPE_FILEDELETE         = 0x35, /* Delete a file */
  TYPE_FILEVIEW           = 0x36, /* View file contents */
  TYPE_FILERENAME         = 0x37, /* Rename a file */
  TYPE_FILECOPY           = 0x38, /* Copy a file */
  TYPE_NETVIEW            = 0x39, /* List all network devices, domain names and shares */
  TYPE_NETUSE             = 0x3a, /* Connect a network resource */
  TYPE_NETDELETE          = 0x3b, /* End connection of a network resource */
  TYPE_NETCONNECTIONS     = 0x3c, /* Show network connections */
  TYPE_DIRECTORYMAKE      = 0x3d, /* Create directory (folder) */
  TYPE_DIRECTORYDELETE    = 0x3e, /* Remove directory */
  TYPE_APPLIST            = 0x3f  /* Show running applications */
};

#endif

