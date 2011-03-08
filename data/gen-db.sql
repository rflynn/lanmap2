-- ex: set ff=dos ts=2 et:
-- SQL for sqlite3

-- a few aspects we see repeated:
--  earliest/latest
--    our database is meant to store data over a long period of time,
--    but due to the very high level of repeated data in a network we
--    cannot store one record per instance. therefore, for each piece
--    of data we store a range of time between which it was seen; this
--    allows us to store a fixed number of records and yet correctly
--    reconstruct the state of the network at any point in time.
-- 

--DROP TABLE IF EXISTS prottype;
--DROP TABLE IF EXISTS addrtype;
--DROP TABLE IF EXISTS addrtype;
--DROP TABLE IF EXISTS addr;
--DROP TABLE IF EXISTS traffic;
--DROP TABLE IF EXISTS hint;

-- map IEEE Organizationally Unique Identifier to vendor name
CREATE TABLE oui (
  oui         TEXT    NOT NULL,
  org         TEXT    NOT NULL,
  UNIQUE (oui)
);

-- one record per unique protocol
CREATE TABLE prottype (
  prot        TEXT NOT NULL,
  longname    TEXT NOT NULL,
  descr       TEXT NOT NULL,
  UNIQUE (prot)
);

INSERT INTO prottype VALUES ('ARP',       '',             '');
INSERT INTO prottype VALUES ('BitTorrent','',             '');
INSERT INTO prottype VALUES ('BOOTP',     '',             '');
INSERT INTO prottype VALUES ('BROWSE',    '',             '');
INSERT INTO prottype VALUES ('CDP',       '',             '');
INSERT INTO prottype VALUES ('CUPS',      '',             '');
INSERT INTO prottype VALUES ('DCHPv6',    '',             '');
INSERT INTO prottype VALUES ('DNS',       '',             '');
INSERT INTO prottype VALUES ('Gnutella',  '',             '');
INSERT INTO prottype VALUES ('HTTP',      '',             '');
INSERT INTO prottype VALUES ('ICMP',      '',             '');
INSERT INTO prottype VALUES ('IEEE802.3', '',             '');
INSERT INTO prottype VALUES ('IGMPv2',    '',             '');
INSERT INTO prottype VALUES ('IPv4',      '',             '');
INSERT INTO prottype VALUES ('IPv6',      '',             '');
INSERT INTO prottype VALUES ('IPX',       '',             '');
INSERT INTO prottype VALUES ('LinuxSLL',  '',             '');
INSERT INTO prottype VALUES ('LLC',       '',             '');
INSERT INTO prottype VALUES ('LLDP',      '',             '');
INSERT INTO prottype VALUES ('Logical',   '',             '');
INSERT INTO prottype VALUES ('McAfeeRumor','',            '');
INSERT INTO prottype VALUES ('MSSQLM',    '',             '');
INSERT INTO prottype VALUES ('NB-Dgm',    '',             '');
INSERT INTO prottype VALUES ('NBNS',      '',             '');
INSERT INTO prottype VALUES ('NetBIOS',   '',             '');
INSERT INTO prottype VALUES ('NTP',       '',             '');
INSERT INTO prottype VALUES ('RADIUS',    '',             '');
INSERT INTO prottype VALUES ('RASADV',    '',             '');
INSERT INTO prottype VALUES ('RTSP',      '',             '');
INSERT INTO prottype VALUES ('SMB',       '',             '');
INSERT INTO prottype VALUES ('SNMP',      '',             '');
INSERT INTO prottype VALUES ('SSDP',      '',             '');
INSERT INTO prottype VALUES ('StormBotnet','',            '');
INSERT INTO prottype VALUES ('STP',       '',             '');
INSERT INTO prottype VALUES ('Symbol8781','',             '');
INSERT INTO prottype VALUES ('TCP',       '',             '');
INSERT INTO prottype VALUES ('TivoConn',  '',             '');
INSERT INTO prottype VALUES ('UDP',       '',             '');

-- types of addresses and the protocols from which they come
CREATE TABLE addrtype (
  type_       TEXT NOT NULL,
  prottype    TEXT NOT NULL,
  shortname   TEXT NOT NULL,
  longname    TEXT NOT NULL,
  UNIQUE (type_),
  FOREIGN KEY (prottype) REFERENCES prottype (prot)
);

INSERT INTO addrtype VALUES ('BH',  'BOOTP',    'BOOTP Hostname',   '');
INSERT INTO addrtype VALUES ('BR',  'BROWSE',   'BROWSE Hostname',  '');
INSERT INTO addrtype VALUES ('CUPS','CUPS',     'CUPS.Location',    '');
INSERT INTO addrtype VALUES ('D',   'DNS',      'DNS name',         '');
INSERT INTO addrtype VALUES ('M',   'MAC',      'IEEE802.3',        '');
INSERT INTO addrtype VALUES ('N',   'NetBIOS',  'NetBIOS',          '');
INSERT INTO addrtype VALUES ('4',   'IPv4',     'IPv4',             '');
INSERT INTO addrtype VALUES ('6',   'IPv6',     'IPv6',             '');
INSERT INTO addrtype VALUES ('RAS', 'RASADV',   'rasadv hostname',  '');
INSERT INTO addrtype VALUES ('Storm','StormBotnet','Infected w/ Storm Worm','');
INSERT INTO addrtype VALUES ('TH',  'TivoConn', 'TivoConn Hostname','');

-- classifications of hints
CREATE TABLE hintsrc (
  src         TEXT NOT NULL,
  prottype    TEXT NOT NULL,
  descr       TEXT NOT NULL,
  UNIQUE (src),
  FOREIGN KEY (prottype) REFERENCES prottype (prot)
);

INSERT INTO hintsrc VALUES ('BOOTP.VendorClass',    'BOOTP',    '');
INSERT INTO hintsrc VALUES ('BOOTP.Fingerprint',    'BOOTP',    '');
INSERT INTO hintsrc VALUES ('BOOTP.Offer',          'BOOTP',    '');
INSERT INTO hintsrc VALUES ('BOOTP.Router',         'BOOTP',    '');
INSERT INTO hintsrc VALUES ('BOOTP.DHCPD',          'BOOTP',    '');
INSERT INTO hintsrc VALUES ('BROWSE.OS',            'BROWSE',   '');
INSERT INTO hintsrc VALUES ('BROWSE.Browser',       'BROWSE',   '');
INSERT INTO hintsrc VALUES ('BROWSE.Comment',       'BROWSE',   '');
INSERT INTO hintsrc VALUES ('CDP.Platform',         'CDP',      '');
INSERT INTO hintsrc VALUES ('CDP.SoftVer',          'CDP',      '');
INSERT INTO hintsrc VALUES ('CUPS.Location',        'CUPS',     '');
INSERT INTO hintsrc VALUES ('DNS.TXT',              'DNS',      '');
INSERT INTO hintsrc VALUES ('DNS.LOCAL',            'DNS',      '');
INSERT INTO hintsrc VALUES ('Gnutella.User-Agent',  'Gnutella', '');
INSERT INTO hintsrc VALUES ('HTTP.Server',          'HTTP',     '');
INSERT INTO hintsrc VALUES ('HTTP.User-Agent',      'HTTP',     '');
INSERT INTO hintsrc VALUES ('HTTP.X-Powered-By',    'HTTP',     '');
INSERT INTO hintsrc VALUES ('ICMP.ECHO.Fingerprint','ICMP',     '');
INSERT INTO hintsrc VALUES ('LLDP.PortDescr',       'LLDP',     '');
INSERT INTO hintsrc VALUES ('LLDP.PortId',          'LLDP',     '');
INSERT INTO hintsrc VALUES ('LLDP.SysDescr',        'LLDP',     '');
INSERT INTO hintsrc VALUES ('LLDP.SysName',         'LLDP',     '');
INSERT INTO hintsrc VALUES ('MAC.Vendor',           'IEEE802.3','');
INSERT INTO hintsrc VALUES ('MSSQLM.ServerName',    'MSSQLM',   '');
INSERT INTO hintsrc VALUES ('MSSQLM.InstanceName',  'MSSQLM',   '');
INSERT INTO hintsrc VALUES ('MSSQLM.Version',       'MSSQLM',   '');
INSERT INTO hintsrc VALUES ('MSSQLM.TCPPort',       'MSSQLM',   '');
INSERT INTO hintsrc VALUES ('MSSQLM.UDPPort',       'MSSQLM',   '');
INSERT INTO hintsrc VALUES ('MSSQLM.NamedPipe',     'MSSQLM',   '');
INSERT INTO hintsrc VALUES ('RAS.Domain',           'RASADV',   '');
INSERT INTO hintsrc VALUES ('RTSP.Server',          'RTSP',     '');
INSERT INTO hintsrc VALUES ('RTSP.User-Agent',      'RTSP',     '');
INSERT INTO hintsrc VALUES ('RTSP.URL',             'RTSP',     '');
INSERT INTO hintsrc VALUES ('SSDP.Server',          'SSDP',     '');
INSERT INTO hintsrc VALUES ('SSDP.Location',        'SSDP',     '');
INSERT INTO hintsrc VALUES ('SSDP.NT',              'SSDP',     '');
INSERT INTO hintsrc VALUES ('SSDP.USN',             'SSDP',     '');
INSERT INTO hintsrc VALUES ('STP.Bridge',           'STP',      '');
INSERT INTO hintsrc VALUES ('TCP.Fingerprint',      'TCP',      '');
INSERT INTO hintsrc VALUES ('TivoConn.Platform',    'TivoConn', '');

-- translate between network addresses
-- from ARP and BOOTP i guess
CREATE TABLE addr (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  fromtype    TEXT    NOT NULL,
  from_       TEXT    NOT NULL,
  totype      TEXT    NOT NULL,
  to_         TEXT    NOT NULL,
  reason      TEXT    NOT NULL, -- why do we think this? include a human-readable description of the rule that provides this weight
  -- TODO: drop 'weight' field here
  weight      INTEGER NOT NULL, -- total weight reported for this mac:target
  earliest    INTEGER NOT NULL, -- earliest UNIX timestamp for this hint
  latest      INTEGER NOT NULL, -- latest UNIX timestamp for this hint
  UNIQUE (fromtype, from_, totype, to_, reason),
  FOREIGN KEY (fromtype) REFERENCES addrtype (type_),
  FOREIGN KEY (totype)   REFERENCES addrtype (type_)
);

-- TODO: rename to 'attr'(ibute)
-- each record represents a single attribute, tied to a network address, that
-- was gleaned from that machine's traffic; most of these are intended to be
-- used in identifying the host; though others can be URLs or comments or other
-- potentially interesting pieces of data
CREATE TABLE hint (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  addrtype    TEXT    NOT NULL,
  addr        TEXT    NOT NULL, -- address hint is associated with
  hintsrc     TEXT    NOT NULL,
  contents    TEXT    NOT NULL,
  earliest    INTEGER NOT NULL, -- earliest UNIX timestamp for this hint
  latest      INTEGER NOT NULL, -- latest UNIX timestamp for this hint
  UNIQUE (addrtype, addr, hintsrc, contents),
  FOREIGN KEY (addrtype) REFERENCES addrtype (type_),
  FOREIGN KEY (hintsrc)  REFERENCES hintsrc (src)
);

-- track traffic in a single direction 'from_' -> 'to_'
-- this is pretty straight-forward
CREATE TABLE traffic (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  fromtype    TEXT    NOT NULL,
  from_       TEXT    NOT NULL,
  totype      TEXT    NOT NULL,
  to_         TEXT    NOT NULL,
  protocol    TEXT    NOT NULL, -- name of the protocol
  bytes       INTEGER NOT NULL, -- number of actual protocol bytes
  bytes_encap INTEGER NOT NULL, -- number of bytes encapsulated by protocol including
                                --   other protocols
  counter     INTEGER NOT NULL, -- number of times updated; useful for calculating
                                --    mean metrics
  earliest    INTEGER NOT NULL, -- earliest UNIX timestamp for this hint
  latest      INTEGER NOT NULL, -- latest UNIX timestamp for this hint
  UNIQUE (fromtype, from_, totype, to_, protocol),
  FOREIGN KEY (fromtype) REFERENCES addrtype (type_),
  FOREIGN KEY (totype)   REFERENCES addrtype (type_),
  FOREIGN KEY (protocol) REFERENCES prottype (prot)
);

CREATE TABLE maptype (
  type_       TEXT    NOT NULL,
  descr       TEXT    NOT NULL,
  UNIQUE (type_)
);

INSERT INTO maptype (type_,descr) VALUES ('APP',  'Application');
INSERT INTO maptype (type_,descr) VALUES ('OS',   'Operating System');
INSERT INTO maptype (type_,descr) VALUES ('HW',   'Hardware');
INSERT INTO maptype (type_,descr) VALUES ('Role', 'Role in the network');
INSERT INTO maptype (type_,descr) VALUES ('Dev',  'A full device... I need to get a multi-level mapping system working for this to really work...');

-- map hint.contents to a hardware platform, an operating system or application 
CREATE TABLE map (
  enable      INTEGER NOT NULL DEFAULT 1,
  maptype     TEXT    NOT NULL,
  map         TEXT    NOT NULL,
  weight      INTEGER NOT NULL DEFAULT 1, -- 
  src         TEXT    NOT NULL,
  val         TEXT    NOT NULL,
  UNIQUE (maptype, map, src, val),
  FOREIGN KEY (maptype) REFERENCES maptype (type_),
  FOREIGN KEY (src)     REFERENCES hintsrc (src)
);

CREATE INDEX idx_map_maptype ON map (maptype);

-- we may have more than one client simultaneously
-- looking at a different set of hosts from different timespans;
-- we'll key off the timespans
CREATE TABLE host_perspective (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  earliest    INTEGER NOT NULL,
  latest      INTEGER NOT NULL,
  UNIQUE (earliest, latest)
);

-- defines a unique "host"; a collection of one or more addresses
-- that relate to one another
CREATE TABLE host (
  hp_id       INTEGER NOT NULL,
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  addr        TEXT    NOT NULL, -- main address at this host
  FOREIGN KEY (hp_id) REFERENCES host_perspective (id)
);
CREATE INDEX index_host_addr ON host (addr);

-- this table is derived from the 'addr' table data by our
-- own 'conglomerate' algorithm in php
CREATE TABLE host_addr (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id     INTEGER NOT NULL,
  addr        TEXT    NOT NULL, -- a subordinate address to the main host address
  FOREIGN KEY (host_id) REFERENCES host (id)
);
CREATE INDEX index_host_addr_hid ON host_addr (host_id);
CREATE INDEX index_host_addr_addr ON host_addr (addr);

-- an instance of hint->map applied to a particular host address
-- that is, one or more hints have been gathered from a particular address and 
-- they match a 'map' entry; these are combined into a single record denoting the
-- "weight" of this evidence for a particular property (i.e. that address A is Operating System O)
-- this is the "final" outcome of hint and map
CREATE TABLE host_map (
  host_addr_id  INTEGER NOT NULL,
  maptype       TEXT    NOT NULL,
  map           TEXT    NOT NULL,
  weight        INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (host_addr_id) REFERENCES host_addr (id),
  FOREIGN KEY (maptype)      REFERENCES maptype (type_)
  FOREIGN KEY (map)          REFERENCES map (map)
);

-- 
--CREATE TABLE icon (
--  maptype       TEXT    NOT NULL,
--  map           TEXT    NOT NULL,
--  image         TEXT    NOT NULL,
--  UNIQUE (maptype, map)
--);

