-- ex: set ff=dos ts=2 et:
-- $Id$

-- map hints from the SSDP protocol

INSERT INTO map(maptype,map,src,val)VALUES('Dev',  'Router-WRT54G', 'SSDP.Server','LINUX/2.4 UPnP/1.0 BRCM400/1.0');
INSERT INTO map(maptype,map,src,val)VALUES('OS',  'Linux2.4.x',    'SSDP.Server','LINUX/2.4 UPnP/1.0 BRCM400/1.0');
INSERT INTO map(maptype,map,src,val)VALUES('OS',  'WinNT5.1',      'SSDP.Server','Microsoft-Windows-NT/5.1 UPnP/1.0 UPnP-Device-Host/1.0');
INSERT INTO map(maptype,map,src,val)VALUES('OS',  'WinNT5',        'SSDP.Server','NT/5.0 UPnP/1.0');

INSERT INTO map(maptype,map,src,val)VALUES('Role','Router',       'SSDP.NT',    'urn:schemas-upnp-org:device:InternetGatewayDevice:1');

-- OKIData C5200n printer
INSERT INTO map(maptype,map,src,val)VALUES('Dev', 'OKIData-C5200n','SSDP.Server','Cream/3.1,UPnP/1.0,UPnP/1.0');

