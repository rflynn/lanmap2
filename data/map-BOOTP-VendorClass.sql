-- ex: set ff=dos ts=2 et:
-- $Id$

-- map BOOTP 'Vendor Class' field contents

INSERT INTO map(maptype,map,src,val)VALUES('OS', 'MacOS9.2.2',         'BOOTP.VendorClass','Mac OS 9.2.2 Open Transport 2.7.9 Power Mac G4 (Graphite)');
INSERT INTO map(maptype,map,src,val)VALUES('HW', 'PowerMacG4-Graphite','BOOTP.VendorClass','Mac OS 9.2.2 Open Transport 2.7.9 Power Mac G4 (Graphite)');

INSERT INTO map(maptype,map,src,val)VALUES('OS', 'WinNT5',             'BOOTP.VendorClass','MSFT 5.0');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','BlackBerry',         'BOOTP.VendorClass','BlackBerry');

-- Ref: Cisco, DHCP OPTION 43 for Lightweight Cisco Aironet Access Points Configuration Example [web page]
--      <URL: http://www.cisco.com/en/US/tech/tk722/tk809/technologies_configuration_example09186a00808714fe.shtml> [Accessed Jan 8 2009]
--Vendor Class Identifier (VCI),Access Point
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1000',        'BOOTP.VendorClass','Airespace.AP1200');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1100',        'BOOTP.VendorClass','Cisco AP c1100');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1130',        'BOOTP.VendorClass','Cisco AP c1130');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1200',        'BOOTP.VendorClass','Cisco AP c1200');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1230',        'BOOTP.VendorClass','Cisco AP c1200');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1240',        'BOOTP.VendorClass','Cisco AP c1240');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1250',        'BOOTP.VendorClass','Cisco AP c1250');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1300',        'BOOTP.VendorClass','Cisco AP c1300');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1500',        'BOOTP.VendorClass','Cisco AP c1500');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1500',        'BOOTP.VendorClass','Cisco AP.OAP1500');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1500',        'BOOTP.VendorClass','Cisco AP.LAP1505');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1500',        'BOOTP.VendorClass','Cisco AP.LAP1510');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1500',        'BOOTP.VendorClass','Cisco AP c1520');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Aironet1500',        'BOOTP.VendorClass','Airespace.AP1200');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Cisco3201LAP',       'BOOTP.VendorClass','Cisco Bridge/AP/WGB c3201');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','Cisco521WEAP',       'BOOTP.VendorClass','Cisco AP c520');
INSERT INTO map(maptype,map,src,val)VALUES('Dev','AP801',              'BOOTP.VendorClass','Cisco AP801');

