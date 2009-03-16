-- ex: set ff=dos
-- $Id$

-- map DNS.TXT

INSERT INTO map(maptype,map,src,val)VALUES('Dev','iMac-7', 'DNS.TXT','\x0dmodel=iMac7,1');
INSERT INTO map(maptype,map,src,val)VALUES('OS','MacOSX',  'DNS.TXT','\x0dmodel=iMac7,1');

-- TODO: implement DNS-SD (Service Discovery), parsing the [length][key=value] pairs and reformatting as a list of keys
-- we can then match this key list fingerprint

--INSERT INTO map(maptype,map,src,val)VALUES('App','?','DNS.TXT.SD','model');
--INSERT INTO map(maptype,map,src,val)VALUES('App','?','DNS.TXT.SD','_kerberos');
--INSERT INTO map(maptype,map,src,val)VALUES('App','?','DNS.TXT.SD','_device-info');
--INSERT INTO map(maptype,map,src,val)VALUES('App','Limewire for OSX?','DNS.TXT.SD','Machine Name,Password,Version');
--INSERT INTO map(maptype,map,src,val)VALUES('App','?','DNS.TXT.SD','');
--INSERT INTO map(maptype,map,src,val)VALUES('App','?','DNS.TXT.SD','');

-- check http://www.dns-sd.org/ServiceTypes.html

