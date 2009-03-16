#!/bin/sh

url=$1
wget -p -H -k -E -U "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" "$url"
if [ 0 == $? ]
then
	echo "$url" > cache.log.tmp
	cat cache.log >> cache.log.tmp
	mv cache.log.tmp cache.log
else
	echo "wget error, skipping post-processing";
fi

