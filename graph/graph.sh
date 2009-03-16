#!/bin/sh

php -q aggregate-hosts.php
php -q gen-graph.php > net.dot
echo "Generating graph, may take a bit..."
fdp -Tpng -onet.png net.dot
echo "done."

