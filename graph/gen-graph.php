<?php
#
# ex: set ts=2 et:
# $Id$
# 
# TODO: update the hosts in the actual database
#

error_reporting(E_ALL);

require_once("inc.db.php");
require_once("algorithm-conglomerate.php");

define('ICON_PATH', '../img/');

function icon($addrs, $addr)
{
  $icon = "dev/Generic-PC";
  if (isset($addrs[$addr]["HW"][0])) {
    $icon = "hw/" . $addrs[$addr]["HW"][0];
  } else if (@$addrs[$addr]["Dev"][0]) {
    $icon = "dev/" . $addrs[$addr]["Dev"][0];
  } else if (@$addrs[$addr]["OS"][0]) {
    $icon = "os/" . $addrs[$addr]["OS"][0];
  }
  $icon = ICON_PATH . $icon . "-32.png";
  return $icon;
}

# calculate our timestamp for inclusion
$addrs = array();

$db = new PDO("sqlite:$DB_PATH") or die();

# list all children for a given host
$sql = "
  SELECT
    h.addr,
    a.addr
  FROM host h
  JOIN host_addr a
  ON a.host_id = h.id
  WHERE h.hp_id = (SELECT MAX(id) FROM host_perspective)";
#echo "$sql\n";
$stmt = $db->query($sql) or die(print_r($db->errorInfo(),1));
#$stmt->setFetchMode(PDO::FETCH_ASSOC);
$rows = $stmt->fetchAll();

#echo "rows=".print_r($rows,1);
#exit;

$addrs = array();
foreach ($rows as $row) {
  @$addrs[$row[0]]["children"][] = $row[1];
  #if (!isset($addrs[$row[0]]["OS"]))
  #  $addrs[$row[0]]["OS"] = array();
}

$stmt = null;
$rows = null;

function make_array($a)
{
  if (is_array($a))
    return $a;
  return array();
}

# get attributes

$sql="
SELECT
  ho.addr AS addr,
  a.addr,
  m.map AS map,
  m.maptype AS maptype,
  --hi.contents,
  SUM(m.weight) AS weight
FROM host AS ho
JOIN host_addr AS a ON a.host_id = ho.id
JOIN hint hi ON hi.addr = a.addr
-- only match hints that have occured for this host within the timeframe of the host;
-- TODO: split this query into two; one for the host_perspective and one for the attributes of it
AND hi.latest >= (SELECT earliest FROM host_perspective WHERE id = (SELECT MAX(id) from host_perspective))
JOIN map m ON m.val = hi.contents
-- we really, really want
-- WHERE m.maptype = 'OS'
-- but it's 100x slower in sqlite3
-- why, god, why?
WHERE ho.hp_id = (SELECT MAX(id) FROM host_perspective)
GROUP BY ho.addr,
         m.map
--ORDER BY sum(m.weight) DESC
";

#echo "$sql\n";
$stmt = $db->query($sql) or die(print_r($db->errorInfo(),1));
$stmt->setFetchMode(PDO::FETCH_ASSOC);
$rows = $stmt->fetchAll();

printf("/*\n%s\n*/\n", print_r($rows,1));
#exit;

# now build an array to map addrs child -> parent, so we can aggregate traffic
$rev = array();
reset($addrs);
while (list($addrfrom,$foo) = each($addrs)) {
  $addrto = make_array(@$foo["children"]);
  reset($addrto);
  while (list($k,$v) = each($addrto))
    $rev[$v] = $addrfrom;
}

#printf("/*\n%s\n*/\n", print_r($rows,1));

# apply mappings to addresses....
# problem is, address may be in $addrs[] or it may be a child of one, so we need to search two levels deep
# TODO: two ways to improve would be to apply mappings earlier, before addresses become hierarchical... or
# generate a reverse-mapping so at least the amount of work is based on number of addresses and not number of mappings...
foreach ($rows as $row) {
  if (isset($addrs[$row["addr"]])) {
    @$addrs[$row["addr"]][$row["maptype"]][] = $row["map"];
  } else {
    # FIXME: quick and dirty and ugly
    # search each key's array keys...
    reset($addrs);
    while (list($k,$v) = each($addrs)) {
      if (in_array($row["addr"], $v["children"])) {
        @$addrs[$k][$row["maptype"]][] = $row["map"];
        break;
      }
    }
  }
}

printf("/*\n%s\n*/\n", print_r($addrs,1));

$stmt = null;
$rows = null;

#echo "rev=".print_r($rev,1);

#echo "---\n"; print_r($addrs); exit;

printf("digraph {\n");
printf("  node [fontsize=8,penwidth=1,color=\"#EEEEEE\",shape=record,overlap=vpsc,fontname=\"Verdana\"];\n");
printf("  edge [color=\"#777777\",arrowsize=0.5,fontname=\"Verdana\",fontsize=4];\n");

# "Outside" CLOUD
printf("  \"%s\" [label=<
<TABLE BORDER=\"0\" CELLSPACING=\"1\" CELLPADDING=\"0\">
  <TR><TD><IMG SRC=\"%sicons-tango/network-cloud.png\"/></TD></TR><TR>
  <TD>%s<BR/>",
  "Outside", ICON_PATH, "Outside");
printf("</TD></TR></TABLE>>];\n");

#digraph structs { node [shape=record]; struct1 [label="<f0> left|<f1> mid\ dle|<f2> right"]; struct2 [label="<f0> one|<f1> two"]; struct3 [label="hello\nworld |{ b |{c|<here> d|e}| f}| g | h"]; struct1:f1 -> struct2:f0; struct1:f2 -> struct3:here; } 

# draw nodes
reset($addrs);
while (list($addrk,$addrto) = each($addrs)) {
  printf("  \"%s\" [label=<
  <TABLE BORDER=\"0\" CELLSPACING=\"1\" CELLPADDING=\"0\">
    <TR><TD><IMG SRC=\"%s\"/></TD></TR><TR>
    <TD>%s<BR/>",
    $addrk, icon($addrs, $addrk), $addrk);
  if (is_array(@$addrto["Dev"])) {
    printf("Dev=%s<BR/>", join(",", $addrto["Dev"]));
  }
  if (is_array(@$addrto["Role"])) {
    printf("Role=%s<BR/>", join(",", $addrto["Role"]));
  }
  if (is_array(@$addrto["OS"])) {
    printf("OS=%s<BR/>", join(",", $addrto["OS"]));
  }
  if (is_array(@$addrto["children"])) {
    reset($addrto["children"]);
    while (list($addrtok,$addrtov) = each($addrto["children"]))
      if ($addrtov != $addrk)
        printf("%s<BR/>", $addrtov);
  }
  printf("</TD></TR></TABLE>>];\n");
}

#draw edges

$edge = array();

# merge traffic between different addresses within the same hosts
# to a single edge
reset($addrs);
while (list($from,$srcv) = each($addrs)) {
  $sql = sprintf("
    SELECT
      to_,
      SUM(bytes)       AS bytes,
      SUM(bytes_encap) AS bytes_encap,
      SUM(counter)     AS counter
    FROM traffic
    WHERE from_ IN ('%s')
    AND to_ NOT LIKE '%%.255'
    GROUP BY to_;",
    join("','",
      array_merge(
        array($from),
        make_array(@$srcv["children"]))));
  #echo "$sql\n";
  $stmt = $db->query($sql) or die(print_r($db->errorInfo(),1));
  while (FALSE !== list($to,$bytes,$encap,$cnt) = $stmt->fetch()) {
    $realto = @$rev[$to];
    if (!$realto)
      $realto = $to;
    @$edge[$from][$realto] += $encap;
  }
}

echo "/* edges=".print_r($edge,1)."*/";

function colorize($n)
{
  $c = 0xF0 - log($n) / log(2) * 10;
  if ($c < 0) {
    $c = $c < -255 ? 255 : -$c;
    return sprintf("#%02x0000", $c);
  } else {
    return sprintf("#%02x%02x%02x", $c, $c, $c);
  }
}


# total "Outside" Gateway edges
# any traffic going to or from a Gateway is assumed to be to/from "Outside"
reset($edge);
while (list($from,$fromv) = each($edge)) {
  reset($fromv);
  while (list($to,$bytes) = each($fromv)) {
    # show route to outside for all routers,
    # even if we can't detect them directly
    if (@in_array("Gateway", $addrs[$to]["Role"]))
      @$edge[$to]["Outside"] += $bytes;
    if (@in_array("Gateway", $addrs[$from]["Role"]))
      @$edge["Outside"][$from] += $bytes;
  }
}

# print edges

reset($edge);
while (list($from,$fromv) = each($edge)) {
  reset($fromv);
  while (list($to,$bytes) = each($fromv)) {
    $width = log(sqrt($bytes+1))-4;
    if ($width < 0.1)
      $width = 0.1;
    printf("\"%s\" -> \"%s\" [penwidth=%.1f,color=\"%s\"]\n",
      $from, $to, $width, colorize($bytes));
  }
}

printf("}\n");

exit;

?>

