<?php
#
# ex: set ts=2 et:
# 
# TODO: update the hosts in the actual database
#

error_reporting(E_ALL);

require_once("inc.db.php");
require_once("algorithm-conglomerate.php");

function get_pers_id($db, $early_ts, $late_ts)
{
  $sql = sprintf("
    SELECT id
    FROM host_perspective
    WHERE latest >= DATETIME(%s,'LOCALTIME')
    OR earliest <= DATETIME(%s,'LOCALTIME');",
      $db->quote($early_ts),
      $db->quote($late_ts));
      echo "$sql\n";
  $stmt = $db->query($sql) or die(print_r($db->errorInfo(),1));
  if ($stmt->rowCount()) {
    $id = $stmt->fetchColumn(1);
  } else {
    $sql = sprintf("
      INSERT INTO host_perspective(earliest,latest)
      VALUES(DATETIME(%s,'LOCALTIME'),DATETIME(%s,'LOCALTIME'));",
        $db->quote($early_ts),
        $db->quote($late_ts));
    echo "$sql\n";
    $stmt = $db->query($sql) or die(print_r($db->errorInfo(),1));
    $id = $db->lastInsertId();
  }
  echo "id=$id\n";
  return $id;
}

function host_create($db, $pers_id, $root_addr)
{
  $sql = sprintf("INSERT INTO host(hp_id,addr)VALUES(%u,%s)",
    $pers_id, $db->quote($root_addr));
  $stmt = $db->query($sql) or die(print_r($db->errorInfo(),1));
  $id = $db->lastInsertId();
  return $id;
}

function host_add_addr($db, $host_id, $addr)
{
  $sql = sprintf("INSERT INTO host_addr(host_id,addr)VALUES(%u,%s)",
    $host_id, $db->quote($addr));
  $stmt = $db->query($sql) or die(print_r($db->errorInfo(),1));
}

function create_hosts($db, $early_ts, $late_ts, $addrs)
{
  $pers_id = get_pers_id($db, $early_ts, $late_ts);
  reset($addrs);
  while (list($addrfrom,$addrto) = each($addrs)) {
    printf("%s\n", $addrfrom);
    $host_id = host_create($db, $pers_id, $addrfrom);
    reset($addrto);
    while (list($k,$v) = each($addrto)) {
      printf("  %s\n", $k);
      host_add_addr($db, $host_id, $k);
    }
  }
}

# calculate our timestamp for inclusion
$earliest = strtotime("-48 hours");
$latest = time();
$early_ts = date("Y-m-d H:i:s", $earliest);
$late_ts = date("Y-m-d H:i:s", $latest);
$hints = array();
$addrs = array();
$to = array();

$db = new PDO("sqlite:$DB_PATH") or die();

$sql = sprintf("
  SELECT from_, to_
  FROM addr
  WHERE latest >= DATETIME(%s,'LOCALTIME')
  -- AND earliest <= DATETIME(%s,'LOCALTIME')
  AND from_ NOT LIKE 'htype=%%'
  AND to_ NOT LIKE 'htype=%%'
  UNION
  -- any MAC addresses that haven't got any other addresses associated
  -- with them, but do have a hint or two
  SELECT DISTINCT addr, addr
  FROM hint
  WHERE addrtype = 'M'
  AND addr NOT LIKE 'htype=%%'
  AND latest >= DATETIME(%s,'LOCALTIME')
  AND earliest <= DATETIME(%s,'LOCALTIME')",
    $db->quote($early_ts),
    $db->quote($late_ts),
    $db->quote($early_ts),
    $db->quote($late_ts));
echo "$sql\n";
$stmt = $db->query($sql) or die(print_r($db->errorInfo(),1));
$res = $stmt->setFetchMode(PDO::FETCH_ASSOC);
$rows = $stmt->fetchAll();
$res = null;
$stmt = null;

$addrs = array();
foreach ($rows as $row)
	$addrs[$row['from_']][$row['to_']] = $row;

$rows = null;

#echo "orig: "; var_dump($addrs);
#printf("original %d\n", count($addrs));
#echo "before addrs=".print_r($addrs,1);
#exit;

$addrs = conglomerate($addrs);

echo "after addrs=".print_r($addrs,1);
#exit;

create_hosts($db, $early_ts, $late_ts, $addrs);

?>

