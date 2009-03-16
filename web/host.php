<!doctype html>
<html>
<head>
<style type="text/css">
BODY {
	padding:0;
}
</style>
</head>
<body>

<pre>
<?php
print_r($_GET);
?>
</pre>

<h1>Hostname (ID=<?php echo $_GET['id']; ?>)</h1>

<?php
$db = new PDO('sqlite:../db/db') or die();

# FIXME: merge with gen-graph code

$sql = sprintf("
SELECT
  ho.addr AS addr,
  a.addr,
  m.map AS map,
  m.maptype AS maptype,
	hi.hintsrc,
  hi.contents,
  hi.earliest,
  hi.latest,
  SUM(m.weight) AS weight
FROM host AS ho
JOIN host_addr AS a ON a.host_id = ho.id
JOIN hint hi ON hi.addr = a.addr
JOIN map m ON m.val = hi.contents
WHERE ho.hp_id = %s
AND a.host_id = %s
GROUP BY a.addr,
         m.map,
				 hi.contents
ORDER BY SUM(m.weight) DESC",
	$db->quote($_GET['hp_id']),
	$db->quote($_GET['id']));

$stmt = $db->query($sql) or die(print_r($db->errorInfo(),1));
$stmt->setFetchMode(PDO::FETCH_ASSOC);
$rows = $stmt->fetchAll();
$stmt = null;

foreach ($rows as $row) {
	$host[$row["addr"]][$row["maptype"]][] = $row["map"];
	$host[$row["addr"]][$row["maptype"]."-Hint"][] =
		array($row["map"],
					$row["hi.hintsrc"],
					$row["hi.contents"],
					$row["hi.earliest"],
					$row["hi.latest"],
					$row["weight"]);
}
?>

<table border="1">

<?php

function section($val, $key)
{
	if (is_array($val[$key])) {
		printf(
			"<tr><td colspan=\"6\"><img src=\"../img/%s/%s-128.png\">
			<span style=\"font-size:larger\">%s</span>",
			strtolower($key), $val["$key-Hint"][0][0], $key);
		foreach ($val["$key-Hint"] as $v) {
			echo "<tr><td>".join("<td>",$v);
		}
		echo "\n";
	}

}

reset($host);
while (list($addr,$val) = each($host)) {
	echo "<tr><td>Address<td colspan=\"4\">$addr";
	section($val, "Dev");
	section($val, "Role");
	section($val, "OS");
}

?>

</table>

<pre>
<?php
print_r($host);
?>
</pre>

</body>
</html>


