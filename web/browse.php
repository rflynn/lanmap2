<!doctype html>
<html>
<head>
<style type="text/css">
BODY {
  font-family:Verdana;
  font-size:small;
}
UL {
  margin-left:0.5em;
  padding:1px;
}
</style>
</head>
<body>
<?php
$db = new PDO('sqlite:../db/db') or die();
$sql = "SELECT hp_id,id FROM host WHERE hp_id = (SELECT MAX(hp_id) FROM host) AND addr='00:21:29:70:ea:46'";
$stmt = $db->query($sql) or die(print_r($db->errorInfo(),1));
list($hp_id,$id) = $stmt->fetch();
?>
<ul>
  <li><a href="net.html" target="main">View network</a>
  <li><a href="host.php?hp_id=<?php echo $hp_id; ?>&id=<?php echo $id; ?>" target="main">Host</a> by...
    <ul>
    <li>Hostname
    <li>IP Address
    <li>Role
      <ul>
        <li>Bridge
        <li>Router
        <li>Server
          <ul>
            <li>All...
            <li>DHCP
            <li>Mail
            <li>DNS
          </ul>
        <li>Client
      </ul>
    <li>Operating System
    <li>Hardware
   </ul>
  <li>Reports
    <ul>
      <li>Traffic
      <li>Host
    </ul>
  <li>Problems
    <ul>
      <li>Rogue DHCP
      <li>Servers down
      <li>Internet down
      <li>Unwanted traffic
      <li>Unexpected hosts
    </ul>
</ul>
</body>
</html>
