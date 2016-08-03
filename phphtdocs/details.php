<!DOCTYPE html>
<?include("include.php");?>
<html lang=html>
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="css/bootstrap.min.css">
<link rel="stylesheet" href="css/bootstrap-theme.min.css">
</head>
<body>
<div class='container'>
<?
if (isset($_GET['sensor_name']))
    $sensor_name = $_GET['sensor_name'];
else
    {
    echo "<br>Please provide a sensor_name";
    exit(1);
    }

if (isset($_GET['ip']))
    $ip = $_GET['ip'];
else
    {
    echo "<br>Please provide an ip address";
    exit(1);
    }
                                                                                                                             
echo "<h3>";
if (strpos($ip, "/") === FALSE)
	echo "$ip - ".gethostbyaddr($ip)."</h3>";
else
	echo "Total - $ip</h3>";

$db = ConnectDb();

if ($ip == "0.0.0.0/0")
	{
    $rxtable = "bd_rx_total_log";
	$txtable = "bd_tx_total_log";
	}
else
	{
    $rxtable = "bd_rx_log";
	$txtable = "bd_tx_log";
	}

$sql_subnet = prepare_sql_subnet($ip);

$sql = "select rx.scale as rxscale, tx.scale as txscale, tx.total+rx.total as total, tx.total as sent,
rx.total as received, tx.tcp+rx.tcp as tcp, tx.udp+rx.udp as udp,
tx.icmp+rx.icmp as icmp, tx.http+rx.http as http,
tx.p2p+rx.p2p as p2p, tx.ftp+rx.ftp as ftp
from
                                                                                                                             
(SELECT ip, max(total/sample_duration)*8 as scale, sum(total) as total, sum(tcp) as tcp, sum(udp) as udp, sum(icmp) as icmp,
sum(http) as http, sum(p2p) as p2p, sum(ftp) as ftp
from sensors, $txtable
where sensor_name = '$sensor_name'
and sensors.sensor_id = ".$txtable.".sensor_id
$sql_subnet
group by ip) as tx,
                                                                                                                             
(SELECT ip, max(total/sample_duration)*8 as scale, sum(total) as total, sum(tcp) as tcp, sum(udp) as udp, sum(icmp) as icmp,
sum(http) as http, sum(p2p) as p2p, sum(ftp) as ftp
from sensors, $rxtable
where sensor_name = '$sensor_name'
and sensors.sensor_id = ".$rxtable.".sensor_id
$sql_subnet
group by ip) as rx
                                                                                                                             
where tx.ip = rx.ip;";
//error_log($sql); printf('<tt>%s</tt>', $sql);
$db = ConnectDb();
$result = $db->query($sql);
echo "<table class='table table-striped table-hover'><thead><tr><th>Ip<th>Name<th>Total<th>Sent<th>Received<th>tcp<th>udp<th>icmp<th>http<th>smtp<th>ftp</th></tr></thead><tbody>";
$r = $result->fetch();
$db = NULL;
echo "<tr class='table-striped'><td>";
if (strpos($ip, "/") === FALSE)
	echo "$ip<td>".gethostbyaddr($ip);
else
	echo "Total<td>$ip";
echo fmtb($r['total']).fmtb($r['sent']).fmtb($r['received']).
	fmtb($r['tcp']).fmtb($r['udp']).fmtb($r['icmp']).fmtb($r['http']).
    fmtb($r['p2p']).fmtb($r['ftp']);
echo "</tbody></table>";

echo "<h4>Daily</h4>";
echo "Send:<br><img src=graph.php?ip=$ip&sensor_name=".$sensor_name."&table=$txtable&yscale=".(max($r['txscale'], $r['rxscale']))."><br>";
echo "<img src=legend.gif><br>";
echo "Receive:<br><img src=graph.php?ip=$ip&sensor_name=".$sensor_name."&table=$rxtable&yscale=".(max($r['txscale'], $r['rxscale']))."><br>";
echo "<img src=legend.gif><br>";

echo "<h4>Weekly</h4>";
echo "Send:<br><img src=graph.php?interval=".INT_WEEKLY."&ip=$ip&sensor_name=$sensor_name&table=$txtable&yscale=".(max($r['txscale'], $r['rxscale']))."><br>";
echo "<img src=legend.gif><br>";
echo "Receive:<br><img src=graph.php?interval=".INT_WEEKLY."&ip=$ip&sensor_name=$sensor_name&table=$rxtable&yscale=".(max($r['txscale'], $r['rxscale']))."><br>";
echo "<img src=legend.gif><br>";

echo "<h4>Monthly</h4>";
echo "Send:<br><img src=graph.php?interval=".INT_MONTHLY."&ip=$ip&sensor_name=$sensor_name&table=$txtable&yscale=".(max($r['txscale'], $r['rxscale']))."><br>";
echo "<img src=legend.gif><br>";
echo "Receive:<br><img src=graph.php?interval=".INT_MONTHLY."&ip=$ip&sensor_name=$sensor_name&table=$rxtable&yscale=".(max($r['txscale'], $r['rxscale']))."><br>";
echo "<img src=legend.gif><br>";

echo "<h4>Yearly</h4>";
echo "Send:<br><img src=graph.php?interval=".INT_YEARLY."&ip=$ip&sensor_name=$sensor_name&table=$txtable&yscale=".(max($r['txscale'], $r['rxscale']))."><br>";
echo "<img src=legend.gif><br>";
echo "Receive:<br><img src=graph.php?interval=".INT_YEARLY."&ip=$ip&sensor_name=$sensor_name&table=$rxtable&yscale=".(max($r['txscale'], $r['rxscale']))."><br>";
echo "<img src=legend.gif><br>";

include('footer.php');
