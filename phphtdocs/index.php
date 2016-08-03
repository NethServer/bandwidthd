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
<div class="container">
<?
// Get variables from url

if (isset($_GET['sensor_name']) && $_GET['sensor_name'] != "none") {
    $sensor_name = $_GET['sensor_name'];
} else {
    $sensor_name = 'unset';
}

if (isset($_GET['interval']) && $_GET['interval'] != "none")
    $interval = $_GET['interval'];

if (isset($_GET['timestamp']) && $_GET['timestamp'] != "none")
    $timestamp = $_GET['timestamp'];

if (isset($_GET['subnet']) && $_GET['subnet'] != "none")
    $subnet = $_GET['subnet'];

if (isset($_GET['limit']) && $_GET['limit'] != "none")
	$limit = $_GET['limit'];


$tmp = explode(':',$db_connect_string);
if ($tmp[0] == 'sqlite' && ! file_exists($tmp[1])) {
   die("Data not available. Please wait a couple of minutes, then reload the page.");
}
$db = ConnectDb();
?>
<FORM name="navigation" method="get">
<input type='hidden' name="sensor_name" value="unset"/>
<table class='table'>
<tr>
<td>Select An Interval: <SELECT name="interval" class="form-control">
<OPTION value=<?=INT_DAILY?> <?=$interval==INT_DAILY?"SELECTED":""?>>Daily
<OPTION value=<?=INT_WEEKLY?> <?=$interval==INT_WEEKLY?"SELECTED":""?>>Weekly
<OPTION value=<?=INT_MONTHLY?> <?=$interval==INT_MONTHLY?"SELECTED":""?>>Monthly
<OPTION value=<?=INT_YEARLY?> <?=$interval==INT_YEARLY?"SELECTED":""?>>Yearly
<OPTION value=<?=24*60*60?> <?=$interval==24*60*60?"SELECTED":""?>>24hrs
<OPTION value=<?=30*24*60*60?> <?=$interval==30*24*60*60?"SELECTED":""?>>30days
</select>

<td>How Many Results:<SELECT name="limit" class="form-control">
<OPTION value=20 <?=$limit==20?"SELECTED":""?>>20
<OPTION value=50 <?=$limit==50?"SELECTED":""?>>50
<OPTION value=100 <?=$limit==100?"SELECTED":""?>>100
<OPTION value=all <?=$limit=="all"?"SELECTED":""?>>All
</select>

<td>Subnet Filter:<input name=subnet value="<?=isset($subnet)?$subnet:"0.0.0.0/0"?>" class="form-control"></td>
<td style='vertical-align: bottom'><button type="submit" class="btn btn-default">Go</button></td>
</tr>
</table>
</FORM>
<?
// Set defaults
if (!isset($interval))
	$interval = DFLT_INTERVAL;

if (!isset($timestamp))
	$timestamp = time() - $interval + (0.05*$interval);

if (!isset($limit))
	$limit = 20;

// Validation
if (!isset($sensor_name))
	exit(0);

// Print Title

if (isset($limit))
	echo "<h2>Top $limit</h2>";
else
	echo "<h2>All Records</h2>";

// Sqlize the incomming variables
if (isset($subnet)) {
    $sql_subnet = prepare_sql_subnet($subnet);
}

// Sql Statement
$sql = "select tx.ip, rx.scale as rxscale, tx.scale as txscale, tx.total+rx.total as total, tx.total as sent, 
rx.total as received, tx.tcp+rx.tcp as tcp, tx.udp+rx.udp as udp,
tx.icmp+rx.icmp as icmp, tx.http+rx.http as http,
tx.p2p+rx.p2p as p2p, tx.ftp+rx.ftp as ftp
from

(SELECT ip, max(total/sample_duration)*8 as scale, sum(total) as total, sum(tcp) as tcp, sum(udp) as udp, sum(icmp) as icmp,
sum(http) as http, sum(p2p) as p2p, sum(ftp) as ftp
from sensors, bd_tx_log
where sensor_name = '$sensor_name'
and sensors.sensor_id = bd_tx_log.sensor_id
$sql_subnet
and timestamp > $timestamp and timestamp < ".($timestamp+$interval)."
group by ip) as tx,

(SELECT ip, max(total/sample_duration)*8 as scale, sum(total) as total, sum(tcp) as tcp, sum(udp) as udp, sum(icmp) as icmp,
sum(http) as http, sum(p2p) as p2p, sum(ftp) as ftp
from sensors, bd_rx_log
where sensor_name = '$sensor_name'
and sensors.sensor_id = bd_rx_log.sensor_id
$sql_subnet
and timestamp > $timestamp and timestamp < ".($timestamp+$interval)."
group by ip) as rx

where tx.ip = rx.ip
order by total desc;";

//echo "<pre>$sql</pre>";
$pdoResult = $db->query($sql);
$result = $pdoResult->fetchAll();
$db = NULL;
$num_rows = count($result);
if ($limit == "all")
	$limit = $num_rows;

echo "<table class='table table-striped table-hover'><thead><tr><th>Ip<th>Name<th>Total<th>Sent<th>Received<th>tcp<th>udp<th>icmp<th>http<th>smtp<th>ftp</th></tr></thead><tbody>";

if (!isset($subnet)) // Set this now for total graphs
	$subnet = "0.0.0.0/0";

// Output Total Line
echo "<TR><TD><a href='#Total'>Total</a><TD>$subnet";
foreach (array("total", "sent", "received", "tcp", "udp", "icmp", "http", "p2p", "ftp") as $key)
	{
	for($Counter=0, $Total = 0; $Counter < $num_rows; $Counter++)
		{
		$r = $result[$Counter];
		$Total += $r[$key];
		}
	echo fmtb($Total);
	}
echo "\n";

// Output Other Lines
for($Counter=0; $Counter < $num_rows && $Counter < $limit; $Counter++)
	{
	$r = $result[$Counter];
	$r['ip'] = long2ip($r['ip']);
	echo "<tr><td><a href=#".$r['ip'].">";
	echo $r['ip']."<td>".gethostbyaddr($r['ip']);
	echo "</a>";
	echo fmtb($r['total']).fmtb($r['sent']).fmtb($r['received']).
		fmtb($r['tcp']).fmtb($r['udp']).fmtb($r['icmp']).fmtb($r['http']).
		fmtb($r['p2p']).fmtb($r['ftp'])."\n";
	}
echo "</tbody></table>";

// Output Total Graph
for($Counter=0, $Total = 0; $Counter < $num_rows; $Counter++)
	{
	$r = $result[$Counter];
	$scale = max($r['txscale'], $scale);
	$scale = max($r['rxscale'], $scale);
	}

if ($subnet == "0.0.0.0/0")
	$total_table = "bd_tx_total_log";
else
	$total_table = "bd_tx_log";
echo "<a name=Total><h3><a href=details.php?sensor_name=$sensor_name&ip=$subnet>";
echo "Total - Total of $subnet</h3>";
echo "</a>";
echo "Send:<br><img src=graph.php?ip=$subnet&interval=$interval&sensor_name=".$sensor_name."&table=$total_table><br>";
echo "<img src=legend.gif><br>\n";
if ($subnet == "0.0.0.0/0")
	$total_table = "bd_rx_total_log";
else
	$total_table = "bd_rx_log";
echo "Receive:<br><img src=graph.php?ip=$subnet&interval=$interval&sensor_name=".$sensor_name."&table=$total_table><br>";
echo "<img src=legend.gif><br>\n";


// Output Other Graphs
for($Counter=0; $Counter < $num_rows && $Counter < $limit; $Counter++)
	{
	$r = $result[$Counter];
	$r['ip'] = long2ip($r['ip']);
	echo "<a name=".$r['ip']."><h3><a href=details.php?sensor_name=$sensor_name&ip=".$r['ip'].">";
	if ($r['ip'] == "0.0.0.0")
		echo "Total - Total of all subnets</h3>";
	else
		echo $r['ip']." - ".gethostbyaddr($r['ip'])."</h3>";
	echo "</a>";
	echo "Send:<br><img src=graph.php?ip=".$r['ip']."&interval=$interval&sensor_name=".$sensor_name."&table=bd_tx_log&yscale=".(max($r['txscale'], $r['rxscale']))."><br>";
	echo "<img src=legend.gif><br>\n";
	echo "Receive:<br><img src=graph.php?ip=".$r['ip']."&interval=$interval&sensor_name=".$sensor_name."&table=bd_rx_log&yscale=".(max($r['txscale'], $r['rxscale']))."><br>";
	echo "<img src=legend.gif><br>\n";
	}

include('footer.php');
