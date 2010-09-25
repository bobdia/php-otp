<?php
include 'phpEntropy.php';
if(isset($_GET['len']) && !empty($_GET['len'])) {
		$length = (int) $_GET['len'];
}
?>
<html>
<head><title>PhpEntropy Test</title></head>
<style type="text/css">
    table {border-collapse: collapse;}
    table, td, th {border: solid 1px #ccc;}
    th {background: #e1e1e1;border-color: #999;}
    td, th {padding: 0.25em;}
    td.algo {font-weight: bold;}
	td.hash { font-family: "Courier New", Courier, monospace; }
    tr.on td {background: #f0f0f0;}
</style>
<body>
    <h1>Testing PhpEntropy</h1>
    <form method="get" action="<?php echo basename(__FILE__) ?>">
        <p><label for="p">Enter a length (bytes):</label><br /><input id="len" type="text" name="len" value="<?php echo $length ?>" /></p>
        <p><input type="submit" name="submit" value="Run" /></p>
    </form>
   
    <hr />
    <h2>Table of random values</h2>
	
<pre>
<?php


?>
</pre>	
    <table>
        <tr>
            <th>Source</th>
            <th>Value</th>
        </tr>
    <?php
	if($length) {
		$on = false; 
		$sources = array(
			'shatime' => 'shatime',
			'rand()' => 'rand',
			'mt_rand()' => 'mtrand',
			'mtshatime' => 'mtshatime',
			'Random.org' => 'randomorg',
			'HotBits' => 'hotbits',
			'OpenSSL' => 'openssl',
			'Mcrypt' => 'mcrypt',
			'/dev/urandom' => 'urandom',
			'Windows GetRandom' => 'windows'
			
			);
		$en = new phpEntropy();
		
		foreach ($sources as $src => $f) {
			$cl = $on?'':' class="on"';
			$tr = '<tr'.$cl.'>';
			$tr .= '<td class="algo">'.$src.'</td>';
			$tr .= '<td class="hash">'.$en->$f($length).'</td>';
			$tr .= '</tr>';
			echo $tr;
			$on = !$on;
		}
	}
   ?>
    </table>
	<h3>Debug messages</h3>
	<?php
	//$e = $en->randomorg(32); 
	
	echo '<pre>';
	print_r($en->debug);
	echo '</pre>';
	?>
</body>
</html>