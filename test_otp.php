<?php

include 'php-otp.php';
include 'PhpEntropy.php';
include 'PassHash.php';

echo '<h3>Generating 10 random passwords</h3>';
$otp = new phpotp();
$passes = $otp->passwords('bah',10,32);

echo 'Total: '. count($passes) . '<br>';
echo 'Unique: '. count(array_unique($passes)). '<br><br>';
echo '<pre>';
print_r($passes);
echo '</pre>';

echo '<h3>Hashing password with secret: "foo"</h3>';

$hashes = $otp->hashPasswords('foo', $passes);

echo '<pre>';
print_r($hashes);
echo '</pre>';

echo '<h3>Check if hashes match "foo".$password</h3>';

$ph = new PassHash();
$checks = array();

foreach($passes as $n => $pass) {
	$checks[$n] = ($ph->CheckPassword('foo'.$pass, $hashes[$n]) === false) ? 'false' : 'true';

}
echo '<pre>';
print_r($checks);
echo '</pre>';
?>