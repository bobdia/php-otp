<?php
include 'PhpEntropy.php';
include 'PassHash.php';

$ph = new PassHash('whirlpool', 32);
echo '<h3>Testing PassHash using Whirlpool</h3>';

echo 'Hashing "foo": ';

if(($h = $ph->HashPassword('foo')) === false) {
	echo 'FAIL';
} else {
	echo $h;
}

echo '<br>';

echo 'Checking "foo" against hash: ';
if($ph->CheckPassword('foo', $h)) {
	echo 'OK';
} else {
	echo 'FAIL';
}

echo '<h3>Debug messages</h3>';

echo '<pre>';
print_r($ph->debug);
echo '</pre>';

/* Test SHA */

$ph = new PassHash('sha512', 32);
echo '<h3>Testing PassHash using SHA-512</h3>';

echo 'Hashing "foo": ';

if(($h = $ph->HashPassword('foo')) === false) {
	echo 'FAIL';
} else {
	echo $h;
}

echo '<br>';

echo 'Checking "foo" against hash: ';
if($ph->CheckPassword('foo', $h)) {
	echo 'OK';
} else {
	echo 'FAIL';
}

echo '<h3>Debug messages</h3>';

echo '<pre>';
print_r($ph->debug);
echo '</pre>';

?>