<?php
/*
Name: PassHash
Author: Robert Diaes
Version: 1.0
URL: http://disattention.php/labs/php/passhash
Description: PassHash is a PHP5 password hashing class. It is loosely based on phpass, the original license of which is reproduced verbatim below.

# Portable PHP password hashing framework.
#
# Version 0.3 / genuine.
#
# Written by Solar Designer <solar at openwall.com> in 2004-2006 and placed in
# the public domain.  Revised in subsequent years, still public domain.
#
# There's absolutely no warranty.
#
# The homepage URL for this framework is:
#
#	http://www.openwall.com/phpass/
#
# Please be sure to update the Version line if you edit this file in any way.
# It is suggested that you leave the main version number intact, but indicate
# your project name (after the slash) and add your own revision information.
#
# Please do not change the "private" password hashing method implemented in
# here, thereby making your hashes incompatible.  However, if you must, please
# change the hash type identifier (the "$P$") to something different.
#
# Obviously, since this code is in the public domain, the above are not
# requirements (there can be none), but merely suggestions.
*/

class PassHash {

	public $algo;	
	public $rounds;
	public $debug = array();
	
	// you can add more hashing algorithms here
	// hash name => id, length in chars (will be halved by encode())
	protected $algos = array(
		'whirlpool' => array('a1',128),
		'sha512' => array('h1',128)
		);
	protected $sogla = array(
		'a1' => 'whirlpool',
		'h1' => 'sha512'
		);
	

	public function __construct($algo='whirlpool', $rounds=16) {
		if ($rounds < 4 || $rounds > 99) {
			$rounds = 16;
		}
		$this->rounds = $rounds;
		
		if(isset($this->algos[$algo])) {
			$this->algo = $algo;
		} else {
			$this->algo = 'whirlpool';
		}
	}
	
	public function HashPassword($password) {
		$r = $this->random($this->salt_length - 6);
		$salt = $this->salt($r);
		
		$hash = $this->crypt($password,$salt);
		if($hash === false) {
			$this->debug('hashing failed');
			return false;
		}
		
		// Check hash length
		$n = $this->HashSize();
		$hn = strlen($hash);
		if ($hn == $n) {
			return $hash;
		} else {
			$this->debug('invalid hash length: '. $hn .' required: '. $n);
			return false;
		}
	}

	public function CheckPassword($password, $stored_hash) {
		$hash = $this->crypt($password, $stored_hash);

		return $hash == $stored_hash;
	}

	// hash size in chars
	public function HashSize() {
		$algo_length = $this->algos[$this->algo][1];
		return $this->salt_length + $algo_length;
	}
	
	protected function debug($msg) {
		$this->debug[] = $msg;
	}
	
	// length in bytes, returns a length*2 hex string
	protected function random($length) {
		$e = new PhpEntropy();
		$entropy = $e->random($length,'mtshatime');
		return $entropy;
	}
	
	// DANGER! Do not change unless you are sure about what you are doing.
	private $salt_length = 22;
	
	protected function salt($hex) {
		$a = $this->algo;
		$id = '$'.$this->algos[$a][0].'$';
		
		$output = $id;
		
		$output .= sprintf('%02d',$this->rounds).'$';
		$output .= $hex;
		
		if(strlen($output) > $this->salt_length) {
			$output = substr($output,0,$this->salt_length);
		}
		return $output;
	}

	protected function crypt($password, $salt) {
		$salt = substr($salt, 0, $this->salt_length);
		
		// check for valid hash id
		$ogla = substr($salt, 1,2);
		if(isset($this->sogla[$ogla])) {
			$algo = $this->sogla[$ogla];
		} else {
			$this->debug('invalid hash id: '. $ogla);
			return false;
		}
		
		// check stretching rounds
		$rounds = (int) substr($salt, 4,5);
		if ($rounds < 4 || $rounds > 99) {
			$this->debug('invalid number of rounds: '. $rounds);
			return false;
		}
		
		$hash = hash($algo, $salt . $password);
		do {
			$hash = hash($algo, $hash . $password);
		} while (--$rounds);
		
		$stretch_length = strlen($hash);
		
		if($stretch_length > $this->algos[$algo][1]) {
			$hash = substr($hash,0, $this->algos[$algo][1]);
			$this->debug('warning, invalid hash length after stretching: '. $stretch_length .' required: '. $this->algos[$algo][1] );
		}
		
		$output = $salt;
		$output .= $hash;

		return $output;
	}	
	
}

?>
