<?php

/*
user sends secret,number,length

generate passwords

hash each password + secret

store in database
	user, id, hash, state(active, used, waiting)
	
user asks to login via otp

system returns a random id, changes state to waiting

user sends pass matching id

system compares pass with hash, if correct changes state to used

system returns session token

user does stuff with session

user logs out
*/


class phpotp {

	public $en_sources = 'urandom,mtshatime,randomorg,hotbits';
	//removed look-alikes: o,O,l,0
	protected $chars = '-_=$#@123456789abcdefghijkmnpqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ';

	protected $hash_algo = 'whirlpool';
	
	
	public function passwords($number, $number, $length) {
		$passwords = array();
		$entropy = '';
		$e = new PhpEntropy();
		$total = ($length * number)*2;
		
		do {
			$ents = $e->random(128,$this->en_sources, true);
			foreach($ents as $ent) {
				$entropy .= str_shuffle($ent);
			}
			$entropy = str_shuffle($entropy);
		} while( $total > strlen($entropy));
		
		$seeds = str_split($entropy,$length*2);
		
		for($i=0; $i<$number; $i++) {
			$pass ='';
			$seed = array_pop($seeds).$i.microtime();
			do {
				$pass .= hash($this->hash_algo, $seed.$pass.microtime());
			} while(strlen($pass) < $length * 2);
			
			if(strlen($pass) > $length * 2) {
				$pass = substr($pass,0,$length*2);
			}
			$passwords[$i] = $this->encode($pass);
		}
	
		return $passwords;
	}
	
	protected function encode($hex) {
		$chars = $this->chars;
		$bytes = str_split($hex,2);
		$out = '';
		
		foreach($bytes as $hex_byte) {
			$d = hexdec($hex_byte);
			
			$n = $d % 64;
			$out .= $this->chars{$n};
		}

		return $out;
	}
	
	public function hashPasswords($secret,$passwords) {
		$hashes = array();
		$ph = new PassHash();
		
		foreach($passwords as $n => $password) {
		
			if(($hash = $ph->HashPassword($secret.$password)) !== false) {;
				$hashes[$n] = $hash;
			} else {
				$this->debug('Hashing failed for password '. $n );
			}
		
		}
		
		return $hashes;
	}
	

	
	public function checkPassword($pass, $hash) {
		$ph = new PassHash();
		$check = $ph->CheckPassword($pass,$hash);
		return $check;
	}
}

class phpotpFile {
	
	public $data = array();
	public $locks = array();
	
	protected $newline = "\n";
	
	public function __construct($filename, $hashes=null) {
	
		$this->filename = $filename;
		
		if($hashes === null) {
			$lines = file($filename);
			$head =  array_shift($lines);
			$heads = explode(' ', $head);
			
			foreach($lines as $line) {
				$id = substr($line, 0, $heads[0]);
				$hash = substr($line, $heads[0], $heads[1]);
				$this->data[$id] = $hash;
			}
		} else {
			$this->data = $hashes;
		}
	}
	
	public function get($id) {
		return $this->data[$id];
	
	}
	
	public function delete($id) {
		unset($this->data[$id]);
	}
	
	public function random() {
		$id = array_rand($this->data);
		return array($id, $this->data[$id]);
	
	}
	
	
	public function store() {
		
		$hashes = $this->data;

		$output = '';
		
		$k = count($hashes);
		$nk = strlen($k);
		$head = $nk.' '.strlen($hashes[0]);
		
		$output .= $head;
		
		foreach($hashes as $n => $hash) {
				$num = sprintf('%0'.$nk.'d', $n);
				$output .=  $num . $hash . $this->newline;
		}
		
		file_put_contents($this->filename,$output);
	}

}

?>