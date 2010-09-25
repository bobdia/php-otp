<?php
/*
Name: PhpEntropy
Author: Robert Diaes
Version: 0.9
URL: http://disattention.php/labs/php/entropy
Description: PhpEntropy is a collection of entropy gathering methods for PHP. 

*/

class PhpEntropy {

	public $debug = array();
	
	public $types = array(
					'urandom',
					'mtshatime',
					'openssl',
					'mcrypt',
					'mtrand',
					'time',
					'rand',
					'randomorg',
					'hotbits',
					'windows',
					);
					
	
	public function random($length, $types=null,$returnAll=false) {
		if($types) {
			$types = explode(',',$types);
		} else {
			$types = $this->types;
		}
		if($returnAll) {
			$entropy = array();
		} else {
			$entropy = '';
		}
		foreach($types as $fn) {
			if($returnAll) {
				$entropy[] = $this->$fn($length);
			} else {
				$entropy = $this->$fn($length);
			}
			if($entropy === false) {
				continue;
			} else {
				break;
			}
		}
		return $entropy;
	}
	
	protected  function debug($msg) {
		$this->debug[] = $msg;
	}
	
	public function mtshatime($length) {
		$entropy = '';
		
		do {
			$entropy .= sha1(microtime() . $entropy . mt_rand());
		} while($length*2 > strlen($entropy));
		
		$entropy = substr($entropy, 0, $length*2);
		
		return $entropy;
	
	}

	public function shatime($length) {
		$entropy = '';
		
		do {
			$entropy .= sha1(microtime() . $entropy);
		} while($length*2 > strlen($entropy));
		
		$entropy = substr($entropy, 0, $length*2);
		
		return $entropy;
	}
	
	public function rand($length) {
		$entropy = '';
		do {
			$entropy .= dechex(rand());
		} while($length*2 > strlen($entropy));
		
		$entropy = substr($entropy, 0, $length*2);
		return $entropy;
	}

	public function mtrand($length) {
		$entropy = '';
		do {
			$entropy .= dechex(mt_rand());
		} while($length*2 > strlen($entropy));
		
		$entropy = substr($entropy, 0, $length*2);
		return $entropy;
	}
	
	public function randomorg($length) {
		
		$len = 4;
		
		$num = (int) ($length/$len);
		if(($length % $len ) > 0) { $num++; }
		
		$url = 'https://www.random.org/integers/?num='.$num;
		$url .= '&min=0&max=1000000000&col=1&base=16&format=plain&rnd=new';
		
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_HEADER, 0);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 1);
		curl_setopt($ch, CURLOPT_FAILONERROR, 1);
		
		
		$re = curl_exec($ch);
		
		if($re === false) {
			// curl error
			$this->debug('cURL error');
			return false;
		}
		
		$entropy = str_replace("\n", '', $re);
		$en = strlen($entropy);
		if($en < $length * 2) {
			$this->debug('randomorg shorter than expected');
			return false;
			
		}
		if($en > $length * 2) {
			$entropy = substr($entropy, 0, $length * 2);
		}
		return $entropy;
	}

	public function hotbits($length) {
		//https://www.fourmilab.ch/hotbits/secure_generate.html
		if($length > 2048) { $length = 2048; }
		$url = 'https://www.fourmilab.ch/cgi-bin/Hotbits?nbytes='.$length.'&fmt=hex';

		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_HEADER, 0);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 1);
		curl_setopt($ch, CURLOPT_FAILONERROR, 1);
		
		$re = curl_exec($ch);

		if($re === false) {
			// curl error
			$this->debug('cURL error');
			return false;
		}
		
		if((($s1 = strpos($re, '<pre>')) !== false) && (($s2 = strpos($re, '</pre>')) !== false)) {
			$entropy = substr($re, $s1+6,$s2-$s1-7);
			$entropy = str_replace("\n", '', $entropy);
		} else {
			$this->debug('hotbits sent wrong html');
			return false;
		}
		
		if(strlen($entropy) > $length*2) {
			$entropy = substr($entropy,0,$length*2);
		}
		
		return $entropy;
	}
	
	public function openssl($length) {
		$entropy = '';
		// try ssl first
		if (function_exists('openssl_random_pseudo_bytes')) {
			$entropy = openssl_random_pseudo_bytes($length, $strong);
			// skip ssl since it wasn't using the strong algo
			if($strong !== true) {
				$this->debug('openssl not strong');
				return false;
			} else {
				return $entropy;
			}
		} else {
			$this->debug('openssl_random_pseudo_bytes is not available');
			return false;
		}
	}
	
	/*
	The source can be MCRYPT_RAND (system random number generator), MCRYPT_DEV_RANDOM (read data from /dev/random) and MCRYPT_DEV_URANDOM (read data from /dev/urandom). Prior to 5.3.0, MCRYPT_RAND was the only one supported on Windows. 
	*/
	public function mcrypt($length, $source=MCRYPT_RAND) {
		if(function_exists('mcrypt_create_iv')) {
			$ent = mcrypt_create_iv($length, $source);
			$entropy = '';
			for($i=0; $i < $length; $i++) {
				$entropy .= dechex(ord($ent{$i}));
			}
			
			return $entropy;
		} else {
			$this->debug(' mcrypt_create_iv is not available');
			return false;
		}
	}

	public function urandom($length) {
		$entropy = '';
		// try to read from the linux pRNG
		if (is_readable('/dev/urandom') &&
		    ($fh = @fopen('/dev/urandom', 'rb'))) {
			$entropy = fread($fh, $length);
			fclose($fh);
			return $entropy;
		} else {
			$this->debug('/dev/urandom not readable');
			return false;
		}
	}

	public function windows($length) {
		$entropy = '';
		// try to read from the windows RNG
		if (class_exists('COM')) {
			try {
				$arr = range(0,$length);
				$com = new COM('System.Security.Cryptography.RNGCryptoServiceProvider');
				$entropy .= implode('',$com->GetBytes($arr));
			} catch (Exception $ex) {
				$this->debug('COM exception '.print_r($ex,true));
				return false;
			}
			return $entropy;
		} else {
			$this->debug('COM not available');
			return false;
		}
	}
}
?>