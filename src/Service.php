<?php
/**
 * @author	Quentin Bonaventure
 * @link    https://github.com/QBonaventure/Inner-Cryptography for the canonical source repository
 * @license New BSD License
 */

namespace QBonaventure\InnerCryptography;

use Zend\Config\Config;

class Service {
	
	/**
	 * @var Config
	 */
	protected $config;
	
	/**
	 * Default cypher method
	 * @var $method
	 */
	protected $method	= 'aes-256-cbc';
	
	/**
	 * Default hash algorithm 
	 * @var $hashAlgo
	 */
	protected $hashAlgo = 'sha256';
	
	/**
	 * Encryption key
	 * @var $key
	 */
	protected $key;
	
	/**
	 * Initialisation vector, used for weak encryption
	 * @var $iv
	 */
	protected $iv;
	
	/**
	 * Hash cost for the PHP password_hash() function
	 * @var $cost
	 */
	protected $cost;
	
	/**
	 * 
	 * @param Zend\Config\Config $config
	 */
	public function __construct(Config $config) {
		$this->setConfig($config);
	}
	
	public function getConfig() {
		return $this->config;
	}
	
	
	
	public function setConfig(Config $config) {
		$this->config	= $config;
		
		if (is_null($config['key'])) {
			throw new \InvalidArgumentException('The "key" must be configured');
		}
		$this->key	= $config['key'];

		if (is_null($config['iv'])) {
			throw new \InvalidArgumentException('The "IV" must be configured');
		}
		$this->iv	= $config['iv'];
		

		if (!is_null($config['hashCost']))
		{
			if($config['hashCost'] <= 0)
				throw new \InvalidArgumentException('When set, "cost" param must be an integer superior to 0');
			$this->cost	= $config['hashCost'];
		}
		
		if($config['hash_algo'])
			$this->hashAlgo	= $config['hash_algo'];
		if($config['method'])
			$this->method	= $config['method'];
		
		return $this;
	}
	
	
	public function weakEncrypt($message, $key = null, $encode = false, $iv = null) {
		if (is_null($key)) {
			$key	= $this->key;
		}
		if (is_null($iv)) {
			$iv	= $this->iv;
		}
		
		$crypt	= openssl_encrypt($message, $this->method, $key, OPENSSL_RAW_DATA, $iv);
		
		if($encode) {
			$crypt   = base64_encode($crypt);
        }
        
        return $crypt;
	}
	
	
	public function weakDecrypt($message, $key = null, $encoded = false, $iv = null) {
		if (is_null($key)) {
			$key	= $this->key;
		}
		if (is_null($iv)) {
			$iv	= $this->iv;
		}
		if ($encoded) {
			$message	= base64_decode($message);
        }
        
        return openssl_decrypt($message, $this->method, $key, OPENSSL_RAW_DATA, $iv);
	}
	
	
	public function encrypt($message, $key = null, $encode = false) {		
		if (is_null($key)) {
			$key	= $this->key;
		}
		
		list($encKey, $authKey) = $this->splitKeys($key);
	
		$ivSize = openssl_cipher_iv_length($this->method);
		$iv = openssl_random_pseudo_bytes($ivSize);

		$cyphertext = openssl_encrypt($message,
                        				$this->method,
                        				$encKey,
                        				OPENSSL_RAW_DATA,
                        				$iv);

		$cyphertext	= $iv . $cyphertext;
		$mac = hash_hmac($this->hashAlgo, $cyphertext, $authKey, true);

		if ($encode) {
			return base64_encode($mac).base64_encode($cyphertext);
		}
		
		return $mac.$cyphertext;
	}
	
	
	
	public function decrypt($message, $key = null, $encoded = false) {
		if (is_null($key)) {
			$key	= $this->key;
        }
		
		list($encKey, $authKey) = $this->splitKeys($key);

	
		if ($encoded) {
			$hs = mb_strlen(base64_encode(hash_hmac($this->hashAlgo, '', $authKey, true)));
			$mac = base64_decode(mb_substr($message, 0, $hs));
			$ciphertext = base64_decode(mb_substr($message, $hs));
		} else {
			$hs = mb_strlen(hash($this->hashAlgo, '', true), '8bit');
			$mac = mb_substr($message, 0, $hs, '8bit');
			$ciphertext = mb_substr($message, $hs, mb_strlen($message), '8bit');
		}

		$calculated = hash_hmac($this->hashAlgo,
                				$ciphertext,
                				$authKey,
                				true);
	
		if (!$this->hashEquals($mac, $calculated)) {
			throw new Exception('Encryption failure');
		}
	
		$ivSize = openssl_cipher_iv_length($this->method);
		$iv = mb_substr($ciphertext, 0, $ivSize, '8bit');
		
		$plaintext = openssl_decrypt($ciphertext,
				$this->method,
				$encKey,
				true,
				$iv);
		
		return substr($plaintext, openssl_cipher_iv_length($this->method), mb_strlen($plaintext));
	}
	



	/**
	 * Simple access to the PHP password_hash() function http://php.net/manual/fr/function.password-hash.php
	 * along with the config set by the user.
	 * @param string $string The string to hash
	 * @return string A hash
	 */
	function hash($string) {
		$options = [];
		if (!is_null($this->cost))
			$options	= ['cost'	=> $this->cost];
		
		return password_hash($string, PASSWORD_DEFAULT, $options);
	}
	
	
	/**
	 * Simple access to the PHP password_verify() function http://php.net/manual/fr/function.password-verify.php
	 * @param string $string The string to check
	 * @param string $hash The hash to check the $string against
	 * @return boolean
	 */
	function checkHash($string, $hash) {
		return password_verify($string, $hash);
	}
	
	
	/**
	 * HKDF for keys derivation.
	 * @param string $masterKey
	 * @return string[]
	 */
	protected function splitKeys($masterKey) {
		return [hash_hmac($this->hashAlgo, 'ENCRYPTION', $masterKey, true),
                hash_hmac($this->hashAlgo, 'AUTHENTICATION', $masterKey, true)];
	}
	
	/**
	 * Tests whether the provided hashes are equal
	 * @param string $a
	 * @param string $b
	 * @return boolean
	 */
	protected function hashEquals($a, $b) {
		if (function_exists('hash_equals')) {
			return hash_equals($a, $b);
		}
		
		$nonce = openssl_random_pseudo_bytes(32);
		return hash_hmac($this->hashAlgo, $a, $nonce) === hash_hmac($this->hashAlgo, $b, $nonce);
	}
}