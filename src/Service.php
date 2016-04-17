<?php
namespace QBonaventure\InnerCryptography;

use Zend\Config\Config;

class Service {
	
	/**
	 * @var Config
	 */
	protected $config;
	
	protected $method	= 'aes-256-cbc';
	protected $hashAlgo = 'sha256';
	protected $key;
	protected $iv;
	
	public function __construct(Config $config) {
		$this->setConfig($config);
	}
	
	public function getConfig() {
		return $this->config;
	}
	
	protected function setConfig(Config $config) {
		$this->config	= $config;
		$this->key	= $config['key'];
		$this->iv	= $config['IV'];
		if($config['hash_algo'])
			$this->hashAlgo	= $config['hash_algo'];
		if($config['method'])
			$this->method	= $config['method'];
		
		return $this;
	}
	
	
	public function weakEncrypt($message, $key = null, $encode = false, $iv = null) {
		if(is_null($key))
			$key	= $this->key;
		if(is_null($iv))
			$iv	= $this->iv;
		
		$crypt	= @openssl_encrypt($message, $this->method, $key, 'OPENSSL_ZERO_PADDING', $iv);
		if($encode)
			return base64_encode($crypt);
			else
				return $crypt;
	}
	
	
	public function weakDecrypt($message, $key = null, $encoded = false, $iv = null) {
		if(is_null($key))
			$key	= $this->key;
		if(is_null($iv))
			$iv	= $this->iv;
		
		if($encoded)
			$message	= base64_decode($message);
			return @openssl_decrypt($message, $this->method, $key, 'OPENSSL_ZERO_PADDING', $iv);
	}
	
	
	public function encrypt($message, $key = null, $encode = false) {
		if(is_null($key))
			$key	= $this->key;
		
		list($encKey, $authKey) = self::splitKeys($key);
	
	
		$ivSize = openssl_cipher_iv_length($this->method);
		$iv = openssl_random_pseudo_bytes($ivSize);
	
		$cyphertext = @openssl_encrypt($message,
				$this->method,
				$encKey,
				'OPENSSL_ZERO_PADDING',
				$iv);
	
		$cyphertext	= $iv . $cyphertext;
	
		$mac = hash_hmac($this->hashAlgo, $cyphertext, $authKey, true);
	
		if ($encode)
			return base64_encode($mac).base64_encode($cyphertext);
			return $mac.$cyphertext;
	}
	
	
	
	public function decrypt($message, $key = null, $encoded = false) {
		if(is_null($key))
			$key	= $this->key;
		
		list($encKey, $authKey) = self::splitKeys($key);
	
	
		if($encoded) {
			$hs = mb_strlen(base64_encode(hash_hmac(self::HASH_ALGO, '', $authKey, true)));
			$mac = base64_decode(mb_substr($message, 0, $hs));
			$ciphertext = base64_decode(mb_substr($message, $hs));
		}
		else {
			$hs = mb_strlen(hash($this->hashAlgo, '', true), '8bit');
			$mac = mb_substr($message, 0, $hs, '8bit');
			$ciphertext = mb_substr($message, $hs, mb_strlen($message), '8bit');
		}
	
		$calculated = hash_hmac($this->hashAlgo,
				$ciphertext,
				$authKey,
				true);
	
		if (!self::hashEquals($mac, $calculated)) {
			throw new Exception('Encryption failure');
		}
	
	
		$ivSize = openssl_cipher_iv_length($this->method);
		$iv = mb_substr($ciphertext, 0, $ivSize, '8bit');
	
		$plaintext = @openssl_decrypt($ciphertext,
				$this->method,
				$encKey,
				'OPENSSL_ZERO_PADDING',
				$iv);
	
		return mb_substr($plaintext, openssl_cipher_iv_length($this->method));
		return $plaintext;
	}
	
	
	protected function splitKeys($masterKey) {
		// You really want to implement HKDF here instead!
		return array(hash_hmac($this->hashAlgo, 'ENCRYPTION', $masterKey, true),
				hash_hmac($this->hashAlgo, 'AUTHENTICATION', $masterKey, true));
	}
	
	
	protected function hashEquals($a, $b) {
		if (function_exists('hash_equals')) {
			return hash_equals($a, $b);
		}
		$nonce = openssl_random_pseudo_bytes(32);
		return hash_hmac($this->hashAlgo, $a, $nonce) === hash_hmac($this->hashAlgo, $b, $nonce);
	}
}