<?php
namespace QBonaventure\InnerCryptography;

use Zend\Config\Config;

class Service {
	
	const METHOD	= 'aes-256-cbc';
	const HASH_ALGO = 'sha256';
	protected $key;
	protected $iv;
	
	public function __construct(Config $config) {
		$this->key	= $config['key'];
		$this->iv	= $config['IV'];
	}
	
	
	public static function weakEncrypt($message, $key = null, $encode = false, $iv = null) {
		if(is_null($key))
			$key	= $this->key;
		if(is_null($iv))
			$iv	= $this->iv;
		
		$crypt	= @openssl_encrypt($message, self::METHOD, $key, 'OPENSSL_ZERO_PADDING', $iv);
		if($encode)
			return base64_encode($crypt);
			else
				return $crypt;
	}
	
	
	public static function weakDecrypt($message, $key = null, $encoded = false, $iv = null) {
		if(is_null($key))
			$key	= $this->key;
		if(is_null($iv))
			$iv	= $this->iv;
		
		if($encoded)
			$message	= base64_decode($message);
			return @openssl_decrypt($message, self::METHOD, $key, 'OPENSSL_ZERO_PADDING', $iv);
	}
	
	
	public function encrypt($message, $key = null, $encode = false) {
		if(is_null($key))
			$key	= $this->key;
		
		list($encKey, $authKey) = self::splitKeys($key);
	
	
		$ivSize = openssl_cipher_iv_length(self::METHOD);
		$iv = openssl_random_pseudo_bytes($ivSize);
	
		$cyphertext = @openssl_encrypt($message,
				self::METHOD,
				$encKey,
				'OPENSSL_ZERO_PADDING',
				$iv);
	
		$cyphertext	= $iv . $cyphertext;
	
		$mac = hash_hmac(self::HASH_ALGO, $cyphertext, $authKey, true);
	
		if ($encode)
			return base64_encode($mac).base64_encode($cyphertext);
			return $mac.$cyphertext;
	}
	
	
	
	public static function decrypt($message, $key = null, $encoded = false) {
		if(is_null($key))
			$key	= $this->key;
		
		list($encKey, $authKey) = self::splitKeys($key);
	
	
		if($encoded) {
			$hs = mb_strlen(base64_encode(hash_hmac(self::HASH_ALGO, '', $authKey, true)));
			$mac = base64_decode(mb_substr($message, 0, $hs));
			$ciphertext = base64_decode(mb_substr($message, $hs));
		}
		else {
			$hs = mb_strlen(hash(self::HASH_ALGO, '', true), '8bit');
			$mac = mb_substr($message, 0, $hs, '8bit');
			$ciphertext = mb_substr($message, $hs, mb_strlen($message), '8bit');
		}
	
		$calculated = hash_hmac(self::HASH_ALGO,
				$ciphertext,
				$authKey,
				true);
	
		if (!self::hashEquals($mac, $calculated)) {
			throw new Exception('Encryption failure');
		}
	
	
		$ivSize = openssl_cipher_iv_length(self::METHOD);
		$iv = mb_substr($ciphertext, 0, $ivSize, '8bit');
	
		$plaintext = @openssl_decrypt($ciphertext,
				self::METHOD,
				$encKey,
				'OPENSSL_ZERO_PADDING',
				$iv);
	
		return mb_substr($plaintext, openssl_cipher_iv_length(self::METHOD));
		return $plaintext;
	}
	
	
	protected static function splitKeys($masterKey) {
		// You really want to implement HKDF here instead!
		return array(hash_hmac(self::HASH_ALGO, 'ENCRYPTION', $masterKey, true),
				hash_hmac(self::HASH_ALGO, 'AUTHENTICATION', $masterKey, true));
	}
	
	
	protected static function hashEquals($a, $b) {
		if (function_exists('hash_equals')) {
			return hash_equals($a, $b);
		}
		$nonce = openssl_random_pseudo_bytes(32);
		return hash_hmac(self::HASH_ALGO, $a, $nonce) === hash_hmac(self::HASH_ALGO, $b, $nonce);
	}
}