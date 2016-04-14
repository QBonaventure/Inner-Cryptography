<?php
namespace Inner\Cryptography;


class Service {
	
	const METHOD	= 'aes-256-cbc';
	const HASH_ALGO = 'sha256';
	const KEY		= 'JoqXQkZEKXuHBxzs6iAfBHDIULTtrJPqI1IYDS0Ffy0ToPWUjDi4HeDqIbYl2FgkcsXwZQs29tr9cvOZ6w4thsTaq1VZtTOYRkG5eJG2UX8zuBkptrPRJ3P6sGAmMQ62HWgbtyXtVG76n8qm0PoZieTOshdYnas7EMfQ9xzkkUV9boTeat0T9kuZzU6MkD8R24s8dAnJluuus8snF2CbUpNVAPzR7Z52q0Rn0zvhbHjLg58n8qhnuGQ3ZiMIOABJPL1da8OPWA3IcgAenKl+MG9SaPYnOl9eXfNyGFL+lbP2Lyhbgy57bFpaCthxGYE4v4OAPYvCMrz0HCeZrJFkZzTdMG3pHSt9Z+yZ6Z4ZsqnqnT2Gaan94zHwqlMgGi1Wm9UqaErJv94yXoiZfNlRCVBdNYUvT6Q0SrSVAKhZ9iMrwURatmZ0YlTamJg7wq6WHPexkZh8G8m0063H5rcCdTsB7qRaKnGxUOpthpvtZyyR1LIxuv7HPPXiOAKcsC90';
	const IV		= 'FRQYrUYtwNWPZNxY';
	
	
	public static function weakEncrypt($message, $key = self::KEY, $encode = false, $iv = self::IV) {
		$crypt	= @openssl_encrypt($message, self::METHOD, $key, 'OPENSSL_ZERO_PADDING', $iv);
		if($encode)
			return base64_encode($crypt);
			else
				return $crypt;
	}
	
	
	public static function weakDecrypt($message, $key = self::KEY, $encoded = false, $iv = self::IV) {
		if($encoded)
			$message	= base64_decode($message);
			return @openssl_decrypt($message, self::METHOD, $key, 'OPENSSL_ZERO_PADDING', $iv);
	}
	
	
	public static function encrypt($message, $key = self::KEY, $encode = false) {
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
	
	
	
	public static function decrypt($message, $key = self::KEY, $encoded = false) {
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