<?php
namespace Flex\Crypto;

class Mcrypt2Openssl {

	/**
	 * Return OpenSSL cipher name for a Mcrypt cipher name and mode name
	 * Return null if no corresponding cipher
	 * @param string $cipher Mcrypt Cipher name
	 * @param string $mode Mcrypt Mode name
	 * @param int $keylength Key length
	 * @return string OpenSSL Cipher
	 * @see https://github.com/tom--/mcrypt2openssl/blob/master/mapping.md
	 */
	public static function get($cipher, $mode, $keylength) {

		if($cipher == MCRYPT_BLOWFISH || $cipher == MCRYPT_BLOWFISH_COMPAT) {
			if($mode == MCRYPT_MODE_CBC)
				return 'bf-cbc';			
			else if($mode == MCRYPT_MODE_ECB)
				return 'bf-ecb';
			else if($mode == 'ncfb')
				return 'bf-cfb';
			else if($mode == MCRYPT_MODE_NOFB)
				return 'bf-ofb';
		}
		else if($cipher == MCRYPT_CAST_128) {
			if($mode == MCRYPT_MODE_CBC)
				return 'cast5-cbc';
			else if($mode == MCRYPT_MODE_ECB)
				return 'cast5-ecb';
			else if($mode == 'ncfb')
				return 'cast5-cfb';
			else if($mode == MCRYPT_MODE_NOFB)
				return 'cast5-ofb';
		}
		else if($cipher == MCRYPT_DES) {
			if($mode == MCRYPT_MODE_CBC)
				return 'des-cbc';
			else if($mode == MCRYPT_MODE_CFB)
				return 'des-cfb8';
			else if($mode == MCRYPT_MODE_ECB)
				return 'des-ecb';
			else if($mode == 'ncfb')
				return 'des-cfb';
			else if($mode == MCRYPT_MODE_NOFB)
				return 'des-ofb';
		}
		else if($cipher == MCRYPT_RIJNDAEL_128 && $keylength == 16) {
			if($mode == MCRYPT_MODE_CBC)
				return 'aes-128-cbc';
			else if($mode == MCRYPT_MODE_CFB)
				return 'aes-128-cfb8';
			else if($mode == MCRYPT_MODE_ECB)
				return 'aes-128-ecb';
			else if($mode == 'ncfb')
				return 'aes-128-cfb';
			else if($mode == MCRYPT_MODE_NOFB)
				return 'aes-128-ofb';
		}
		else if($cipher == MCRYPT_RIJNDAEL_128 && $keylength == 24) {
			if($mode == MCRYPT_MODE_CBC)
				return 'aes-192-cbc';
			else if($mode == MCRYPT_MODE_CFB)
				return 'aes-192-cfb8';
			else if($mode == MCRYPT_MODE_ECB)
				return 'aes-192-ecb';
			else if($mode == 'ncfb')
				return 'aes-192-cfb';
			else if($mode == MCRYPT_MODE_NOFB)
				return 'aes-192-ofb';
		}
		else if($cipher == MCRYPT_RIJNDAEL_128 && $keylength == 32) {
			if($mode == MCRYPT_MODE_CBC)
				return 'aes-256-cbc';
			else if($mode == MCRYPT_MODE_CFB)
				return 'aes-256-cfb8';
			else if($mode == MCRYPT_MODE_ECB)
				return 'aes-256-ecb';
			else if($mode == 'ncfb')
				return 'aes-256-cfb';
			else if($mode == MCRYPT_MODE_NOFB)
				return 'aes-256-ofb';
		}
		else if($cipher == MCRYPT_TRIPLEDES && $keylength == 8) {
			if($mode == MCRYPT_MODE_CBC)
				return 'des-cbc';
			else if($mode == MCRYPT_MODE_CFB)
				return 'des-cfb8';
			else if($mode == MCRYPT_MODE_ECB)
				return 'des-ecb';
			else if($mode == 'ncfb')
				return 'des-cfb';
			else if($mode == MCRYPT_MODE_NOFB)
				return 'des-ofb';
		}
		else if($cipher == MCRYPT_TRIPLEDES && $keylength == 16) {
			if($mode == MCRYPT_MODE_CBC)
				return 'des-ede-cbc';
			/*else if($mode == MCRYPT_MODE_CFB)
				return 'des-ede-cfb8';*/
			else if($mode == MCRYPT_MODE_ECB)
				return 'des-ede';
			else if($mode == 'ncfb')
				return 'des-ede-cfb';
			else if($mode == MCRYPT_MODE_NOFB)
				return 'des-ede-ofb';
		}
		else if($cipher == MCRYPT_TRIPLEDES && $keylength == 24) {
			if($mode == MCRYPT_MODE_CBC)
				return 'des-ede3-cbc';
			else if($mode == MCRYPT_MODE_CFB)
				return 'des-ede3-cfb8';
			else if($mode == MCRYPT_MODE_ECB)
				return 'des-ede3';
			else if($mode == 'ncfb')
				return 'des-ede3-cfb';
			else if($mode == MCRYPT_MODE_NOFB)
				return 'des-ede3-ofb';
		}
		else if($cipher == MCRYPT_ARCFOUR) {
			if($mode == MCRYPT_MODE_STREAM)
				return 'rc4-40';
		}
	}

	public static function getKeySize($openssl_cipher) {

		if(preg_match('/^bf-/i', $openssl_cipher)) {
			return 56;
		}
		else if(preg_match('/^cast5/i', $openssl_cipher)) {
			return 16;
		}
		else if(preg_match('/^des-ede3/i', $openssl_cipher)) {
			return 24;
		}
		else if(preg_match('/^des-ede/i', $openssl_cipher)) {
			return 16;
		}
		else if(preg_match('/^des-/i', $openssl_cipher)) {
			return 8;
		}
		else if(preg_match('/^aes-128-/i', $openssl_cipher)) {
			return 16;
		}
		else if(preg_match('/^aes-192-/i', $openssl_cipher)) {
			return 24;
		}
		else if(preg_match('/^aes-256-/i', $openssl_cipher)) {
			return 32;
		}
		else if(preg_match('/^rc4-/i', $openssl_cipher)) {
			return 256;
		}
		else {
			return 16;
		}
	}

}
