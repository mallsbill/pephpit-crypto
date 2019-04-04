<?php
namespace Flex\Crypto;

class Substitution {

	private $key;
	private $pbox = array();

	/**
	 * @param string $key Key
	 * @param array $pbox Multi-dimensional substitution box
	 */
	public function __construct($key, array $pbox) {
		$this->key = $key;
		$this->pbox = $pbox;
	}

	/**
	 *	Subsitute string
	 *	@param string $string String to substitute
	 *	@param string $pbox Substitution box
	 *	@return string Substituted string
	 */
	private function substitute($string, $pbox) {
		$length = strlen($string);
		$string_substituted = '';
		
		for($i = 0; $i < $length; $i++){
			$string_substituted .= $string[$pbox[$i]];
		}
		return $string_substituted;
	}

	/**
	 * Xor bit shifting between string and key
	 * http://php.net/manual/en/language.operators.bitwise.php
	 * @param string $string String to xor
	 * @return string String result after xor
	 */
	private function xorBitShifting($string) {
		if(empty($this->key)) {
			throw new \LogicException('key can\'t be empty');
		}
		// key should have same length than string
		else if(strlen($this->key) > count($this->pbox[0])) {
			$key = substr($this->key, 0, count($this->pbox[0]));
		}
		else if(strlen($this->key) < count($this->pbox[0])) {
			$key = str_pad($this->key, count($this->pbox[0]), $this->key);
		}
		else {
			$key = $this->key;
		}
		
		return $string^$key;
	}


	/**
	 * Encrypt a string
	 * @param string $string String to encrypt
	 * @return string Encrypted
	 */
	public function encrypt($string) {
		if(strlen($string) > count($this->pbox[0])) {
			throw new \InvalidArgumentException('String can\'t be longer than your pbox length');
		}

		// string should have same length than pbox
		$string = str_pad($string, count($this->pbox[0]), ' ');

		foreach($this->pbox as $pbox) {
			$string_substituted = $this->substitute($string, $pbox);
			$string = $this->xorBitShifting($string_substituted);
		}

		return $string;
	}


	/**
	 *	Decrypt crypted string
	 *	@param string $crypt Crypted string
	 *	@return string Decrypted string
	 */
	public function decrypt($crypt) {
		$pboxes = array_reverse($this->pbox);
		
		foreach($pboxes as $pbox) {
			$crypt_substituted = $this->xorBitShifting($crypt);
			$crypt = $this->substitute($crypt_substituted, array_flip($pbox));
		}

		$string = rtrim($crypt);

		return $string;
	}

	/**
	 * Return a PBox
	 * @param array $choices
	 * @param int $dimension
	 * @return array PBox array
	 */
	public function generatePBox($length = 30, $dimension = 3) {
		$pbox = array();
		

		for($i = 0; $i < $dimension; $i++) {
			$positions = range(0, $length-1);
			shuffle($positions);
			$pbox[$i] = $positions;
		}

		return $pbox;
	}

}
