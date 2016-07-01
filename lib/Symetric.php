<?php
namespace Flex\Crypto;

/**
 *	Abstraction class for mcrypt
 *	@var		string	$cipher		Algorithm
 *	@var		string	$mode		Mode
 *	@var		string	$key		Key
 *	@var		string	$iv			Initialization vector
 */
class Symetric {

	private $cipher;
	private $mode;
	private $key;
	private $iv;

	/**
	 *	Constructeur
	 *	@param	string	$cipher	Algorithm
	 *	@param	string	$mode	Mode
	 *	@param	string	$key	Key
	 */
	public function __construct ($cipher, $mode, $key) {
		if(!in_array($cipher, $this->getCiphers()))
			throw new Exception('Cipher not available');

		$this->cipher = $cipher;

		if(!in_array($mode, $this->getModes()))
			throw new Exception('Mode not available');

		$this->mode = $mode;

		$keysize = mcrypt_get_key_size($this->cipher, $this->mode);
		if(strlen($key) < $keysize){
			$key = substr(md5($key), 0, $keysize);
		}
		elseif(strlen($key) > $keysize){
			$key = substr($key, 0, $keysize);
		}
		$this->key = $key;
	}

	/**
	 *	Opens the module of the algorithm and the mode to be used
	 *	@return	resource	$module	Encryption descriptor
	 */
	private function open () {
		if(($module = mcrypt_module_open($this->cipher, '', $this->mode, '')) === false) {
			throw new Exception('Unable to open the module');
		}

		return $module;
	}

	/**
	 * Closes the mcrypt module
	 * @param	resource	$module	Encryption descriptor
	 */
	private function close ($module) {
		mcrypt_module_close($module);
	}

	/**
	 *	Create initialization vector
	 *  @param	resource	$module
	 */
	private function createIV ($module) {
		$iv_size = mcrypt_enc_get_iv_size($module);

		if(!empty($this->iv) && strlen($this->iv) == $iv_size)
			return;

		if(false === $this->iv = mcrypt_create_iv($iv_size, MCRYPT_DEV_URANDOM)){
			throw new Exception('Unable to create initialization vector');
		}
	}

	/**
	 *	Define initialization vector
	 *	@param string $iv Initialization vector
	 */
	public function setIV ($iv) {
		$this->iv = $iv;
	}

	/**
	 *	Encrypt a string
	 *	@param		string	$string	String to crypt
	 *	@return		string	$res	Crypted string
	 */
	public function encrypt ($string) {
		$module = $this->open();

		$this->createIV($module);

		mcrypt_generic_init($module, $this->key, $this->iv);
		$res = mcrypt_generic($module, $string);
		mcrypt_generic_deinit($module);
		
		$this->close($module);

		return base64_encode($this->iv.$res);
	}

	/**
	 *	Decrypt crypted string
	 *	@param		string	$crypt_encode	Crypted string base64 encoded
	 *	@return		string	$res	Decrypted string
	 */
	public function decrypt ($crypt_encode) {
		$module = $this->open();

		$iv_size = mcrypt_enc_get_iv_size($module);

		$crypt_decode = base64_decode($crypt_encode);

		$this->iv = substr($crypt_decode, 0, $iv_size);
		$crypt = substr($crypt_decode, $iv_size);

		if($crypt != ''){
			mcrypt_generic_init($module, $this->key, $this->iv);
			$res = mdecrypt_generic($module, $crypt);
			mcrypt_generic_deinit($module);
			$this->close($module);
			return $res;
		}
		else {
			return false;
		}

	}

	/**
	 *	Gets an array of all supported modes
	 *	@return	array	Returns an array with all the supported modes
	 */
	public function getModes(){
		return mcrypt_list_modes();
	}

	/**
	 *	Gets an array of all supported ciphers
	 *	@return	array	Returns an array with all the supported algorithms
	 */
	public function getCiphers(){
		return mcrypt_list_algorithms();
	}
}
