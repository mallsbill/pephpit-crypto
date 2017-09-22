<?php
namespace Flex\Crypto\tests\units;

use Flex\Crypto\Symetric as TestedClass;
use	mageekguy\atoum;

class Symetric extends atoum\test {

	public function testCryptDecrypt() {

		$key = 'xcCLTuw1rv';
		$string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

		$symetric = new TestedClass(MCRYPT_BLOWFISH, MCRYPT_MODE_NOFB, $key);
		$crypt = $symetric->encrypt($string);

		$this->string($crypt)->isNotEmpty();

		$symetric = new TestedClass(MCRYPT_BLOWFISH, MCRYPT_MODE_NOFB, $key);
		$decrypt = $symetric->decrypt($crypt);

		$this->string($decrypt)->isEqualTo($string);
	}

}
