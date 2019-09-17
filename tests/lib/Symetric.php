<?php
namespace Flex\Crypto\tests\units;

use Flex\Crypto\Symetric as TestedClass;
use mageekguy\atoum;

class Symetric extends atoum\test
{

    public function testGetCiphers()
    {

        $key = 'xcCLTuw1rv';

        $symetric = new TestedClass("bf-cbc", null, $key);
        $cipher_list = $symetric->getCiphers();

        $this->array($cipher_list)->isNotEmpty();
    }

    public function testCryptDecryptBF_CBC()
    {

        $key = 'xcCLTuw1rv';
        $string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

        $symetric = new TestedClass("bf-cbc", null, $key);
        $crypt = $symetric->encrypt($string);

        $this->string($crypt)->isNotEmpty();

        $symetric = new TestedClass("bf-cbc", null, $key);
        $decrypt = $symetric->decrypt($crypt);

        $this->string($decrypt)->isEqualTo($string);
    }

    public function testCryptDecryptBF_NOFB()
    {

        $key = 'xcCLTuw1rv';
        $string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

        $symetric = new TestedClass("bf-ofb", null, $key);
        $crypt = $symetric->encrypt($string);

        $this->string($crypt)->isNotEmpty();

        $symetric = new TestedClass("bf-ofb", null, $key);
        $decrypt = $symetric->decrypt($crypt);

        $this->string($decrypt)->isEqualTo($string);
    }

    public function testCryptDecryptCAST128()
    {

        $key = 'xcCLTuw1rv';
        $string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

        $symetric = new TestedClass("cast5-cfb", null, $key);
        $crypt = $symetric->encrypt($string);

        $this->string($crypt)->isNotEmpty();

        $symetric = new TestedClass("cast5-cfb", null, $key);
        $decrypt = $symetric->decrypt($crypt);

        $this->string($decrypt)->isEqualTo($string);
    }

    public function testDecryptBFWithMcrypt()
    {

        if (function_exists('mcrypt_decrypt') === false)
            return;

        $key = 'xcCLTuw1rv';
        $string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

        $symetric = new TestedClass(MCRYPT_BLOWFISH, MCRYPT_MODE_NOFB, $key);
        $crypt = $symetric->encrypt($string);
        $crypt_encoded = $symetric->encrypt($string);

        $crypt_decode = base64_decode($crypt_encoded);

        $iv = substr($crypt_decode, 0, 8);
        $crypt = substr($crypt_decode, 8);

        $decrypt = mcrypt_decrypt(MCRYPT_BLOWFISH, $symetric->getKey(), $crypt, MCRYPT_MODE_NOFB, $iv);

        $this->string($decrypt)->isEqualTo($string);
    }

    public function testDecryptCAST128WithMcrypt()
    {

        if (function_exists('mcrypt_decrypt') === false)
            return;

        $key = 'xcCLTuw1rv';
        $string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

        $symetric = new TestedClass(MCRYPT_CAST_128, 'ncfb', $key);
        $crypt = $symetric->encrypt($string);
        $crypt_encoded = $symetric->encrypt($string);

        $crypt_decode = base64_decode($crypt_encoded);

        $iv = substr($crypt_decode, 0, 8);
        $crypt = substr($crypt_decode, 8);

        $decrypt = mcrypt_decrypt(MCRYPT_CAST_128, $symetric->getKey(), $crypt, 'ncfb', $iv);

        $this->string($decrypt)->isEqualTo($string);
    }

}
