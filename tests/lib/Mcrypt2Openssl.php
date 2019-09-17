<?php
namespace Flex\Crypto\tests\units;

use Flex\Crypto\Mcrypt2Openssl as TestedClass;
use mageekguy\atoum;

class Mcrypt2Openssl extends atoum\test
{

    public function testGetBlowfish()
    {

        $cipher = TestedClass::get(MCRYPT_BLOWFISH, MCRYPT_MODE_CBC, 56);
        $this->string($cipher)->isEqualTo('bf-cbc');

        $cipher = TestedClass::get(MCRYPT_BLOWFISH, MCRYPT_MODE_CFB, 56);
        $this->string($cipher)->isEqualTo('bf-cfb');

        $cipher = TestedClass::get(MCRYPT_BLOWFISH, MCRYPT_MODE_ECB, 56);
        $this->string($cipher)->isEqualTo('bf-ecb');

        $cipher = TestedClass::get(MCRYPT_BLOWFISH, 'ncfb', 56);
        $this->string($cipher)->isEqualTo('bf-cfb');

        $cipher = TestedClass::get(MCRYPT_BLOWFISH, MCRYPT_MODE_NOFB, 56);
        $this->string($cipher)->isEqualTo('bf-ofb');

        $cipher = TestedClass::get(MCRYPT_BLOWFISH, MCRYPT_MODE_OFB, 56);
        $this->string($cipher)->isEqualTo('bf-ofb');
    }

    public function testGetCast128()
    {

        $cipher = TestedClass::get(MCRYPT_CAST_128, MCRYPT_MODE_CBC, 16);
        $this->string($cipher)->isEqualTo('cast5-cbc');

        $cipher = TestedClass::get(MCRYPT_CAST_128, MCRYPT_MODE_CFB, 16);
        $this->variable($cipher)->isNull();

        $cipher = TestedClass::get(MCRYPT_CAST_128, MCRYPT_MODE_ECB, 16);
        $this->string($cipher)->isEqualTo('cast5-ecb');

        $cipher = TestedClass::get(MCRYPT_CAST_128, 'ncfb', 16);
        $this->string($cipher)->isEqualTo('cast5-cfb');

        $cipher = TestedClass::get(MCRYPT_CAST_128, MCRYPT_MODE_NOFB, 16);
        $this->string($cipher)->isEqualTo('cast5-ofb');

        $cipher = TestedClass::get(MCRYPT_CAST_128, MCRYPT_MODE_OFB, 16);
        $this->variable($cipher)->isNull();
    }

    public function testGetDES()
    {

        $cipher = TestedClass::get(MCRYPT_DES, MCRYPT_MODE_CBC, 8);
        $this->string($cipher)->isEqualTo('des-cbc');

        $cipher = TestedClass::get(MCRYPT_DES, MCRYPT_MODE_CFB, 8);
        $this->string($cipher)->isEqualTo('des-cfb8');

        $cipher = TestedClass::get(MCRYPT_DES, MCRYPT_MODE_ECB, 8);
        $this->string($cipher)->isEqualTo('des-ecb');

        $cipher = TestedClass::get(MCRYPT_DES, 'ncfb', 8);
        $this->string($cipher)->isEqualTo('des-cfb');

        $cipher = TestedClass::get(MCRYPT_DES, MCRYPT_MODE_NOFB, 8);
        $this->string($cipher)->isEqualTo('des-ofb');

        $cipher = TestedClass::get(MCRYPT_DES, MCRYPT_MODE_OFB, 8);
        $this->variable($cipher)->isNull();
    }

    public function testGetAES128()
    {

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC, 16);
        $this->string($cipher)->isEqualTo('aes-128-cbc');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CFB, 16);
        $this->string($cipher)->isEqualTo('aes-128-cfb8');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB, 16);
        $this->string($cipher)->isEqualTo('aes-128-ecb');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, 'ncfb', 16);
        $this->string($cipher)->isEqualTo('aes-128-cfb');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_NOFB, 16);
        $this->string($cipher)->isEqualTo('aes-128-ofb');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_OFB, 16);
        $this->variable($cipher)->isNull();
    }

    public function testGetAES192()
    {

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC, 24);
        $this->string($cipher)->isEqualTo('aes-192-cbc');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CFB, 24);
        $this->string($cipher)->isEqualTo('aes-192-cfb8');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB, 24);
        $this->string($cipher)->isEqualTo('aes-192-ecb');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, 'ncfb', 24);
        $this->string($cipher)->isEqualTo('aes-192-cfb');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_NOFB, 24);
        $this->string($cipher)->isEqualTo('aes-192-ofb');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_OFB, 24);
        $this->variable($cipher)->isNull();
    }

    public function testGetAES256()
    {

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC, 32);
        $this->string($cipher)->isEqualTo('aes-256-cbc');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CFB, 32);
        $this->string($cipher)->isEqualTo('aes-256-cfb8');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB, 32);
        $this->string($cipher)->isEqualTo('aes-256-ecb');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, 'ncfb', 32);
        $this->string($cipher)->isEqualTo('aes-256-cfb');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_NOFB, 32);
        $this->string($cipher)->isEqualTo('aes-256-ofb');

        $cipher = TestedClass::get(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_OFB, 32);
        $this->variable($cipher)->isNull();
    }

    public function testGetTripleDES()
    {

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_CBC, 8);
        $this->string($cipher)->isEqualTo('des-cbc');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_CFB, 8);
        $this->string($cipher)->isEqualTo('des-cfb8');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_ECB, 8);
        $this->string($cipher)->isEqualTo('des-ecb');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, 'ncfb', 8);
        $this->string($cipher)->isEqualTo('des-cfb');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_NOFB, 8);
        $this->string($cipher)->isEqualTo('des-ofb');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_OFB, 8);
        $this->variable($cipher)->isNull();
    }

    public function testGetTripleDES_EDE()
    {

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_CBC, 16);
        $this->string($cipher)->isEqualTo('des-ede-cbc');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_CFB, 16);
        $this->variable($cipher)->isNull();

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_ECB, 16);
        $this->string($cipher)->isEqualTo('des-ede');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, 'ncfb', 16);
        $this->string($cipher)->isEqualTo('des-ede-cfb');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_NOFB, 16);
        $this->string($cipher)->isEqualTo('des-ede-ofb');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_OFB, 16);
        $this->variable($cipher)->isNull();
    }

    public function testGetTripleDES_EDE3()
    {

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_CBC, 24);
        $this->string($cipher)->isEqualTo('des-ede3-cbc');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_CFB, 24);
        $this->string($cipher)->isEqualTo('des-ede3-cfb8');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_ECB, 24);
        $this->string($cipher)->isEqualTo('des-ede3');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, 'ncfb', 24);
        $this->string($cipher)->isEqualTo('des-ede3-cfb');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_NOFB, 24);
        $this->string($cipher)->isEqualTo('des-ede3-ofb');

        $cipher = TestedClass::get(MCRYPT_TRIPLEDES, MCRYPT_MODE_OFB, 24);
        $this->variable($cipher)->isNull();
    }

    public function testGetTripleRC4()
    {

        $cipher = TestedClass::get(MCRYPT_ARCFOUR, MCRYPT_MODE_STREAM, 256);
        $this->string($cipher)->isEqualTo('rc4-40');
    }

    public function testGetBlowfishKeySize()
    {
        $size = TestedClass::getKeySize('bf-cbc');
        $this->integer($size)->isEqualTo(56);

        $size = TestedClass::getKeySize('bf-ecb');
        $this->integer($size)->isEqualTo(56);

        $size = TestedClass::getKeySize('bf-cfb');
        $this->integer($size)->isEqualTo(56);

        $size = TestedClass::getKeySize('bf-ofb');
        $this->integer($size)->isEqualTo(56);
    }

    public function testGetCast128Size()
    {
        $size = TestedClass::getKeySize('cast5-cbc');
        $this->integer($size)->isEqualTo(16);

        $size = TestedClass::getKeySize('cast5-ecb');
        $this->integer($size)->isEqualTo(16);

        $size = TestedClass::getKeySize('cast5-cfb');
        $this->integer($size)->isEqualTo(16);

        $size = TestedClass::getKeySize('cast5-ofb');
        $this->integer($size)->isEqualTo(16);
    }

    public function testGetDESSize()
    {
        $size = TestedClass::getKeySize('des-cbc');
        $this->integer($size)->isEqualTo(8);

        $size = TestedClass::getKeySize('des-cfb8');
        $this->integer($size)->isEqualTo(8);

        $size = TestedClass::getKeySize('des-ecb');
        $this->integer($size)->isEqualTo(8);

        $size = TestedClass::getKeySize('des-cfb');
        $this->integer($size)->isEqualTo(8);

        $size = TestedClass::getKeySize('des-ofb');
        $this->integer($size)->isEqualTo(8);
    }

    public function testGetAES128Size()
    {
        $size = TestedClass::getKeySize('aes-128-cbc');
        $this->integer($size)->isEqualTo(16);

        $size = TestedClass::getKeySize('aes-128-cfb8');
        $this->integer($size)->isEqualTo(16);

        $size = TestedClass::getKeySize('aes-128-ecb');
        $this->integer($size)->isEqualTo(16);

        $size = TestedClass::getKeySize('aes-128-cfb');
        $this->integer($size)->isEqualTo(16);

        $size = TestedClass::getKeySize('aes-128-ofb');
        $this->integer($size)->isEqualTo(16);
    }

    public function testGetAES192Size()
    {
        $size = TestedClass::getKeySize('aes-192-cbc');
        $this->integer($size)->isEqualTo(24);

        $size = TestedClass::getKeySize('aes-192-cfb8');
        $this->integer($size)->isEqualTo(24);

        $size = TestedClass::getKeySize('aes-192-ecb');
        $this->integer($size)->isEqualTo(24);

        $size = TestedClass::getKeySize('aes-192-cfb');
        $this->integer($size)->isEqualTo(24);

        $size = TestedClass::getKeySize('aes-192-ofb');
        $this->integer($size)->isEqualTo(24);
    }

    public function testGetAES256Size()
    {
        $size = TestedClass::getKeySize('aes-256-cbc');
        $this->integer($size)->isEqualTo(32);

        $size = TestedClass::getKeySize('aes-256-cfb8');
        $this->integer($size)->isEqualTo(32);

        $size = TestedClass::getKeySize('aes-256-ecb');
        $this->integer($size)->isEqualTo(32);

        $size = TestedClass::getKeySize('aes-256-cfb');
        $this->integer($size)->isEqualTo(32);

        $size = TestedClass::getKeySize('aes-256-ofb');
        $this->integer($size)->isEqualTo(32);
    }

    public function testGetTripleDESSize()
    {
        $size = TestedClass::getKeySize('des-cbc');
        $this->integer($size)->isEqualTo(8);

        $size = TestedClass::getKeySize('des-cfb8');
        $this->integer($size)->isEqualTo(8);

        $size = TestedClass::getKeySize('des-ecb');
        $this->integer($size)->isEqualTo(8);

        $size = TestedClass::getKeySize('des-cfb');
        $this->integer($size)->isEqualTo(8);

        $size = TestedClass::getKeySize('des-ofb');
        $this->integer($size)->isEqualTo(8);
    }

    public function testGetTripleDES_EDESize()
    {
        $size = TestedClass::getKeySize('des-ede-cbc');
        $this->integer($size)->isEqualTo(16);

        $size = TestedClass::getKeySize('des-ede');
        $this->integer($size)->isEqualTo(16);

        $size = TestedClass::getKeySize('des-ede-cfb');
        $this->integer($size)->isEqualTo(16);

        $size = TestedClass::getKeySize('des-ede-ofb');
        $this->integer($size)->isEqualTo(16);
    }

    public function testGetTripleDES_EDE3Size()
    {
        $size = TestedClass::getKeySize('des-ede3-cbc');
        $this->integer($size)->isEqualTo(24);

        $size = TestedClass::getKeySize('des-ede3-cfb8');
        $this->integer($size)->isEqualTo(24);

        $size = TestedClass::getKeySize('des-ede3');
        $this->integer($size)->isEqualTo(24);

        $size = TestedClass::getKeySize('des-ede3-cfb');
        $this->integer($size)->isEqualTo(24);

        $size = TestedClass::getKeySize('des-ede3-ofb');
        $this->integer($size)->isEqualTo(24);
    }

    public function testGetTripleRC4Size()
    {
        $size = TestedClass::getKeySize('rc4-40');
        $this->integer($size)->isEqualTo(256);
    }

    public function testGetDefaultSize()
    {
        $size = TestedClass::getKeySize('xtea-cbc');
        $this->integer($size)->isEqualTo(16);
    }

}
