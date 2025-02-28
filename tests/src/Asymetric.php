<?php
namespace Pephpit\Crypto\tests\units;

use Pephpit\Crypto\Asymetric as TestedClass;
use atoum;

class Asymetric extends atoum
{

    public function testCryptDecryptPublic()
    {

        $string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

        $fp = fopen(realpath(dirname(__FILE__)) . '/../key/public.crt', 'r');
        $public_key = fread($fp, 8192);
        fclose($fp);

        $asymetric = new TestedClass();
        $asymetric->setPublicKey($public_key);
        $crypt = $asymetric->publicEncrypt($string);

        $this->string($crypt)->isNotEmpty();

        $fp = fopen(realpath(dirname(__FILE__)) . '/../key/private.key', 'r');
        $private_key = fread($fp, 8192);
        fclose($fp);

        $asymetric = new TestedClass();
        $asymetric->setPrivateKey($private_key);
        $decrypt = $asymetric->privateDecrypt($crypt);

        $this->string($decrypt)->isEqualTo($string);
    }

    public function testCryptDecryptPublicFile()
    {

        $string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

        $asymetric = new TestedClass();
        $asymetric->setPublicKeyFile(realpath(dirname(__FILE__)) . '/../key/public.crt');
        $crypt = $asymetric->publicEncrypt($string);

        $this->string($crypt)->isNotEmpty();

        $asymetric = new TestedClass();
        $asymetric->setPrivateKeyFile(realpath(dirname(__FILE__)) . '/../key/private.key');
        $decrypt = $asymetric->privateDecrypt($crypt);

        $this->string($decrypt)->isEqualTo($string);
    }

    public function testCryptDecryptPrivate()
    {

        $string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

        $fp = fopen(realpath(dirname(__FILE__)) . '/../key/private.key', 'r');
        $private_key = fread($fp, 8192);
        fclose($fp);

        $asymetric = new TestedClass();
        $asymetric->setPrivateKey($private_key);
        $crypt = $asymetric->privateEncrypt($string);

        $this->string($crypt)->isNotEmpty();

        $fp = fopen(realpath(dirname(__FILE__)) . '/../key/public.crt', 'r');
        $public_key = fread($fp, 8192);
        fclose($fp);

        $asymetric = new TestedClass();
        $asymetric->setPublicKey($public_key);
        $decrypt = $asymetric->publicDecrypt($crypt);

        $this->string($decrypt)->isEqualTo($string);
    }

    public function testCryptDecryptPrivateFile()
    {

        $string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

        $asymetric = new TestedClass();
        $asymetric->setPrivateKeyFile(realpath(dirname(__FILE__)) . '/../key/private.key');
        $crypt = $asymetric->privateEncrypt($string);

        $this->string($crypt)->isNotEmpty();

        $asymetric = new TestedClass();
        $asymetric->setPublicKeyFile(realpath(dirname(__FILE__)) . '/../key/public.crt');
        $decrypt = $asymetric->publicDecrypt($crypt);

        $this->string($decrypt)->isEqualTo($string);
    }

    public function testCryptDecryptPublicFileOAEP()
    {

        $string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

        $asymetric = new TestedClass();
        $asymetric->setPublicKeyFile(realpath(dirname(__FILE__)) . '/../key/public.crt');
        $asymetric->setPadding(OPENSSL_PKCS1_OAEP_PADDING);
        $crypt = $asymetric->publicEncrypt($string);

        $this->string($crypt)->isNotEmpty();

        $asymetric = new TestedClass();
        $asymetric->setPrivateKeyFile(realpath(dirname(__FILE__)) . '/../key/private.key');
        $asymetric->setPadding(OPENSSL_PKCS1_OAEP_PADDING);
        $decrypt = $asymetric->privateDecrypt($crypt);

        $this->string($decrypt)->isEqualTo($string);
    }

    public function testCryptDecryptPublicFileSSLV23()
    {

        $string = 'hdLo2gGU459fUy0ICXpFMXpRXJpYT8TbjqCv48J0xMtDjKvpEh';

        $asymetric = new TestedClass();
        $asymetric->setPublicKeyFile(realpath(dirname(__FILE__)) . '/../key/public.crt');
        $asymetric->setPadding(OPENSSL_SSLV23_PADDING);
        $crypt = $asymetric->publicEncrypt($string);

        $this->string($crypt)->isNotEmpty();

        $asymetric = new TestedClass();
        $asymetric->setPrivateKeyFile(realpath(dirname(__FILE__)) . '/../key/private.key');
        $decrypt = $asymetric->privateDecrypt($crypt);

        $this->string($decrypt)->isEqualTo($string);
    }

}
