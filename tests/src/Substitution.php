<?php
namespace Pephpit\Crypto\tests\units;

use Pephpit\Crypto\Substitution as TestedClass;
use atoum;

class Substitution extends atoum
{

    public function testGeneratePbox()
    {

        $substitution = new TestedClass('', array());
        $pbox = $substitution->generatePBox();

        $this->array($pbox)->hasSize(3);
        $this->array($pbox[0])->hasSize(30);

        $substitution = new TestedClass('', array());
        $pbox = $substitution->generatePBox(10, 1);

        $this->array($pbox)->hasSize(1);
        $this->array($pbox[0])->hasSize(10);
    }

    public function testCryptDecrypt()
    {

        $pbox = [
            [23, 16, 2, 20, 8, 7, 3, 1, 27, 26, 10, 0, 28, 4, 22, 6, 17, 21, 12, 5, 18, 14, 15, 25, 11, 13, 9, 24, 29, 19],
            [11, 20, 8, 10, 16, 14, 5, 21, 15, 28, 24, 17, 27, 7, 3, 4, 2, 29, 22, 26, 1, 12, 19, 25, 0, 9, 23, 18, 13, 6],
            [28, 11, 6, 2, 23, 27, 14, 1, 25, 26, 4, 16, 17, 10, 0, 12, 18, 15, 29, 19, 22, 7, 8, 13, 24, 9, 5, 3, 20, 21]
        ];


        // key shorter than pbox length
        $key = 'xcCLTuw1rvA!';
        $string = 'hdLo2gGU459fUy0ICXpFMX';

        $substitution = new TestedClass($key, $pbox);
        $crypt = $substitution->encrypt($string);

        $this->string($crypt)->isNotEmpty();

        $substitution = new TestedClass($key, $pbox);
        $decrypt = $substitution->decrypt($crypt);

        $this->string($decrypt)->isEqualTo($string);
    }

    public function testCryptDecryptOneDimension()
    {

        $pbox = [[9, 3, 0, 2, 6, 7, 1, 8, 4, 5]];

        // key longer than pbox length
        $key = 'xcCLTuw1rvA!';
        $string = 'hdLo2gGU45';

        $substitution = new TestedClass($key, $pbox);
        $crypt = $substitution->encrypt($string);

        $this->string($crypt)->isNotEmpty();

        $substitution = new TestedClass($key, $pbox);
        $decrypt = $substitution->decrypt($crypt);

        $this->string($decrypt)->isEqualTo($string);
    }

    public function testCryptDecryptOneDimension2()
    {

        $pbox = [[9, 3, 0, 2, 6, 7, 1, 8, 4, 5]];


        // key length equal pbox length
        $key = 'xcCLTuw1rv';
        $string = 'hdLo2gGU45';

        $substitution = new TestedClass($key, $pbox);
        $crypt = $substitution->encrypt($string);

        $this->string($crypt)->isNotEmpty();
    }

}
