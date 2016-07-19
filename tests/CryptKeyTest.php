<?php

namespace LeagueTests\Utils;

use League\OAuth2\Server\CryptKey;

class CryptKeyTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException \LogicException
     */
    public function testNoFile()
    {
        new CryptKey('undefined file');
    }

    public function testKeyCreation()
    {
        $keyFile = __DIR__ . '/Stubs/public.key';
        $key = new CryptKey($keyFile, 'secret');

        $this->assertEquals('file://' . $keyFile, $key->getKeyPath());
        $this->assertEquals('secret', $key->getPassPhrase());
    }

    public function testKeyFileCreation()
    {
        $keyContent = file_get_contents(__DIR__ . '/Stubs/public.key');
        $key = new CryptKey($keyContent);

        $this->assertEquals(
            'file://' . sys_get_temp_dir() . '/' . sha1($keyContent) . '.key',
            $key->getKeyPath()
        );
    }
}
