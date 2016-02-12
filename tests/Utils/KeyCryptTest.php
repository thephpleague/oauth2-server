<?php

namespace LeagueTests\Utils;

use League\OAuth2\Server\Utils\KeyCrypt;

class KeyCryptTest extends \PHPUnit_Framework_TestCase
{
    public function testEncryptDecrypt()
    {
        $payload = 'alex loves whisky';
        $encrypted = KeyCrypt::encrypt($payload, 'file://'.__DIR__.'/private.key');
        $plainText = KeyCrypt::decrypt($encrypted, 'file://'.__DIR__.'/public.key');

        $this->assertNotEquals($payload, $encrypted);
        $this->assertEquals($payload, $plainText);
    }

    /**
     * @expectedException \LogicException
     */
    public function testBadPrivateKey()
    {
        KeyCrypt::encrypt('', 'file://'.__DIR__.'/public.key');
    }

    /**
     * @expectedException \LogicException
     */
    public function testBadPublicKey()
    {
        KeyCrypt::decrypt('', 'file://'.__DIR__.'/private.key');
    }
}
