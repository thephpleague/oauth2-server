<?php

namespace LeagueTests\Utils;

use League\OAuth2\Server\MessageEncryption;

class MessageEncryptionTest extends \PHPUnit_Framework_TestCase
{
    public function testEncryptDecrypt()
    {
        $encryption = new MessageEncryption(__DIR__ . '/Stubs/private.key', __DIR__ . '/Stubs/public.key');
        $payload = 'alex loves whisky';
        $encrypted = $encryption->encrypt($payload);
        $plainText = $encryption->decrypt($encrypted);

        $this->assertNotEquals($payload, $encrypted);
        $this->assertEquals($payload, $plainText);
    }

    /**
     * @expectedException \LogicException
     */
    public function testBadPrivateKey()
    {
        $encryption = new MessageEncryption(__DIR__ . '/Stubs/public.key', __DIR__ . '/Stubs/public.key');
        $encryption->encrypt('');
    }

    /**
     * @expectedException \LogicException
     */
    public function testBadPublicKey()
    {
        $encryption = new MessageEncryption(__DIR__ . '/Stubs/private.key', __DIR__ . '/Stubs/private.key');
        $encryption->decrypt('');
    }
}
