<?php

namespace LeagueTests\Utils;

use Defuse\Crypto\Key;
use LeagueTests\Stubs\CryptTraitStub;
use PHPUnit\Framework\TestCase;

class CryptTraitTest extends TestCase
{
    /**
     * @var \LeagueTests\Stubs\CryptTraitStub
     */
    protected $cryptStub;

    public function setUp()
    {
        $this->cryptStub = new CryptTraitStub;
    }

    public function testEncryptDecryptWithPassword()
    {
        $this->cryptStub->setEncryptionKey(base64_encode(random_bytes(36)));

        $payload = 'alex loves whisky';
        $encrypted = $this->cryptStub->doEncrypt($payload);
        $plainText = $this->cryptStub->doDecrypt($encrypted);

        $this->assertNotEquals($payload, $encrypted);
        $this->assertEquals($payload, $plainText);
    }

    public function testEncryptDecryptWithKey()
    {
        $this->cryptStub->setEncryptionKey(Key::createNewRandomKey());

        $payload = 'alex loves whisky';
        $encrypted = $this->cryptStub->doEncrypt($payload);
        $plainText = $this->cryptStub->doDecrypt($encrypted);

        $this->assertNotEquals($payload, $encrypted);
        $this->assertEquals($payload, $plainText);
    }
}
