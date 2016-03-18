<?php

namespace LeagueTests\Utils;

use LeagueTests\Stubs\CryptTraitStub;

class CryptTraitTest extends \PHPUnit_Framework_TestCase
{
    /**
     * CryptTrait stub
     */
    protected $cryptStub;

    public function setUp()
    {
        $this->cryptStub = new CryptTraitStub;
    }

    public function testEncryptDecrypt()
    {
        $payload = 'alex loves whisky';
        $encrypted = $this->cryptStub->doEncrypt($payload);
        $plainText = $this->cryptStub->doDecrypt($encrypted);

        $this->assertNotEquals($payload, $encrypted);
        $this->assertEquals($payload, $plainText);
    }

    /**
     * @expectedException \LogicException
     */
    public function testBadPrivateKey()
    {
        $this->cryptStub->setPrivateKeyPath(__DIR__ . '/Stubs/public.key');
        $this->cryptStub->doEncrypt('');
    }

    /**
     * @expectedException \LogicException
     */
    public function testBadPublicKey()
    {
        $this->cryptStub->setPublicKeyPath(__DIR__ . '/Stubs/private.key');
        $this->cryptStub->doDecrypt('');
    }
}
