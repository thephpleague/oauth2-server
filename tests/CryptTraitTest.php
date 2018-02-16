<?php

namespace LeagueTests\Utils;

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

    public function testEncryptDecrypt()
    {
        $payload = 'alex loves whisky';
        $encrypted = $this->cryptStub->doEncrypt($payload);
        $plainText = $this->cryptStub->doDecrypt($encrypted);

        $this->assertNotEquals($payload, $encrypted);
        $this->assertEquals($payload, $plainText);
    }
}
