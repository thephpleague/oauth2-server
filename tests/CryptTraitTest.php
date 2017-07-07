<?php

namespace LeagueTests\Utils;

use League\OAuth2\Server\CryptKey;
use LeagueTests\Stubs\CryptTraitStub;

class CryptTraitTest extends \PHPUnit_Framework_TestCase
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
