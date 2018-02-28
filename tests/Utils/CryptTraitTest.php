<?php

namespace LeagueTests\Utils;

use Defuse\Crypto\Key;
use LeagueTests\Stubs\CryptTraitStub;
use PHPUnit\Framework\TestCase;

class CryptTraitTest extends TestCase
{
    public function testEncryptDecryptWithPassword()
    {
        $cryptStub = new CryptTraitStub();
        $cryptStub->setEncryptionKey(base64_encode(random_bytes(36)));

        return $this->encryptDecrypt($cryptStub);
    }

    public function testEncryptDecryptWithKey()
    {
        $cryptStub = new CryptTraitStub();
        $cryptStub->setEncryptionKey(Key::createNewRandomKey());

        return $this->encryptDecrypt($cryptStub);
    }

    protected function encryptDecrypt(CryptTraitStub $cryptStub) {

        $payload = 'alex loves whisky';
        $encrypted = $cryptStub->doEncrypt($payload);
        $plainText = $cryptStub->doDecrypt($encrypted);

        $this->assertNotEquals($payload, $encrypted);
        $this->assertEquals($payload, $plainText);
    }
}
