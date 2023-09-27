<?php

declare(strict_types=1);

namespace LeagueTests\Utils;

use Defuse\Crypto\Key;
use LeagueTests\Stubs\CryptTraitStub;
use PHPUnit\Framework\TestCase;

use function base64_encode;
use function random_bytes;

class CryptTraitTest extends TestCase
{
    protected CryptTraitStub $cryptStub;

    protected function setUp(): void
    {
        $this->cryptStub = new CryptTraitStub();
    }

    public function testEncryptDecryptWithPassword(): void
    {
        $this->cryptStub->setEncryptionKey(base64_encode(random_bytes(36)));

        $this->encryptDecrypt();
    }

    public function testEncryptDecryptWithKey(): void
    {
        $this->cryptStub->setEncryptionKey(Key::createNewRandomKey());

        $this->encryptDecrypt();
    }

    private function encryptDecrypt(): void
    {
        $payload = 'alex loves whisky';
        $encrypted = $this->cryptStub->doEncrypt($payload);
        $plainText = $this->cryptStub->doDecrypt($encrypted);

        self::assertNotEquals($payload, $encrypted);
        self::assertEquals($payload, $plainText);
    }
}
