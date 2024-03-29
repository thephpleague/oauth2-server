<?php

declare(strict_types=1);

namespace LeagueTests\Stubs;

use Defuse\Crypto\Key;
use League\OAuth2\Server\CryptTrait;

use function base64_encode;
use function random_bytes;

class CryptTraitStub
{
    use CryptTrait;

    public function __construct()
    {
        $this->setEncryptionKey(base64_encode(random_bytes(36)));
    }

    public function getKey(): string|Key|null
    {
        return $this->encryptionKey;
    }

    public function doEncrypt(string $unencryptedData): string
    {
        return $this->encrypt($unencryptedData);
    }

    public function doDecrypt(string $encryptedData): string
    {
        return $this->decrypt($encryptedData);
    }
}
