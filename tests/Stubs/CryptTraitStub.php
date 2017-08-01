<?php

namespace LeagueTests\Stubs;

use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;

class CryptTraitStub
{
    use CryptTrait;

    public function __construct()
    {
        $this->setEncryptionKey(base64_encode(random_bytes(36)));
    }

    public function getKey()
    {
        return $this->encryptionKey;
    }

    public function doEncrypt($unencryptedData)
    {
        return $this->encrypt($unencryptedData);
    }

    public function doDecrypt($encryptedData)
    {
        return $this->decrypt($encryptedData);
    }
}
