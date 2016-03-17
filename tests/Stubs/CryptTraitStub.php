<?php

namespace LeagueTests\Stubs;

use League\OAuth2\Server\CryptTrait;

class CryptTraitStub
{
    use CryptTrait;

    public function __construct()
    {
        $this->setPrivateKeyPath('file://' . __DIR__ . '/private.key');
        $this->setPublicKeyPath('file://' . __DIR__ . '/public.key');
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
