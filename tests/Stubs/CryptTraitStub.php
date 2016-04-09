<?php

namespace LeagueTests\Stubs;

use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;

class CryptTraitStub
{
    use CryptTrait;

    public function __construct()
    {
        $this->setPrivateKey(new CryptKey('file://' . __DIR__ . '/private.key'));
        $this->setPublicKey(new CryptKey('file://' . __DIR__ . '/public.key'));
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
