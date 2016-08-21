<?php

namespace League\OAuth2\Server\TokenSigner;

interface TokenSignerInterface
{
    /**
     * @return \Lcobucci\JWT\Signer
     */
    public function getSigner();

    /**
     * @return mixed
     */
    public function getKey();
}
