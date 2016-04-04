<?php

namespace League\OAuth2\Server\Jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;

class AccessTokenConverter implements AccessTokenConverterInterface
{
    /**
     * @var string
     */
    private $privateKeyPath;
    /**
     * @var Builder
     */
    private $builder;

    /**
     * @param $privateKeyPath
     */
    public function __construct($privateKeyPath)
    {
        $this->builder = new Builder();
        $this->privateKeyPath = $privateKeyPath;
    }

    /**
     * Generate a JWT from the access token
     *
     * @param AccessTokenEntityInterface $accessTokenEntity
     *
     * @return Builder
     */
    public function convert(AccessTokenEntityInterface $accessTokenEntity)
    {
        return $this->builder
            ->setAudience($accessTokenEntity->getClient()->getIdentifier())
            ->setId($accessTokenEntity->getIdentifier(), true)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration($accessTokenEntity->getExpiryDateTime()->getTimestamp())
            ->setSubject($accessTokenEntity->getUserIdentifier())
            ->set('scopes', $accessTokenEntity->getScopes())
            ->sign(new Sha256(), new Key($this->privateKeyPath));
    }
}
