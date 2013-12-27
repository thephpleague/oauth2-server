<?php

namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Storage\SessionStorageInterface;
use League\OAuth2\Server\Storage\AccessTokenInterface;
use Symfony\Component\HttpFoundation\ParameterBag;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Exception\InvalidAccessTokenException;

class AccessToken extends AbstractToken
{
    /**
     * __construct
     * @param AccessTokenInterface $storage
     * @return self
     */
    public function __construct(AccessTokenInterface $storage)
    {
        parent::__construct($storage);
    }

    public function save()
    {
        $this->getStorage()->createAccessToken(
            $this->getId(),
            $this->getExpireTime(),
            $this->getSession()->getId()
        );

        // Associate the scope with the token
        foreach ($this->getScopes() as $scope) {
            $this->getStorage()->associateScope($this->getId(), $scope->getId());
        }

        return $this;
    }
}
