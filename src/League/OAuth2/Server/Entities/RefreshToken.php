<?php

namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Storage\SessionStorageInterface;
use League\OAuth2\Server\Storage\RefreshTokenInterface;
use Symfony\Component\HttpFoundation\ParameterBag;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Exception\InvalidAccessTokenException;

class RefreshToken extends AbstractToken
{
    protected $accessToken;

    /**
     * __construct
     * @param RefreshTokenInterface $storage
     * @return self
     */
    public function __construct(RefreshTokenInterface $storage)
    {
        parent::__construct($storage);
    }

    /**
     * Associate an access token
     * @param AccessToken $accessToken
     * @return self
     */
    public function setAccessToken(AccessToken $accessToken)
    {
        $this->accessToken = $accessToken;
        return $this;
    }

    /**
     * Return access token
     * @return AccessToken
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * (@inheritdoc)
     */
    public function save()
    {
        $this->getStorage()->createAccessToken(
            $this->getToken(),
            $this->getExpireTime(),
            $this->getAccessToken()->getToken()
        );

        // Associate the scope with the token
        foreach ($this->getScopes() as $scope) {
            $this->getStorage()->associateScope($this->getToken(), $scope->getId());
        }
    }
}
