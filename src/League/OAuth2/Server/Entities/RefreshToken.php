<?php
/**
 * OAuth 2.0 Refresh token entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Storage\SessionStorageInterface;
use League\OAuth2\Server\Storage\RefreshTokenInterface;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Exception\InvalidAccessTokenException;
use Symfony\Component\HttpFoundation\ParameterBag;

/**
 * Refresh token entity class
 */
class RefreshToken extends AbstractToken
{
    /**
     * Access token associated to refresh token
     * @var \League\OAuth2\Server\Entities\AccessToken
     */
    protected $accessToken;

    /**
     * Associate an access token
     * @param \League\OAuth2\Server\Entities\AccessToken $accessToken
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
     * {@inheritdoc}
     */
    public function save()
    {
        $this->server->getStorage('refresh_token')->createAccessToken(
            $this->getToken(),
            $this->getExpireTime(),
            $this->getAccessToken()->getToken()
        );

        // Associate the scope with the token
        foreach ($this->getScopes() as $scope) {
            $this->server->getStorage('refresh_token')->associateScope($this->getToken(), $scope->getId());
        }
    }
}
