<?php
/**
 * OAuth 2.0 Access token entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

use League\OAuth2\Server\Storage\SessionStorageInterface;
use League\OAuth2\Server\Storage\AccessTokenInterface;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Exception\InvalidAccessTokenException;
use Symfony\Component\HttpFoundation\ParameterBag;

/**
 * Access token entity class
 */
class AccessToken extends AbstractToken
{
    /**
     * {@inheritdoc}
     */
    public function save()
    {
        $this->server->getStorage('access_token')->create(
            $this->getToken(),
            $this->getExpireTime(),
            $this->getSession()->getId()
        );

        // Associate the scope with the token
        foreach ($this->getScopes() as $scope) {
            $this->server->getStorage('access_token')->associateScope($this, $scope);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function expire()
    {
        $this->server->getStorage('access_token')->delete($this);
    }
}
