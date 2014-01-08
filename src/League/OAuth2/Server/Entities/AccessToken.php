<?php
/**
 * OAuth 2.0 Access token entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

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
        $this->server->getStorage('access_token')->createAccessToken(
            $this->getToken(),
            $this->getExpireTime(),
            $this->getSession()->getId()
        );

        // Associate the scope with the token
        foreach ($this->getScopes() as $scope) {
            $this->server->getStorage('access_token')->associateScope($this->getToken(), $scope->getId());
        }

        return $this;
    }
}
