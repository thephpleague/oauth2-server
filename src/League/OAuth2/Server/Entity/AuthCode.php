<?php
/**
 * OAuth 2.0 Auth code entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
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
class AuthCode extends AbstractToken
{
    /**
     * {@inheritdoc}
     */
    public function getSession()
    {
        if ($this->session instanceof Session) {
            return $this->session;
        }

        $this->session = $this->server->getStorage('session')->getByAuthCode($this->token);
        return $this->session;
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes()
    {
        if ($this->scopes === null) {
            $this->scopes = $this->formatScopes(
                $this->server->getStorage('auth_code')->getScopes($this->getToken())
            );
        }

        return $this->scopes;
    }

    /**
     * {@inheritdoc}
     */
    public function save()
    {
        $this->server->getStorage('auth_code')->create(
            $this->getToken(),
            $this->getExpireTime(),
            $this->getSession()->getId()
        );

        // Associate the scope with the token
        foreach ($this->getScopes() as $scope) {
            $this->server->getStorage('auth_code')->associateScope($this->getToken(), $scope->getId());
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function expire()
    {
        $this->server->getStorage('auth_code')->delete($this->getToken());
    }
}
