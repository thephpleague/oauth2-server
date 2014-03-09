<?php
/**
 * OAuth 2.0 Abstract token
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

use League\OAuth2\Server\Storage\SessionStorageInterface;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Exception\ServerException;
use League\OAuth2\Server\AbstractServer;
use Symfony\Component\HttpFoundation\ParameterBag;

/**
 * Abstract token class
 */
abstract class AbstractToken
{
    /**
     * Access token ID
     * @var string
     */
    protected $token;

    /**
     * Associated session
     * @var \League\OAuth2\Server\Session
     */
    protected $session;

    /**
     * Session scopes
     * @var \Symfony\Component\HttpFoundation\ParameterBag
     */
    protected $scopes;

    /**
     * Token expire time
     * @var int
     */
    protected $expireTime = 0;

    /**
     * Authorization or resource server
     * @var \League\OAuth2\Server\Authorization|\League\OAuth2\Server\Resource
     */
    protected $server;

    /**
     * __construct
     * @param \League\OAuth2\Server\AbstractServer $server
     * @return self
     */
    public function __construct(AbstractServer $server)
    {
        $this->server = $server;
        return $this;
    }

    /**
     * Set session
     * @param \League\OAuth2\Server\Session $session
     * @return self
     */
    public function setSession(Session $session)
    {
        $this->session = $session;
        return $this;
    }

    /**
     * Get session
     * @return \League\OAuth2\Server\Session
     */
    public function getSession()
    {
        if ($this->session instanceof Session) {
            return $this->session;
        }

        $this->session = $this->server->getStorage('session')->getByAccessToken($this->token);
        return $this->session;
    }

    /**
     * Set the expire time of the token
     * @param integer $expireTime Unix time stamp
     * @return self
     */
    public function setExpireTime($expireTime)
    {
        $this->expireTime = $expireTime;
        return $this;
    }

    /**
     * Return token expire time
     * @return int
     */
    public function getExpireTime()
    {
        return $this->expireTime;
    }

    /**
     * Set access token ID
     * @param string $token Token ID
     * @return self
     */
    public function setToken($token = null)
    {
        $this->token = ($token !== null) ? $token : SecureKey::make();
        return $this;
    }

    /**
     * Get the token ID
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * Associate a scope
     * @param \League\OAuth2\Server\Entity\Scope $scope
     * @return self
     */
    public function associateScope(Scope $scope)
    {
        if (!isset($this->scopes[$scope->getId()])) {
            $this->scopes[$scope->getId()] = $scope;
        }

        return $this;
    }

    /**
     * Check if access token has an associated scope
     * @param string $scope Scope to check
     * @return bool
     */
    public function hasScope($scope)
    {
        if ($this->scopes === null) {
            $this->getScopes();
        }

        return isset($this->scopes[$scope]);
    }

    /**
     * Return all scopes associated with the session
     * @return array Array of \League\OAuth2\Server\Entity\Scope
     */
    public function getScopes()
    {
        if ($this->scopes === null) {
            $this->scopes = $this->formatScopes(
                $this->server->getStorage('access_token')->getScopes($this->getToken())
            );
        }

        return $this->scopes;
    }

    /**
     * Format the local scopes array
     * @param  array $unformated Array of \League\OAuth2\Server\Entity\Scope
     * @return array
     */
    private function formatScopes($unformated = [])
    {
        $scopes = [];
        foreach ($unformated as $scope) {
            if ($scope instanceof Scope) {
                $scopes[$scope->getId()] = $scope;
            }
        }
        return $scopes;
    }

    /**
     * Expire the token
     * @return void
     */
    abstract public function expire();

    /**
     * Save the token
     * @return void
     */
    abstract public function save();
}
