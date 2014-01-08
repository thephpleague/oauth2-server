<?php
/**
 * OAuth 2.0 Abstract token
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Storage\SessionStorageInterface;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Exception\ServerException;
use \League\OAuth2\Server\Authorization;
use \League\OAuth2\Server\Resource;
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
     * Session ID
     * @var string
     */
    protected $sessionId;

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
     * @param \League\OAuth2\Server\Authorization|\League\OAuth2\Server\Resource $server
     * @return self
     */
    public function __construct($server)
    {
        if (! $server instanceof Authorization && ! $server instanceof Resource) {
            throw new ServerException('No instance of Authorization or Resource server injected');
        }

        $this->server = $server;
        $this->scopes = new ParameterBag();
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

        if ($this->sessionId !== null) {
            $session = $this->server->getStorage('session')->getSession($this->sessionId);
        }

        throw new ServerException('No session ID set for this token');
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
     * @param \League\OAuth2\Server\Entities\Scope $scope
     * @return self
     */
    public function associateScope($scope)
    {
        if (!$this->scopes->has($scope->getId())) {
            $this->scopes->set($scope->getId(), $scope);
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
        return $this->scopes->has($scope);
    }

    /**
     * Return all associated scopes
     * @return ParameterBag
     */
    public function getScopes()
    {
        return $this->scopes;
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
