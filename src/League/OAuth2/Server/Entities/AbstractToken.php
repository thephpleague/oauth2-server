<?php

namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Storage\SessionStorageInterface;
use Symfony\Component\HttpFoundation\ParameterBag;
use League\OAuth2\Server\Util\SecureKey;

abstract class AbstractToken
{
    /**
     * Access token ID
     * @var string
     */
    protected $token = null;

    /**
     * Access token storage
     * @var \League\OAuth2\Server\Storage\AccessTokenInterface
     */
    protected $storage = null;

    /**
     * Session storage
     * @var \League\OAuth2\Server\Storage\SessionInterface
     */
    protected $sessionStorage = null;

    /**
     * Associated session
     * @var \League\OAuth2\Server\Session
     */
    protected $session = null;

    /**
     * Session scopes
     * @var \Symfony\Component\HttpFoundation\ParameterBag
     */
    protected $scopes = null;

    /**
     * __construct
     * @param mixed $storage
     * @return self
     */
    public function __construct($storage)
    {
        $this->storage = $storage;
        $this->scopes = new ParameterBag();
        return $this;
    }

    /**
     * Get storage
     * @return AccessTokenInterface
     */
    public function getStorage()
    {
        return $this->storage;
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
        return $this->session;
    }

    /**
     * Set token TTL
     * @param integer $ttl TTL in seconds
     * @return self
     */
    public function setTTL($ttl = 0)
    {
        $this->ttl = $ttl;
        return $this;
    }

    /**
     * Get token TTL
     * @return integer
     */
    public function getTTL()
    {
        return $this->ttl;
    }

    /**
     * Set the creation timestamp
     * @param integer $timestamp Unix timestamp
     * @return self
     */
    public function setTimestamp($timestamp = 0)
    {
        $this->timestamp = $timestamp;
    }

    /**
     * Get access token creation timestamp
     * @return integer Unix timestamp
     */
    public function getTimestamp()
    {
        return $this->timestamp;
    }

    /**
     * Return creation timestamp + TTL
     * @return int
     */
    public function getExpireTime()
    {
        return $this->getTimestamp() + $this->getTTL();
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
     * Save the token to the database
     * @return self
     */
    abstract function save();
}
