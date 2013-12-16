<?php

namespace League\OAuth2\Server;

use OutOfBoundsException;
use League\OAuth2\Server\Storage\SessionStorageInterface;
use League\OAuth2\Server\Storage\AccessTokenStorageInterface;
use Symfony\Component\HttpFoundation\ParameterBag;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Exception\InvalidAccessTokenException;

class AccessToken
{
    /**
     * Access token ID
     * @var string
     */
    protected $id = null;

    /**
     * Access token storage
     * @var \League\OAuth2\Server\Storage\AccessTokenStorageInterface
     */
    protected $storage = null;

    /**
     * Session storage
     * @var \League\OAuth2\Server\Storage\SessionStorageInterface
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

    public function __construct(AccessTokenStorageInterface $storage)
    {
        $this->storage = $storage;
        $this->scopes = new ParameterBag();
    }

    public function setSession(Session $session)
    {
        $this->session = $session;
    }

    public function getSession()
    {
        return $this->session;
    }

    public function setSessionStorage(SessionStorageInterface $sessionStorage)
    {
        $this->sessionStorage = $sessionStorage;
    }

    public function getSessionStorage()
    {
        return $this->sessionStorage;
    }

    public function setTTL($ttl = 0)
    {
        $this->ttl = $ttl;
    }

    public function getTTL()
    {
        return $this->ttl;
    }

    public function setTimestamp($timestamp = 0)
    {
        $this->timestamp = $timestamp;
    }

    public function getTimestamp()
    {
        return $this->timestamp;
    }

    public function setId($id = null)
    {
        $this->id = ($id !== null) ? $id : SecureKey::make();
    }

    public function getId()
    {
        return $this->id;
    }

    public function associateScope($scope, $details = [])
    {
        if (!$this->scopes->has($scope)) {
            $this->scopes->set($scope, []);
        }

        return $this;
    }

    public function hasScope($scope)
    {
        return $this->scopes->has($scope);
    }

    public function getScopes()
    {
        return $this->scopes->all();
    }
}
