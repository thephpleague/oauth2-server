<?php
/**
 * OAuth 2.0 Abstract Server
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use League\Event\Emitter;
use League\OAuth2\Server\Storage\AccessTokenInterface;
use League\OAuth2\Server\Storage\AuthCodeInterface;
use League\OAuth2\Server\Storage\ClientInterface;
use League\OAuth2\Server\Storage\MacTokenInterface;
use League\OAuth2\Server\Storage\RefreshTokenInterface;
use League\OAuth2\Server\Storage\ScopeInterface;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\TokenType\TokenTypeInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * OAuth 2.0 Resource Server
 */
abstract class AbstractServer
{
    /**
     * The request object
     *
     * @var \Symfony\Component\HttpFoundation\Request
     */
    protected $request;

    /**
     * Session storage
     *
     * @var \League\OAuth2\Server\Storage\SessionInterface
     */
    protected $sessionStorage;

    /**
     * Access token storage
     *
     * @var \League\OAuth2\Server\Storage\AccessTokenInterface
     */
    protected $accessTokenStorage;

    /**
     * Refresh token storage
     *
     * @var \League\OAuth2\Server\Storage\RefreshTokenInterface
     */
    protected $refreshTokenStorage;

    /**
     * Auth code storage
     *
     * @var \League\OAuth2\Server\Storage\AuthCodeInterface
     */
    protected $authCodeStorage;

    /**
     * Scope storage
     *
     * @var \League\OAuth2\Server\Storage\ScopeInterface
     */
    protected $scopeStorage;

    /**
     * Client storage
     *
     * @var \League\OAuth2\Server\Storage\ClientInterface
     */
    protected $clientStorage;

    /**
     * @var \League\OAuth2\Server\Storage\MacTokenInterface
     */
    protected $macStorage;

    /**
     * Token type
     *
     * @var \League\OAuth2\Server\TokenType\TokenTypeInterface
     */
    protected $tokenType;

    /**
     * Event emitter
     *
     * @var \League\Event\Emitter
     */
    protected $eventEmitter;

    /**
     * Abstract server constructor
     */
    public function __construct()
    {
        $this->setEventEmitter();
    }

    /**
     * Set an event emitter
     *
     * @param object $emitter Event emitter object
     */
    public function setEventEmitter($emitter = null)
    {
        if ($emitter === null) {
            $this->eventEmitter = new Emitter();
        } else {
            $this->eventEmitter = $emitter;
        }
    }

    /**
     * Add an event listener to the event emitter
     *
     * @param string   $eventName Event name
     * @param callable $listener  Callable function or method
     * @param int      $priority  Priority of event listener
     */
    public function addEventListener($eventName, callable $listener, $priority = Emitter::P_NORMAL)
    {
        $this->eventEmitter->addListener($eventName, $listener, $priority);
    }

    /**
     * Returns the event emitter
     *
     * @return \League\Event\Emitter
     */
    public function getEventEmitter()
    {
        return $this->eventEmitter;
    }

    /**
     * Sets the Request Object
     *
     * @param \Symfony\Component\HttpFoundation\Request The Request Object
     *
     * @return self
     */
    public function setRequest($request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Gets the Request object. It will create one from the globals if one is not set.
     *
     * @return \Symfony\Component\HttpFoundation\Request
     */
    public function getRequest()
    {
        if ($this->request === null) {
            $this->request = Request::createFromGlobals();
        }

        return $this->request;
    }

    /**
     * Set the client storage
     *
     * @param \League\OAuth2\Server\Storage\ClientInterface $storage
     *
     * @return self
     */
    public function setClientStorage(ClientInterface $storage)
    {
        $storage->setServer($this);
        $this->clientStorage = $storage;

        return $this;
    }

    /**
     * Set the session storage
     *
     * @param \League\OAuth2\Server\Storage\SessionInterface $storage
     *
     * @return self
     */
    public function setSessionStorage(SessionInterface $storage)
    {
        $storage->setServer($this);
        $this->sessionStorage = $storage;

        return $this;
    }

    /**
     * Set the access token storage
     *
     * @param \League\OAuth2\Server\Storage\AccessTokenInterface $storage
     *
     * @return self
     */
    public function setAccessTokenStorage(AccessTokenInterface $storage)
    {
        $storage->setServer($this);
        $this->accessTokenStorage = $storage;

        return $this;
    }

    /**
     * Set the refresh token storage
     *
     * @param \League\OAuth2\Server\Storage\RefreshTokenInterface $storage
     *
     * @return self
     */
    public function setRefreshTokenStorage(RefreshTokenInterface $storage)
    {
        $storage->setServer($this);
        $this->refreshTokenStorage = $storage;

        return $this;
    }

    /**
     * Set the auth code storage
     *
     * @param \League\OAuth2\Server\Storage\AuthCodeInterface $storage
     *
     * @return self
     */
    public function setAuthCodeStorage(AuthCodeInterface $storage)
    {
        $storage->setServer($this);
        $this->authCodeStorage = $storage;

        return $this;
    }

    /**
     * Set the scope storage
     *
     * @param \League\OAuth2\Server\Storage\ScopeInterface $storage
     *
     * @return self
     */
    public function setScopeStorage(ScopeInterface $storage)
    {
        $storage->setServer($this);
        $this->scopeStorage = $storage;

        return $this;
    }

    /**
     * Return the client storage
     *
     * @return \League\OAuth2\Server\Storage\ClientInterface
     */
    public function getClientStorage()
    {
        return $this->clientStorage;
    }

    /**
     * Return the scope storage
     *
     * @return \League\OAuth2\Server\Storage\ScopeInterface
     */
    public function getScopeStorage()
    {
        return $this->scopeStorage;
    }

    /**
     * Return the session storage
     *
     * @return \League\OAuth2\Server\Storage\SessionInterface
     */
    public function getSessionStorage()
    {
        return $this->sessionStorage;
    }

    /**
     * Return the refresh token storage
     *
     * @return \League\OAuth2\Server\Storage\RefreshTokenInterface
     */
    public function getRefreshTokenStorage()
    {
        return $this->refreshTokenStorage;
    }

    /**
     * Return the access token storage
     *
     * @return \League\OAuth2\Server\Storage\AccessTokenInterface
     */
    public function getAccessTokenStorage()
    {
        return $this->accessTokenStorage;
    }

    /**
     * Return the auth code storage
     *
     * @return \League\OAuth2\Server\Storage\AuthCodeInterface
     */
    public function getAuthCodeStorage()
    {
        return $this->authCodeStorage;
    }

    /**
     * Set the access token type
     *
     * @param TokenTypeInterface $tokenType The token type
     *
     * @return void
     */
    public function setTokenType(TokenTypeInterface $tokenType)
    {
        $tokenType->setServer($this);
        $this->tokenType = $tokenType;
    }

    /**
     * Get the access token type
     *
     * @return TokenTypeInterface
     */
    public function getTokenType()
    {
        return $this->tokenType;
    }

    /**
     * @return MacTokenInterface
     */
    public function getMacStorage()
    {
        return $this->macStorage;
    }

    /**
     * @param MacTokenInterface $macStorage
     */
    public function setMacStorage(MacTokenInterface $macStorage)
    {
        $this->macStorage = $macStorage;
    }
}
