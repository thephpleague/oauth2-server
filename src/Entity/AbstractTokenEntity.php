<?php
/**
 * OAuth 2.0 Abstract token
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
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
abstract class AbstractTokenEntity
{
    /**
     * Access token ID
     * @var string
     */
    protected $token;

    /**
     * Associated session
     * @var \League\OAuth2\Server\SessionEntity
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
     * @var \League\OAuth2\Server\AbstractServer
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
     * @param \League\OAuth2\Server\SessionEntity $session
     * @return self
     */
    public function setSession(SessionEntity $session)
    {
        $this->session = $session;
        return $this;
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
        $this->token = ($token !== null) ? $token : SecureKey::generate();
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
     * @param \League\OAuth2\Server\Entity\ScopeEntity $scope
     * @return self
     */
    public function associateScope(ScopeEntity $scope)
    {
        if (!isset($this->scopes[$scope->getId()])) {
            $this->scopes[$scope->getId()] = $scope;
        }

        return $this;
    }

    /**
     * Format the local scopes array
     * @param  array $unformatted Array of \League\OAuth2\Server\Entity\Scope
     * @return array
     */
    protected function formatScopes($unformatted = [])
    {
        $scopes = [];
        foreach ($unformatted as $scope) {
            if ($scope instanceof ScopeEntity) {
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
