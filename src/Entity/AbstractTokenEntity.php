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

use League\OAuth2\Server\AbstractServer;
use League\OAuth2\Server\Util\SecureKey;

/**
 * Abstract token class
 */
abstract class AbstractTokenEntity
{
    /**
     * Token identifier
     *
     * @var string
     */
    protected $id;

    /**
     * Associated session
     *
     * @var \League\OAuth2\Server\Entity\SessionEntity
     */
    protected $session;

    /**
     * Session scopes
     *
     * @var \League\OAuth2\Server\Entity\ScopeEntity[]
     */
    protected $scopes;

    /**
     * Token expire time
     *
     * @var int
     */
    protected $expireTime = 0;

    /**
     * Authorization or resource server
     *
     * @var \League\OAuth2\Server\AbstractServer
     */
    protected $server;

    /**
     * __construct
     *
     * @param \League\OAuth2\Server\AbstractServer $server
     *
     * @return self
     */
    public function __construct(AbstractServer $server)
    {
        $this->server = $server;

        return $this;
    }

    /**
     * Set session
     *
     * @param \League\OAuth2\Server\Entity\SessionEntity $session
     *
     * @return self
     */
    public function setSession(SessionEntity $session)
    {
        $this->session = $session;

        return $this;
    }

    /**
     * Set the expire time of the token
     *
     * @param integer $expireTime Unix time stamp
     *
     * @return self
     */
    public function setExpireTime($expireTime)
    {
        $this->expireTime = $expireTime;

        return $this;
    }

    /**
     * Return token expire time
     *
     * @return int
     */
    public function getExpireTime()
    {
        return $this->expireTime;
    }

    /**
     * Is the token expired?
     *
     * @return bool
     */
    public function isExpired()
    {
        return ((time() - $this->expireTime) > 0);
    }

    /**
     * Set token ID
     *
     * @param string $id Token ID
     *
     * @return self
     */
    public function setId($id = null)
    {
        $this->id = ($id !== null) ? $id : SecureKey::generate();

        return $this;
    }

    /**
     * Get the token ID
     *
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Associate a scope
     *
     * @param \League\OAuth2\Server\Entity\ScopeEntity $scope
     *
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
     *
     * @param  \League\OAuth2\Server\Entity\ScopeEntity[]
     *
     * @return array
     */
    protected function formatScopes($unformatted = [])
    {
        if (is_null($unformatted)) {
            return [];
        }

        $scopes = [];
        foreach ($unformatted as $scope) {
            if ($scope instanceof ScopeEntity) {
                $scopes[$scope->getId()] = $scope;
            }
        }

        return $scopes;
    }

    /**
     * Returns the token as a string if the object is cast as a string
     *
     * @return string
     */
    public function __toString()
    {
        if ($this->id === null) {
            return '';
        }

        return $this->id;
    }

    /**
     * Expire the token
     *
     * @return void
     */
    abstract public function expire();

    /**
     * Save the token
     *
     * @return void
     */
    abstract public function save();
}
