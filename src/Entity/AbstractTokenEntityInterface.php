<?php

namespace League\OAuth2\Server\Entity;


/**
 * Abstract token class
 */
interface AbstractTokenEntityInterface
{
    /**
     * Set session
     *
     * @param \League\OAuth2\Server\Entity\SessionEntity $session
     *
     * @return self
     */
    public function setSession(SessionEntity $session);

    /**
     * Set the expire time of the token
     *
     * @param integer $expireTime Unix time stamp
     *
     * @return self
     */
    public function setExpireTime($expireTime);

    /**
     * Return token expire time
     *
     * @return int
     */
    public function getExpireTime();

    /**
     * Is the token expired?
     *
     * @return bool
     */
    public function isExpired();

    /**
     * Set token ID
     *
     * @param string $id Token ID
     *
     * @return self
     */
    public function setId($id = null);

    /**
     * Get the token ID
     *
     * @return string
     */
    public function getId();

    /**
     * Associate a scope
     *
     * @param \League\OAuth2\Server\Entity\ScopeEntity $scope
     *
     * @return self
     */
    public function associateScope(ScopeEntity $scope);

    /**
     * Expire the token
     *
     * @return void
     */
    public function expire();

    /**
     * Save the token
     *
     * @return void
     */
    public function save();
}