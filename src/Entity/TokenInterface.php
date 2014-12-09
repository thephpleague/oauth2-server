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

/**
 * Abstract token class
 */
interface TokenInterface
{
    /**
     * Set session
     * @param  \League\OAuth2\Server\Entity\SessionInterface $session
     * @return self
     */
    public function setSession(SessionInterface $session);

    /**
     * Set the expire time of the token
     * @param  integer $expireTime Unix time stamp
     * @return self
     */
    public function setExpireTime($expireTime);

    /**
     * Return token expire time
     * @return int
     */
    public function getExpireTime();

    /**
     * Is the token expired?
     * @return bool
     */
    public function isExpired();

    /**
     * Set token ID
     * @param  string $id Token ID
     * @return self
     */
    public function setId($id = null);

    /**
     * Get the token ID
     * @return string
     */
    public function getId();

    /**
     * Associate a scope
     * @param  \League\OAuth2\Server\Entity\ScopeInterface $scope
     * @return self
     */
    public function associateScope(ScopeInterface $scope);

    /**
     * Returns the token as a string if the object is cast as a string
     * @return string
     */
    public function __toString();

    /**
     * Expire the token
     * @return void
     */
    public function expire();

    /**
     * Save the token
     * @return void
     */
    public function save();
}
