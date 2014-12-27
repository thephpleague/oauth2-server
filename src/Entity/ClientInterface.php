<?php
/**
 * OAuth 2.0 Client entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

/**
 * Client entity interface
 */
interface ClientInterface
{
    /**
     * Return the client identifier
     * @return string
     */
    public function getId();

    /**
     * Set client identifier
     * @param  string                                       $id
     * @return \League\OAuth2\Server\Entity\ClientInterface
     */
    public function setId($id);

    /**
     * Return the client secret
     * @return string
     */
    public function getSecret();

    /**
     * Set client secret
     * @param $secret
     * @return self
     */
    public function setSecret($secret);

    /**
     * Get the client name
     * @return string
     */
    public function getName();

    /**
     * Set client name
     * @return self
     */
    public function setName($name);

    /**
     * Return the client redirect URI
     * @return string
     */
    public function getRedirectUri();

    /**
     * Set redirect URI
     * @return self
     */
    public function setRedirectUri($redirectUri);
}
