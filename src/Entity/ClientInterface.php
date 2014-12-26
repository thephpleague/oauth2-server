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
interface ClientInterface extends HydratableInterface
{
    /**
     * Return the client identifier
     * @return string
     */
    public function getId();

    /**
     * Return the client secret
     * @return string
     */
    public function getSecret();

    /**
     * Get the client name
     * @return string
     */
    public function getName();

    /**
     * Returnt the client redirect URI
     * @return string
     */
    public function getRedirectUri();
}
