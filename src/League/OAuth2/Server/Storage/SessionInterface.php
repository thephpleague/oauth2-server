<?php

/**
 * OAuth 2.0 Session storage interface
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

interface SessionInterface
{
    /**
     * Get a session
     *
     * Response:
     * <code>
     *
     * </code>
     *
     * @param  int $sessionId
     * @return array (As described above)
     */
    public function getSession($sessionId);

    /**
     * Get a session's scopes
     *
     * Response:
     * <code>
     *
     * </code>
     *
     * @param  int $sessionId
     * @return array (As described aboce)
     */
    public function getSessionScopes($sessionId);

    /**
     * Create a new session
     * @param  string $ownerType         Session owner's type (user, client)
     * @param  string $ownerId           Session owner's ID
     * @param  string $clientId          Client ID
     * @param  string $clientRedirectUri Client redirect URI (default = null)
     * @return int    Session ID
     */
    public function createSession($ownerType, $ownerId, $clientId, $clientRedirectUri = null);

    /**
     * Associate a scope with a session
     * @param  int        $sessionId
     * @param  int|string $scopeId    The scopes ID might be an integer or string
     * @return void
     */
    public function associateScope($sessionId, $scopeId);
}
