<?php
/**
 * OAuth 2.0 Session storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

use League\OAuth2\Server\Entity\AccessTokenInterface as AccessTokenEntityInterface;
use League\OAuth2\Server\Entity\AuthCodeInterface as AuthCodeEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;
use League\OAuth2\Server\Entity\SessionInterface as SessionEntityInterface;

/**
 * Session storage interface
 */
interface SessionInterface extends StorageInterface
{
    /**
     * Get a session from an access token
     *
     * @param \League\OAuth2\Server\Entity\AccessTokenInterface $accessToken The access token
     *
     * @return \League\OAuth2\Server\Entity\SessionInterface
     */
    public function getByAccessToken(AccessTokenEntityInterface $accessToken);

    /**
     * Get a session from an auth code
     *
     * @param \League\OAuth2\Server\Entity\AuthCodeInterface $authCode The auth code
     *
     * @return \League\OAuth2\Server\Entity\SessionInterface
     */
    public function getByAuthCode(AuthCodeEntityInterface $authCode);

    /**
     * Get a session's scopes
     * @param SessionEntityInterface $session
     * @internal param $ \League\OAuth2\Server\Entity\SessionEntity
     * @return array Array of \League\OAuth2\Server\Entity\ScopeInterface
     */
    public function getScopes(SessionEntityInterface $session);

    /**
     * Create a new session
     *
     * @param string $ownerType         Session owner's type (user, client)
     * @param string $ownerId           Session owner's ID
     * @param string $clientId          Client ID
     * @param string $clientRedirectUri Client redirect URI (default = null)
     *
     * @return integer The session's ID
     */
    public function create($ownerType, $ownerId, $clientId, $clientRedirectUri = null);

    /**
     * Associate a scope with a session
     * @param SessionEntityInterface $session The session
     * @param \League\OAuth2\Server\Entity\ScopeInterface $scope The scope
     * @return void
     */
    public function associateScope(SessionEntityInterface $session, ScopeEntityInterface $scope);
}
