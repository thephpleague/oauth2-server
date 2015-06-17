<?php
/**
 * OAuth 2.0 Client storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

use League\OAuth2\Server\Entity\AccessTokenEntity;

/**
 * Client storage interface
 */
interface UsersAccessTokenInterface extends StorageInterface
{
    /**
     * Validate a client
     *
     * @param AccessTokenEntity $accessToken     The access token
     * @param int $userId The user ID
     *
     * @return \League\OAuth2\Server\Entity\ClientEntity | null
     */
     public function create(AccessTokenEntity $accessToken, $userId);
}
