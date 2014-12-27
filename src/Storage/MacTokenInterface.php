<?php
/**
 * OAuth 2.0 MAC Token Interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Storage;


/**
 * MacTokenInterface
 */
interface MacTokenInterface extends StorageInterface
{
    /**
     * Create a MAC key linked to an access token
     * @param  string $macKey
     * @param  string $accessToken
     * @return void
     */
    public function create($macKey, $accessToken);

    /**
     * Get a MAC key by access token
     * @param  string $accessToken
     * @return string
     */
    public function getByAccessToken($accessToken);
}
