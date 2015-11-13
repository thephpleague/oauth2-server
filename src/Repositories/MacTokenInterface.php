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

use League\OAuth2\Server\Repositories\RepositoryInterface;


/**
 * MacTokenInterface
 */
interface MacTokenInterface extends RepositoryInterface
{
    /**
     * Create a MAC key linked to an access token
     * @param  string $macKey
     * @param  string $accessToken
     * @return void
     */
    public function persistMacTokenEntity($macKey, $accessToken);

    /**
     * Get a MAC key by access token
     * @param  string $accessToken
     * @return string
     */
    public function getMacKeyByAccessTokenString($accessToken);
}
