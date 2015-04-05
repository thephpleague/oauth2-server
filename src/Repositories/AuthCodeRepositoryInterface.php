<?php
/**
 * OAuth 2.0 Auth code storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\Interfaces\AuthCodeEntityInterface;

/**
 * Auth code storage interface
 */
interface AuthCodeRepositoryInterface extends RepositoryInterface
{
    /**
     * Get the auth code
     *
     * @param string $code
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\AuthCodeEntityInterface
     */
    public function get($code);

    /**
     * Create an auth code.
     *
     * @param string  $token       The token ID
     * @param integer $expireTime  Token expire time
     * @param integer $sessionId   Session identifier
     * @param string  $redirectUri Client redirect uri
     *
     * @return void
     */
    public function create($token, $expireTime, $sessionId, $redirectUri);

    /**
     * Delete an access token
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AuthCodeEntityInterface $token The access token to delete
     */
    public function delete(AuthCodeEntityInterface $token);
}
