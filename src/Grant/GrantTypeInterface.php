<?php
/**
 * OAuth 2.0 Grant type interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

/**
 * Grant type interface
 */
interface GrantTypeInterface
{
    /**
     * Complete the grant flow
     * @return array
     */
    public function completeFlow();
}
