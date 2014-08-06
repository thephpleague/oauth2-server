<?php
/**
 * OAuth 2.0 Token Type Interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\TokenType;

interface TokenTypeInterface
{
    /**
     * Generate a response
     * @return array
     */
    public function generateResponse();
}
