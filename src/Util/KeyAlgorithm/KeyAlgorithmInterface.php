<?php
/**
 * OAuth 2.0 Secure key interface.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\Util\KeyAlgorithm;

interface KeyAlgorithmInterface
{
    /**
     * Generate a new unique code.
     *
     * @param int $len Length of the generated code
     *
     * @return string
     */
    public function generate($len);
}
