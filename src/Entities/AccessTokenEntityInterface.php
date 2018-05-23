<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\CryptKey;

interface AccessTokenEntityInterface extends TokenInterface
{
    /**
     * Set a private key used to encrypt the access token.
     */
    public function setPrivateKey(CryptKey $privateKey);

    /**
     * Generate a string representation of the access token.
     */
    public function __toString();
}
