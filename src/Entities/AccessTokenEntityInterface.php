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
     * Convert the access token to an encrypted access token.
     *
     * @return string
     */
    public function convertToEncryptedAccessToken();

    /**
     * Set the private key
     *
     * @param CryptKey $privateKey
     */
    public function setPrivateKey(CryptKey $privateKey);
}
