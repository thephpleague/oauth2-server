<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\AuthorizationValidators;

use League\OAuth2\Server\CryptKey;

interface PublicKeyAwareInterface
{
    /**
     * Set the public key
     *
     * @param CryptKey $key
     */
    public function setPublicKey(CryptKey $key);
}
