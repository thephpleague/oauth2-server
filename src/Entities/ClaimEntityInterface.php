<?php
/**
 * @author      Sebastian Kroczek <me@xbug.de>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

interface ClaimEntityInterface
{
    /**
     * Get the claim's name.
     *
     * @return string
     */
    public function getName();

    /**
     * Get the claim's value
     *
     * @return mixed
     */
    public function getValue();
}
