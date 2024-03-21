<?php

/**
 * @author      Sebastiano Degan <sebdeg87@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\RedirectUriValidators;

interface RedirectUriValidatorInterface
{
    /**
     * Validates the redirect uri.
     */
    public function validateRedirectUri(string $redirectUri): bool;
}
