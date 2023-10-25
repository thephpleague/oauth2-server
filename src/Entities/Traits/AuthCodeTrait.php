<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Entities\Traits;

trait AuthCodeTrait
{
    protected ?string $redirectUri = null;

    public function getRedirectUri(): string|null
    {
        return $this->redirectUri;
    }

    public function setRedirectUri(string $uri): void
    {
        $this->redirectUri = $uri;
    }
}
