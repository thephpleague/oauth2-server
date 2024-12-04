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

trait ClientTrait
{
    protected string $name;

    /**
     * @var string|string[]
     */
    protected string|array $redirectUri;

    protected bool $isConfidential = false;

    /**
     * Get the client's name.
     *
     *
     * @codeCoverageIgnore
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Returns the registered redirect URI (as a string). Alternatively return
     * an indexed array of redirect URIs.
     *
     * @return string|string[]
     */
    public function getRedirectUri(): string|array
    {
        return $this->redirectUri;
    }

    /**
     * Returns true if the client is confidential.
     */
    public function isConfidential(): bool
    {
        return $this->isConfidential;
    }

    /**
     * Returns true if the client supports the given grant type.
     */
    public function supportsGrantType(string $grantType): bool
    {
        return true;
    }
}
