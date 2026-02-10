<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Entities;

interface ClientEntityInterface
{
    /**
     * Get the client's identifier.
     *
     * @return non-empty-string
     */
    public function getIdentifier(): string;

    /**
     * Get the client's name.
     */
    public function getName(): string;

    /**
     * Returns the registered redirect URI (as a string). Alternatively return
     * an indexed array of redirect URIs.
     *
     * @return string|string[]
     */
    public function getRedirectUri(): string|array;

    /**
     * Returns true if the client is confidential.
     */
    public function isConfidential(): bool;

    /*
     * Returns true if the client supports the given grant type.
     *
     * TODO: To be added in a future major release.
     */
    // public function supportsGrantType(string $grantType): bool;
}
