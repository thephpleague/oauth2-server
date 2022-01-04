<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

use DateInterval;
use League\OAuth2\Server\Grant\GrantTypeInterface;

interface ClientEntityInterface
{
    /**
     * Get the client's identifier.
     *
     * @return string
     */
    public function getIdentifier();

    /**
     * Get the client's name.
     *
     * @return string
     */
    public function getName();

    /**
     * Returns the registered redirect URI (as a string).
     *
     * Alternatively return an indexed array of redirect URIs.
     *
     * @return string|string[]
     */
    public function getRedirectUri();

    /**
     * Returns true if the client is confidential.
     *
     * @return bool
     */
    public function isConfidential();

    /**
     * Returns the access token lifetime for this client and the given grant type. If this
     * client can not determine the desired lifetime, it returns null, indicating that the default
     * from the grant type should be used.
     *
     * @param GrantTypeInterface $grantType
     *
     * @return DateInterval|null
     */
    public function getAccessTokenLifeTime(GrantTypeInterface $grantType): ?DateInterval;

    /**
     * Returns the refresh token lifetime for this client and the given grant type. If this
     * client can not determine the desired lifetime, it returns null, indicating that the default
     * from the grant type should be used.
     *
     * @param GrantTypeInterface $grantType
     *
     * @return DateInterval|null
     */
    public function getRefreshTokenLifeTime(GrantTypeInterface $grantType): ?DateInterval;

    /**
     * Returns the auth code lifetime for this client and the given grant type. If this
     * client can not determine the desired lifetime, it returns null, indicating that the default
     * from the grant type should be used.
     *
     * @param GrantTypeInterface $grantType
     *
     * @return DateInterval|null
     */
    public function getAuthCodeLifeTime(GrantTypeInterface $grantType): ?DateInterval;
}
