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

use League\OAuth2\Server\CryptKeyInterface;

interface AccessTokenEntityInterface extends TokenInterface
{
    /**
     * Generate a string representation of the access token.
     */
    public function toString(): string;

    /**
     * Set the algorithm for signing the access token with the given private key
     * 
     * @see https://lcobucci-jwt.readthedocs.io/en/latest/supported-algorithms/
     * 
     * Symmetric - HS256, HS384, HS512, BLAKE2B
     * Asymmetric - ES256, ES384, ES512, RS256, RS384, RS512, EdDSA
     */
    public function setSigner(string $signerAlgorithm, CryptKeyInterface $privateKey): void;
}
