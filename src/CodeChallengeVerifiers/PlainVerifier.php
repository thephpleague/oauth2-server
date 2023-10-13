<?php

/**
 * @author      Lukáš Unger <lookymsc@gmail.com>
 * @copyright   Copyright (c) Lukáš Unger
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\CodeChallengeVerifiers;

use function hash_equals;

class PlainVerifier implements CodeChallengeVerifierInterface
{
    /**
     * Return code challenge method.
     */
    public function getMethod(): string
    {
        return 'plain';
    }

    /**
     * Verify the code challenge.
     */
    public function verifyCodeChallenge(string $codeVerifier, string $codeChallenge): bool
    {
        return hash_equals($codeVerifier, $codeChallenge);
    }
}
