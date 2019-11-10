<?php
/**
 * @author      Lukáš Unger <lookymsc@gmail.com>
 * @copyright   Copyright (c) Lukáš Unger
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\CodeChallengeVerifiers;

interface CodeChallengeVerifierInterface
{
    /**
     * Return code challenge method.
     *
     * @return string
     */
    public function getMethod();

    /**
     * Verify the code challenge.
     *
     * @param string $codeVerifier
     * @param string $codeChallenge
     *
     * @return bool
     */
    public function verifyCodeChallenge($codeVerifier, $codeChallenge);
}
