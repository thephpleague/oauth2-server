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

use League\Uri\Exceptions\SyntaxError;
use League\Uri\Uri;

use function in_array;
use function is_string;

class RedirectUriValidator implements RedirectUriValidatorInterface
{
    /**
     * @var string[]
     */
    private array $allowedRedirectUris;

    /**
     * New validator instance for the given uri
     *
     * @param string[]|string $allowedRedirectUris
     */
    public function __construct(array|string $allowedRedirectUris)
    {
        if (is_string($allowedRedirectUris)) {
            $this->allowedRedirectUris = [$allowedRedirectUris];
        } else {
            $this->allowedRedirectUris = $allowedRedirectUris;
        }
    }

    /**
     * Validates the redirect uri.
     *
     * @return bool Return true if valid, false otherwise
     */
    public function validateRedirectUri(string $redirectUri): bool
    {
        if ($this->isLoopbackUri($redirectUri)) {
            return $this->matchUriExcludingPort($redirectUri);
        }

        return $this->matchExactUri($redirectUri);
    }

    /**
     * According to section 7.3 of rfc8252, loopback uris are:
     *   - "http://127.0.0.1:{port}/{path}" for IPv4
     *   - "http://[::1]:{port}/{path}" for IPv6
     */
    private function isLoopbackUri(string $redirectUri): bool
    {
        try {
            $uri = Uri::new($redirectUri);
        } catch (SyntaxError $e) {
            return false;
        }

        return $uri->getScheme() === 'http'
            && (in_array($uri->getHost(), ['127.0.0.1', '[::1]'], true));
    }

    /**
     * Find an exact match among allowed uris
     */
    private function matchExactUri(string $redirectUri): bool
    {
        return in_array($redirectUri, $this->allowedRedirectUris, true);
    }

    /**
     * Find a match among allowed uris, allowing for different port numbers
     */
    private function matchUriExcludingPort(string $redirectUri): bool
    {
        $parsedUrl = $this->parseUrlAndRemovePort($redirectUri);

        foreach ($this->allowedRedirectUris as $allowedRedirectUri) {
            if ($parsedUrl === $this->parseUrlAndRemovePort($allowedRedirectUri)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse an url like \parse_url, excluding the port
     */
    private function parseUrlAndRemovePort(string $url): string
    {
        $uri = Uri::new($url);

        return (string) $uri->withPort(null);
    }
}
