<?php
/**
 * @author      Sebastiano Degan <sebdeg87@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\RedirectUriValidators;

use League\Uri\Exceptions\SyntaxError;
use League\Uri\Uri;

class RedirectUriValidator implements RedirectUriValidatorInterface
{
    /**
     * @var array
     */
    private $allowedRedirectUris;

    /**
     * New validator instance for the given uri
     *
     * @param string|array $allowedRedirectUris
     */
    public function __construct($allowedRedirectUri)
    {
        if (\is_string($allowedRedirectUri)) {
            $this->allowedRedirectUris = [$allowedRedirectUri];
        } elseif (\is_array($allowedRedirectUri)) {
            $this->allowedRedirectUris = $allowedRedirectUri;
        } else {
            $this->allowedRedirectUris = [];
        }
    }

    /**
     * Validates the redirect uri.
     *
     * @param string $redirectUri
     *
     * @return bool Return true if valid, false otherwise
     */
    public function validateRedirectUri($redirectUri)
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
     *
     * @param string $redirectUri
     *
     * @return bool
     */
    private function isLoopbackUri($redirectUri)
    {
        try {
            $uri = Uri::createFromString($redirectUri);
        } catch (SyntaxError $e) {
            return false;
        }

        return $uri->getScheme() === 'http'
            && (\in_array($uri->getHost(), ['127.0.0.1', '[::1]'], true));
    }

    /**
     * Find an exact match among allowed uris
     *
     * @param string $redirectUri
     *
     * @return bool Return true if an exact match is found, false otherwise
     */
    private function matchExactUri($redirectUri)
    {
        return \in_array($redirectUri, $this->allowedRedirectUris, true);
    }

    /**
     * Find a match among allowed uris, allowing for different port numbers
     *
     * @param string $redirectUri
     *
     * @return bool Return true if a match is found, false otherwise
     */
    private function matchUriExcludingPort($redirectUri)
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
     *
     * @param string $url
     *
     * @return array
     */
    private function parseUrlAndRemovePort($url)
    {
        $uri = Uri::createFromString($url);

        return (string) $uri->withPort(null);
    }
}
