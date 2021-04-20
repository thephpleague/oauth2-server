<?php
/**
 * @author      Sebastiano Degan <sebdeg87@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\RedirectUriValidators;

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
            $this->allowedRedirectUris = [ $allowedRedirectUri ];
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
        $parsedUrl = $this->parseUrlAndRemovePort($redirectUri);
        if ($this->isLoopbackUri($parsedUrl)) {
            return $this->matchUriExcludingPort($parsedUrl);
        }

        return $this->matchExactUri($redirectUri);
    }

    /**
     * According to section 7.3 of rfc8252, loopback uris are:
     *   - "http://127.0.0.1:{port}/{path}" for IPv4
     *   - "http://[::1]:{port}/{path}" for IPv6
     *
     * @param array $parsedUri As returned by parseUrlAndRemovePort
     *
     * @return bool
     */
    private function isLoopbackUri(array $parsedUri)
    {
        return $parsedUri['scheme'] === 'http'
            && (\in_array($parsedUri['host'], ['127.0.0.1', '[::1]'], true));
    }

    /**
     * Find an exact match among client uris
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
     * Find a match among client uris, allowing for different port numbers
     *
     * @param array $parsedUrl As returned by parseUrlAndRemovePort
     *
     * @return bool Return true if a match is found, false otherwise
     */
    private function matchUriExcludingPort(array $parsedUrl)
    {
        foreach ($this->allowedRedirectUris as $redirectUri) {
            if ($parsedUrl === $this->parseUrlAndRemovePort($redirectUri)) {
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
        $parsedUrl = \parse_url($url);
        unset($parsedUrl['port']);

        return $parsedUrl;
    }
}
