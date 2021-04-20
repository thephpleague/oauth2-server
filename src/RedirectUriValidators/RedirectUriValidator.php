<?php
/**
 * @author      Sebastiano Degan <sebdeg87@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\RedirectUriValidators;

use League\OAuth2\Server\Entities\ClientEntityInterface;

class RedirectUriValidator implements RedirectUriValidatorInterface
{
    /**
     * @var ClientEntityInterface
     */
    private $client;

    /**
     * New validator instance for the given client
     *
     * @param ClientEntityInterface $client
     */
    public function __construct(ClientEntityInterface $client)
    {
        $this->client = $client;
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
        $parsedUrl = $this->parseUrl($redirectUri);
        if ($this->isLoopbackUri($parsedUrl)) {
            return $this->allowDifferentPort($parsedUrl);
        }

        return $this->matchExactUri($redirectUri);
    }

    /**
     * According to section 7.3 of rfc8252, loopback uris are:
     *   - "http://127.0.0.1:{port}/{path}" for IPv4
     *   - "http://[::1]:{port}/{path}" for IPv6
     *
     * @param array $parsedUri As returned by parseUrl
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
        return \in_array($redirectUri, $this->getClientRedirectUris(), true);
    }

    /**
     * Find a match among client uris, allowing for different port numbers
     *
     * @param array $parsedUrl As returned by parseUrl
     *
     * @return bool Return true if a match is found, false otherwise
     */
    private function allowDifferentPort(array $parsedUrl)
    {
        foreach ($this->getClientRedirectUris() as $clientRedirectUri) {
            if ($parsedUrl == $this->parseUrl($clientRedirectUri)) {
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
    private function parseUrl($url)
    {
        $parsedUrl = \parse_url($url);
        unset($parsedUrl['port']);

        return $parsedUrl;
    }

    /**
     * Retrieve allowed client redirect uris
     *
     * @return array
     */
    private function getClientRedirectUris()
    {
        $clientRedirectUri = $this->client->getRedirectUri();
        if (\is_string($clientRedirectUri)) {
            return [$clientRedirectUri];
        } elseif (\is_array($clientRedirectUri)) {
            return $clientRedirectUri;
        }

        return [];
    }
}
