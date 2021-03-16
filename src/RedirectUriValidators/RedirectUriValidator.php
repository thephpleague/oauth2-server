<?php
/**
 * @author      Sebastiano Degan <sebdeg87@gmail.com>
 * @copyright   Copyright (c) Sebastiano Degan
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
        if ($this->isLoopbackAddress($parsedUrl)) {
            return $this->allowDifferentPort($parsedUrl);
        } else {
            return $this->matchExactUri($redirectUri);
        }
    }

    /**
     * Determine if the given url is a loopback url.
     *
     * @param array $parsedUri As returned by parseUrl
     *
     * @return bool
     */
    private function isLoopbackAddress(array $parsedUri)
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
     * @return array
     */
    private function parseUrl(string $url)
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
        } else {
            return [];
        }
    }
}
