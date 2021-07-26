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
     * @param string|array $allowedRedirectUri
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
        $this->allowedRedirectUris = \array_filter($this->allowedRedirectUris, [__CLASS__, 'isValidRedirectUrl']);
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
        if (!self::isValidRedirectUrl($redirectUri)) {
            return false;
        }

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
        $parsedUrl = \parse_url($redirectUri);

        return ($parsedUrl['scheme'] ?? '') === 'http'
            && (\in_array(($parsedUrl['host'] ?? ''), ['127.0.0.1', '[::1]'], true));
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
        $parsedUrl = \parse_url($url);
        unset($parsedUrl['port']);

        return $parsedUrl;
    }

    /**
     * Checking that the URL is the correct URI or URN
     *
     * @param string $url
     *
     * @return bool
     */
    private static function isValidRedirectUrl($url)
    {
        $parsedUrl = \parse_url($url);

        if ($parsedUrl === false) {
            return false; // obviously invalid url
        }

        /**
         * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
         *
         * The redirection endpoint URI
         * - MUST be an absolute URI as defined by [RFC3986] Section 4.3.
         * - MAY include an "application/x-www-form-urlencoded" formatted (per Appendix B) query
         *   component ([RFC3986] Section 3.4), which MUST be retained when adding
         *   additional query parameters.
         * - MUST NOT include a fragment component.
         *
         * @see https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
         * absolute-URI  = scheme ":" hier-part [ "?" query ]
         */

        if (empty($parsedUrl['scheme']) || !empty($parsedUrl['fragment'])) {
            return false;
        }

        if (\in_array(\strtolower($parsedUrl['scheme']), ['http', 'https'], true)) {
            return \filter_var($url, FILTER_VALIDATE_URL) !== false;
        }

        return !empty($parsedUrl['host']) || !empty($parsedUrl['path']);
    }
}
