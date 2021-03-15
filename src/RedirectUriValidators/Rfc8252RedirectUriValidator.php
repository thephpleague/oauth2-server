<?php


namespace League\OAuth2\Server\RedirectUriValidators;


use League\OAuth2\Server\Entities\ClientEntityInterface;

class Rfc8252RedirectUriValidator
{

    private $client;

    public function __construct(ClientEntityInterface $client) {
        $this->client = $client;
    }

    public function validateRedirectUri(string $redirectUri) {
        $parsedUrl = $this->parseUrl($redirectUri);
        if ($this->isLoopbackAddress($parsedUrl)) {
            return $this->allowDifferentPort($parsedUrl);
        } else {
            return $this->matchFullUri($redirectUri);
        }
    }

    private function isLoopbackAddress(array $parsedUri) {
        return $parsedUri['scheme'] === 'http'
            && (\in_array($parsedUri['host'], ['127.0.0.1', '[::1]'], true));
    }

    private function matchFullUri(string $redirectUri) {
        return \in_array($redirectUri, $this->getClientRedirectUris(), true);
    }

    private function allowDifferentPort(array $parsedUrl) {
       foreach ($this->getClientRedirectUris() as $clientRedirectUri) {
            if ($parsedUrl == $this->parseUrl($clientRedirectUri)) {
                return true;
            }
       }
       return false;
    }

    private function parseUrl(string $url) {
        $parsedUrl = parse_url($url);
        $parsedUrl['port'] = 80;

        return $parsedUrl;
    }

    private function getClientRedirectUris() {
        $clientRedirectUri = $this->client->getRedirectUri();
        if (\is_string($clientRedirectUri)) {
            return [ $clientRedirectUri ];
        } else if (\is_array($clientRedirectUri)) {
            return $clientRedirectUri;
        } else {
            return [];
        }
    }

}
