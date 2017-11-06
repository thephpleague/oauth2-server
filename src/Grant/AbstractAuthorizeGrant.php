<?php
/**
 * Abstract authorization grant.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Exception\OAuthServerException;

abstract class AbstractAuthorizeGrant extends AbstractGrant
{
    /**
     * @var string
     */
    protected $defaultScope = '';

    /**
     * @param string $uri
     * @param array  $params
     * @param string $queryDelimiter
     *
     * @return string
     */
    public function makeRedirectUri($uri, $params = [], $queryDelimiter = '?')
    {
        $uri .= (strstr($uri, $queryDelimiter) === false) ? $queryDelimiter : '&';

        return $uri . http_build_query($params);
    }

    /**
     * @param string $scope
     */
    public function setDefaultScope($scope)
    {
        $this->defaultScope = $scope;
    }

    /**
     * @param ScopeEntityInterface[] $requestedScopes
     * @param string $redirectUri
     *
     * @throws OAuthServerException
     */
    protected function checkScopesRequested($requestedScopes, $redirectUri = null)
    {
        if (empty($requestedScopes)) {
            throw OAuthServerException::invalidScope($redirectUri);
        }
    }
}
