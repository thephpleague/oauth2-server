<?php
/**
 * OAuth 2.0 Abstract grant
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Authorization;
use League\OAuth2\Server\Entities\Scope;

/**
 * Abstract grant class
 */
abstract class AbstractGrant implements GrantTypeInterface
{
    /**
     * Grant identifier
     * @var string
     */
    protected $identifier = '';

    /**
     * Response type
     * @var string
     */
    protected $responseType;

    /**
     * Callback to authenticate a user's name and password
     * @var function
     */
    protected $callback;

    /**
     * AuthServer instance
     * @var AuthServer
     */
    protected $server;

    /**
     * Access token expires in override
     * @var int
     */
    protected $accessTokenTTL;

    /**
     * Return the identifier
     * @return string
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * Return the identifier
     * @param string $identifier
     * @return self
     */
    public function setIdentifier($identifier)
    {
        $this->identifier = $identifier;
        return $this;
    }

    /**
     * Return the response type
     * @return string
     */
    public function getResponseType()
    {
        return $this->responseType;
    }

    /**
     * Override the default access token expire time
     * @param int $accessTokenTTL
     * @return self
     */
    public function setAccessTokenTTL($accessTokenTTL)
    {
        $this->accessTokenTTL = $accessTokenTTL;
        return $this;
    }

    /**
     * Inject the authorization server into the grant
     * @param Authorization $server The authorization server instance
     * @return  self
     */
    public function setAuthorizationServer(Authorization $server)
    {
        $this->server = $server;
        return $this;
    }

    /**
     * Given a list of scopes, validate them and return an arrary of Scope entities
     * @param string $scopeParam A string of scopes (e.g. "profile email birthday")
     * @return array
     * @throws ClientException If scope is invalid, or no scopes passed when required
     */
    public function validateScopes($scopeParam = '')
    {
        $scopesList = explode($this->server->getScopeDelimeter(), $scopeParam);

        for ($i = 0; $i < count($scopesList); $i++) {
            $scopesList[$i] = trim($scopesList[$i]);
            if ($scopesList[$i] === '') unset($scopesList[$i]); // Remove any junk scopes
        }

        if (
            $this->server->scopeParamRequired() === true &&
            $this->server->getDefaultScope() === null &&
            count($scopesList) === 0
        ) {
            throw new ClientException(sprintf($this->server->getExceptionMessage('invalid_request'), 'scope'), 0);
        } elseif (count($scopesList) === 0 && $this->server->getDefaultScope() !== null) {
            if (is_array($this->server->getDefaultScope())) {
                $scopesList = $this->server->getDefaultScope();
            } else {
                $scopesList = [0 => $this->server->getDefaultScope()];
            }
        }

        $scopes = [];

        foreach ($scopesList as $scopeItem) {
            $scope = $this->server->getStorage('scope')->get(
                $scopeItem,
                $this->getIdentifier()
            );

            if (($scope instanceof Scope) === false) {
                throw new ClientException(sprintf($this->server->getExceptionMessage('invalid_scope'), $scopeItem), 4);
            }

            $scopes[$scope->getId()] = $scope;
        }

        return $scopes;
    }

    /**
     * Format the local scopes array
     * @param  array $unformated Array of Array of \League\OAuth2\Server\Entities\Scope
     * @return array
     */
    protected function formatScopes($unformated = [])
    {
        $scopes = [];
        foreach ($unformated as $scope) {
            if ($scope instanceof Scope) {
                $scopes[$scope->getId()] = $scope;
            }
        }
        return $scopes;
    }

    /**
     * Complete the grant flow
     *
     * Example response:
     * <pre>
     *  array(
     *      'access_token'  =>  (string),   // The access token
     *      'refresh_token' =>  (string),   // The refresh token (only set if the refresh token grant is enabled)
     *      'token_type'    =>  'bearer',   // Almost always "bearer" (exceptions: JWT, SAML)
     *      'expires'       =>  (int),      // The timestamp of when the access token will expire
     *      'expires_in'    =>  (int)       // The number of seconds before the access token will expire
     *  )
     * </pre>
     *
     * @return array                   An array of parameters to be passed back to the client
     */
    abstract public function completeFlow();

}
