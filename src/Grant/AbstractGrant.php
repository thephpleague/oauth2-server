<?php
/**
 * OAuth 2.0 Abstract grant
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Exception;

/**
 * Abstract grant class
 */
abstract class AbstractGrant implements GrantTypeInterface
{
    /**
     * Grant identifier
     *
     * @var string
     */
    protected $identifier = '';

    /**
     * Response type
     *
     * @var string
     */
    protected $responseType;

    /**
     * Callback to authenticate a user's name and password
     *
     * @var callable
     */
    protected $callback;

    /**
     * AuthServer instance
     *
     * @var \League\OAuth2\Server\AuthorizationServer
     */
    protected $server;

    /**
     * Access token expires in override
     *
     * @var int
     */
    protected $accessTokenTTL;

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * {@inheritdoc}
     */
    public function setIdentifier($identifier)
    {
        $this->identifier = $identifier;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return $this->responseType;
    }

    /**
     * Get the TTL for an access token
     *
     * @return int The TTL
     */
    public function getAccessTokenTTL()
    {
        if ($this->accessTokenTTL) {
            return $this->accessTokenTTL;
        }

        return $this->server->getAccessTokenTTL();
    }

    /**
     * Override the default access token expire time
     *
     * @param int $accessTokenTTL
     *
     * @return self
     */
    public function setAccessTokenTTL($accessTokenTTL)
    {
        $this->accessTokenTTL = $accessTokenTTL;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthorizationServer(AuthorizationServer $server)
    {
        $this->server = $server;

        return $this;
    }

    /**
     * Given a list of scopes, validate them and return an array of Scope entities
     *
     * @param string                                    $scopeParam  A string of scopes (e.g. "profile email birthday")
     * @param \League\OAuth2\Server\Entity\ClientEntity $client      Client entity
     * @param string|null                               $redirectUri The redirect URI to return the user to
     *
     * @return \League\OAuth2\Server\Entity\ScopeEntity[]
     *
     * @throws \League\OAuth2\Server\Exception\InvalidScopeException If scope is invalid, or no scopes passed when required
     * @throws
     */
    public function validateScopes($scopeParam = '', ClientEntity $client, $redirectUri = null)
    {
        $scopesList = explode($this->server->getScopeDelimiter(), $scopeParam);

        for ($i = 0; $i < count($scopesList); $i++) {
            $scopesList[$i] = trim($scopesList[$i]);
            if ($scopesList[$i] === '') {
                unset($scopesList[$i]); // Remove any junk scopes
            }
        }

        if (
            $this->server->scopeParamRequired() === true
            && $this->server->getDefaultScope() === null
            && count($scopesList) === 0
        ) {
            throw new Exception\InvalidRequestException('scope');
        } elseif (count($scopesList) === 0 && $this->server->getDefaultScope() !== null) {
            if (is_array($this->server->getDefaultScope())) {
                $scopesList = $this->server->getDefaultScope();
            } else {
                $scopesList = [0 => $this->server->getDefaultScope()];
            }
        }

        $scopes = [];

        foreach ($scopesList as $scopeItem) {
            $scope = $this->server->getScopeStorage()->get(
                $scopeItem,
                $this->getIdentifier(),
                $client->getId()
            );

            if (($scope instanceof ScopeEntity) === false) {
                throw new Exception\InvalidScopeException($scopeItem, $redirectUri);
            }

            $scopes[$scope->getId()] = $scope;
        }

        return $scopes;
    }

    /**
     * Format the local scopes array
     *
     * @param  \League\OAuth2\Server\Entity\ScopeEntity[]
     *
     * @return array
     */
    protected function formatScopes($unformated = [])
    {
        $scopes = [];
        foreach ($unformated as $scope) {
            if ($scope instanceof ScopeEntity) {
                $scopes[$scope->getId()] = $scope;
            }
        }

        return $scopes;
    }
}
