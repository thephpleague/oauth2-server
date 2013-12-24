<?php
/**
 * OAuth 2.0 Client credentials grant
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Authorization;

trait GrantTrait {

    /**
     * Constructor
     * @return void
     */
    public function __construct()
    {
    }

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
            $scopeDetails = $this->server->getStorage('scope')->getScope(
                $scopeItem,
                $client->getId(),
                $this->getIdentifier()
            );

            if ($scopeDetails === false) {
                throw new ClientException(sprintf($this->server->getExceptionMessage('invalid_scope'), $scopeItem), 4);
            }

            $scope = new Scope($this->server->getStorage('scope'));
            $scope->setId($scopeDetails['id']);
            $scope->setName($scopeDetails['name']);

            $scopes[] = $scope;
        }

        return $scopes;
    }

}
