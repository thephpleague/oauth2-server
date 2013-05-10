<?php
/**
 * OAuth 2.0 Refresh token grant
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Request;
use League\OAuth2\Server\Authorization;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Storage\ClientInterface;
use League\OAuth2\Server\Storage\ScopeInterface;

/**
 * Referesh token grant
 */
class RefreshToken implements GrantTypeInterface {

    /**
     * Grant identifier
     * @var string
     */
    protected $identifier = 'refresh_token';

    /**
     * Response type
     * @var string
     */
    protected $responseType = null;

    /**
     * AuthServer instance
     * @var AuthServer
     */
    protected $authServer = null;

    /**
     * Access token expires in override
     * @var int
     */
    protected $accessTokenTTL = null;

    /**
     * Refresh token TTL
     * @var integer
     */
    protected $refreshTokenTTL = 604800;

    /**
     * Rotate refresh tokens
     * @var boolean
     */
    protected $rotateRefreshTokens = false;

    /**
     * Constructor
     * @param Authorization $authServer Authorization server instance
     * @return void
     */
    public function __construct(Authorization $authServer)
    {
        $this->authServer = $authServer;
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
     * @return void
     */
    public function setAccessTokenTTL($accessTokenTTL)
    {
        $this->accessTokenTTL = $accessTokenTTL;
    }

    /**
     * Set the TTL of the refresh token
     * @param int $refreshTokenTTL
     * @return void
     */
    public function setRefreshTokenTTL($refreshTokenTTL)
    {
        $this->refreshTokenTTL = $refreshTokenTTL;
    }

    /**
     * Get the TTL of the refresh token
     * @return int
     */
    public function getRefreshTokenTTL()
    {
        return $this->refreshTokenTTL;
    }

    /**
     * When a new access is token, expire the refresh token used and issue a new one.
     * @param  boolean $rotateRefreshTokens Set to true to enable (default = false)
     * @return void
     */
    public function rotateRefreshTokens($rotateRefreshTokens = false)
    {
        $this->rotateRefreshTokens = $rotateRefreshTokens;
    }

    /**
     * Complete the refresh token grant
     * @param  null|array $inputParams
     * @return array
     */
    public function completeFlow($inputParams = null)
    {
        // Get the required params
        $authParams = $this->authServer->getParam(array('client_id', 'client_secret', 'refresh_token', 'scope'), 'post', $inputParams);

        if (is_null($authParams['client_id'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'client_id'), 0);
        }

        if (is_null($authParams['client_secret'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'client_secret'), 0);
        }

        // Validate client ID and client secret
        $clientDetails = $this->authServer->getStorage('client')->getClient($authParams['client_id'], $authParams['client_secret'], null, $this->identifier);

        if ($clientDetails === false) {
            throw new Exception\ClientException($this->authServer->getExceptionMessage('invalid_client'), 8);
        }

        $authParams['client_details'] = $clientDetails;

        if (is_null($authParams['refresh_token'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'refresh_token'), 0);
        }

        // Validate refresh token
        $accessTokenId = $this->authServer->getStorage('session')->validateRefreshToken($authParams['refresh_token'], $authParams['client_id']);

        if ($accessTokenId === false) {
            throw new Exception\ClientException($this->authServer->getExceptionMessage('invalid_refresh'), 0);
        }

        // Get the existing access token
        $accessTokenDetails = $this->authServer->getStorage('session')->getAccessToken($accessTokenId);

        // Get the scopes for the existing access token
        $scopes = $this->authServer->getStorage('session')->getScopes($accessTokenDetails['access_token']);

        // Generate new tokens and associate them to the session
        $accessToken = SecureKey::make();
        $accessTokenExpiresIn = ($this->accessTokenTTL !== null) ? $this->accessTokenTTL : $this->authServer->getAccessTokenTTL();
        $accessTokenExpires = time() + $accessTokenExpiresIn;

        // Associate the new access token with the session
        $newAccessTokenId = $this->authServer->getStorage('session')->associateAccessToken($accessTokenDetails['session_id'], $accessToken, $accessTokenExpires);

        if ($this->rotateRefreshTokens === true) {

            // Generate a new refresh token
            $refreshToken = SecureKey::make();
            $refreshTokenExpires = time() + $this->getRefreshTokenTTL();

            // Revoke the old refresh token
            $this->authServer->getStorage('session')->removeRefreshToken($authParams['refresh_token']);

            // Associate the new refresh token with the new access token
            $this->authServer->getStorage('session')->associateRefreshToken($newAccessTokenId, $refreshToken, $refreshTokenExpires, $authParams['client_id']);
        }

        // There isn't a request for reduced scopes so assign the original ones (or we're not rotating scopes)
        if ( ! isset($authParams['scope'])) {

            foreach ($scopes as $scope) {
                $this->authServer->getStorage('session')->associateScope($newAccessTokenId, $scope['id']);
            }

        } elseif ( isset($authParams['scope']) && $this->rotateRefreshTokens === true) {

            // The request is asking for reduced scopes and rotate tokens is enabled
            $reqestedScopes = explode($this->authServer->getScopeDelimeter(), $authParams['scope']);

            for ($i = 0; $i < count($reqestedScopes); $i++) {
                $reqestedScopes[$i] = trim($reqestedScopes[$i]);
                if ($reqestedScopes[$i] === '') unset($reqestedScopes[$i]); // Remove any junk scopes
            }

            // Check that there aren't any new scopes being included
            $existingScopes = array();
            foreach ($scopes as $s) {
                $existingScopes[] = $s['scope'];
            }

            foreach ($reqestedScopes as $reqScope) {
                if ( ! in_array($reqScope, $existingScopes)) {
                    throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'scope'), 0);
                }

                // Associate with the new access token
                $scopeDetails = $this->authServer->getStorage('scope')->getScope($reqScope, $authParams['client_id'], $this->identifier);
                $this->authServer->getStorage('session')->associateScope($newAccessTokenId, $scopeDetails['id']);
            }
        }

        $response = array(
            'access_token'  =>  $accessToken,
            'token_type'    =>  'bearer',
            'expires'       =>  $accessTokenExpires,
            'expires_in'    =>  $accessTokenExpiresIn
        );

        if ($this->rotateRefreshTokens === true) {
            $response['refresh_token'] = $refreshToken;
        }

        return $response;
    }

}
