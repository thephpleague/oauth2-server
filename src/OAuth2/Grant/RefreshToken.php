<?php
/**
 * OAuth 2.0 Refresh token grant
 *
 * @package     lncd/oauth2
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 University of Lincoln
 * @license     http://mit-license.org/
 * @link        http://github.com/lncd/oauth2
 */

namespace OAuth2\Grant;

use OAuth2\Request;
use OAuth2\AuthServer;
use OAuth2\Exception;
use OAuth2\Util\SecureKey;
use OAuth2\Storage\SessionInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\ScopeInterface;

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
    protected $expiresIn = null;

    /**
     * Constructor
     * @param AuthServer $authServer AuthServer instance
     * @return void
     */
    public function __construct(AuthServer $authServer)
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
     * @param int $expiresIn
     * @return void
     */
    public function setExpiresIn($expiresIn)
    {
        $this->expiresIn = $expiresIn;
    }

    /**
     * Complete the refresh token grant
     * @param  null|array $inputParams
     * @return array
     */
    public function completeFlow($inputParams = null)
    {
        // Get the required params
        $authParams = $this->authServer->getParam(array('client_id', 'client_secret', 'refresh_token'), 'post', $inputParams);

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
        $accessTokenId = $this->authServer->getStorage('session')->validateRefreshToken($authParams['refresh_token']);

        if ($accessTokenId === false) {
            throw new Exception\ClientException($this->authServer->getExceptionMessage('invalid_refresh'), 0);
        }

        // Get the existing access token
        $accessTokenDetails = $this->authServer->getStorage('session')->getAccessToken($accessTokenId);

        // Get the scopes for the existing access token
        $scopes = $this->authServer->getStorage('session')->getScopes($accessTokenDetails['access_token']);

        // Generate new tokens and associate them to the session
        $accessToken = SecureKey::make();
        $accessTokenExpiresIn = ($this->expiresIn !== null) ? $this->expiresIn : $this->authServer->getExpiresIn();
        $accessTokenExpires = time() + $accessTokenExpiresIn;
        $refreshToken = SecureKey::make();

        $newAccessTokenId = $this->authServer->getStorage('session')->associateAccessToken($accessTokenDetails['session_id'], $accessToken, $accessTokenExpires);

        foreach ($scopes as $scope) {
            $this->authServer->getStorage('session')->associateScope($newAccessTokenId, $scope['id']);
        }

        $this->authServer->getStorage('session')->associateRefreshToken($newAccessTokenId, $refreshToken);

        return array(
            'access_token'  =>  $accessToken,
            'refresh_token' =>  $refreshToken,
            'token_type'    =>  'bearer',
            'expires'       =>  $accessTokenExpires,
            'expires_in'    =>  $accessTokenExpiresIn
        );
    }

}
