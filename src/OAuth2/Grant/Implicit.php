<?php
/**
 * OAuth 2.0 implicit grant
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
 * Client credentials grant class
 */
class Implict implements GrantTypeInterface {

    /**
     * Grant identifier
     * @var string
     */
    protected $identifier = 'implicit';

    /**
     * Response type
     * @var string
     */
    protected $responseType = 'token';

    /**
     * AuthServer instance
     * @var AuthServer
     */
    protected $authServer = null;

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
     * Complete the client credentials grant
     * @param  null|array $inputParams
     * @return array
     */
    public function completeFlow($authParams = null)
    {
            // Remove any old sessions the user might have
            $this->authServer->getStorage('session')->deleteSession($authParams['client_id'], 'user', $authParams['user_id']);

            // Generate a new access token
            $accessToken = SecureKey::make();

            // Compute expiry time
            $accessTokenExpires = time() + $this->authServer->getExpiresIn();

            // Create a new session
            $sessionId = $this->authServer->getStorage('session')->createSession(
                $authParams['client_id'],
                $authParams['redirect_uri'],
                'user',
                $authParams['user_id'],
                null,
                $accessToken,
                null,
                $accessTokenExpires,
                'granted'
            );

            // Associate scopes with the new session
            foreach ($authParams['scopes'] as $scope)
            {
                $this->authServer->getStorage('session')->associateScope($sessionId, $scope['id']);
            }

            $response = array(
                'access_token'  =>  $accessToken
            );

            return $response;
        }
    }

}