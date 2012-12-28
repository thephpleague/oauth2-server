<?php

namespace OAuth2;

use OutOfBoundsException;
use Storage\SessionInterface;
use Storage\SessionScopeInterface;

class Resource
{
    protected $accessToken = null;

    protected $sessionId = null;

    protected $ownerType = null;

    protected $ownerId = null;

    protected $sessionScopes = array();

    protected $storages = array();

    protected $request = null;

    protected $tokenKey = 'oauth_token';

    /**
     * Sets up the Resource
     *
     * @param  SessionInterface  The Session Storage Object
     * @param  SessionScopeInterface  The Session Scope Storage Object
     * @param  RequestInterface  The Request Object
     */
    public function __construct(SessionInterface $session, SessionScopeInterface $session_scope, RequestInterface $request = null)
    {
        $this->storages['session'] = $session;
        $this->storages['session_scope'] = $session_scope;

        if (is_null($request)) {
            $request = Request::buildFromGlobals();
        }
        $this->request = $request;
    }

    /**
     * Checks if the Access Token is valid or not.
     *
     * @return bool
     */
    public function isValid()
    {
        $access_token = $this->determineAccessToken();

        $result = $this->storages['session']->validateAccessToken($access_token);

        if ( ! $result) {
            return false;
        }

        $this->accessToken = $access_token;
        $this->sessionId = $result['id'];
        $this->ownerType = $result['owner_type'];
        $this->ownerId = $result['owner_id'];

        $this->sessionScopes = $this->storages['session_scope']->getScopes($this->sessionId);

        return true;
    }

    /**
     * Checks if the current session has the given scope(s).
     *
     * @param   array
     */
    public function hasScope($scopes)
    {
        if (is_string($scopes)) {
            if (in_array($scopes, $this->sessionScopes)) {
                return true;
            }
            return false;
        } elseif (is_array($scopes)) {
            foreach ($scopes as $scope) {
                if ( ! in_array($scope, $this->sessionScopes)) {
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    protected function determineAccessToken()
    {
        if ($header = $this->request->header('Authorization')) {
            $access_token = trim(str_replace('Bearer', '', $header));
        } else {
            $method = $this->request->server('REQUEST_METHOD');
            $access_token = $this->request->{$method}($this->tokenKey);
        }

        if (empty($access_token)) {
            throw new MissingAccessTokenException('Access Token is Missing');
        }

        return $access_token;
    }

}
