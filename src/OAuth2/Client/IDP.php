<?php

namespace OAuth2\Client;

use Guzzle\Service\Client as GuzzleClient;

class IDPException extends \Exception
{
    protected $result;

    public function __construct($result)
    {
        $this->result = $result;

        $code = isset($result['code']) ? $result['code'] : 0;

        if (isset($result['error'])) {

            // OAuth 2.0 Draft 10 style
            $message = $result['error'];

        } elseif (isset($result['message'])) {

            // cURL style
            $message = $result['message'];

        } else {

            $message = 'Unknown Error.';

        }

        parent::__construct($message['message'], $message['code']);
    }

    public function getType()
    {
        if (isset($this->result['error'])) {

            $message = $this->result['error'];

            if (is_string($message)) {
                // OAuth 2.0 Draft 10 style
                return $message;
            }
        }

        return 'Exception';
    }

    /**
     * To make debugging easier.
     *
     * @returns
     *   The string representation of the error.
     */
    public function __toString()
    {
        $str = $this->getType() . ': ';

        if ($this->code != 0) {
            $str .= $this->code . ': ';
        }

        return $str . $this->message;
    }

}

abstract class IDP {

    public $clientId = '';

    public $clientSecret = '';

    public $redirectUri = '';

    public $name;

    public $uidKey = 'uid';

    public $scopes = array();

    public $method = 'post';

    public $scopeSeperator = ',';

    public $responseType = 'json';

    public function __construct($options)
    {
        foreach ($options as $option => $value) {
            if (isset($this->{$option})) {
                $this->{$option} = $value;
            }
        }
    }

    abstract public function urlAuthorize();

    abstract public function urlAccessToken();

    abstract public function urlUserDetails(\OAuth2\Client\Token\Access $token);

    abstract public function userDetails($response, \OAuth2\Client\Token\Access $token);

    public function authorize($options = array())
    {
        $state = md5(uniqid(rand(), TRUE));
        setcookie($this->name.'_authorize_state', $state);

        $params = array(
            'client_id'         => $this->clientId,
            'redirect_uri'      => $this->redirectUri,
            'state'             => $state,
            'scope'             => is_array($this->scope) ? implode($this->scopeSeperator, $this->scope) : $this->scope,
            'response_type'     => isset($options['response_type']) ? $options['response_type'] : 'code',
            'approval_prompt'   => 'force' // - google force-recheck
        );

        header('Location: ' . $this->urlAuthorize().'?'.http_build_query($params));
        exit;
    }

    public function getAccessToken($code = NULL, $options = array())
    {
        if ($code === NULL) {
            throw new \BadMethodCallException('Missing authorization code');
        }

        $params = array(
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'grant_type'    => isset($options['grantType']) ? $options['grantType'] : 'authorization_code',
        );

        switch ($params['grant_type']) {

            case 'authorization_code':
                $params['code'] = $code;
                $params['redirect_uri'] = isset($options['redirectUri']) ? $options['redirectUri'] : $this->redirectUri;
            break;

            case 'refresh_token':
                $params['refresh_token'] = $code;
            break;

        }

        try {

            switch ($this->method) {

                case 'get':

                    $client = new GuzzleClient($this->urlAccessToken() . '?' . http_build_query($params));
                    $request = $client->send();
                    $response = $request->getBody();

                    break;

                case 'post':

                    $client = new GuzzleClient($this->urlAccessToken());
                    $request = $client->post(null, null, $params)->send();
                    $response = $request->getBody();

                    break;

            }

        }

        catch (\Guzzle\Http\Exception\BadResponseException $e)
        {
            $raw_response = explode("\n", $e->getResponse());
            $response = end($raw_response);
        }

        switch ($this->responseType) {

            case 'json':
                $result = json_decode($response, true);
            break;

            case 'string':
                parse_str($response, $result);
            break;

        }

        if (isset($result['error']) && ! empty($result['error'])) {

            throw new \OAuth2\Client\IDPException($result);

        }

        switch ($params['grant_type']) {

            case 'authorization_code':
                return \OAuth2\Client\Token::factory('access', $result);
            break;

            case 'refresh_token':
                return \OAuth2\Client\Token::factory('refresh', $result);
            break;

        }
    }

    public function getUserDetails(\OAuth2\Client\Token\Access $token)
    {
        $url = $this->urlUserDetails($token);

        try {
            $client = new GuzzleClient($url);
            $request = $client->get()->send();
            $response = $request->getBody();

            return $this->userDetails(json_decode($response), $token);
        }

        catch (\Guzzle\Http\Exception\BadResponseException $e)
        {
            $raw_response = explode("\n", $e->getResponse());
            throw new \OAuth2\Client\IDPException(end($raw_response));
        }
    }

}