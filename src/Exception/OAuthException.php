<?php
/**
 * OAuth 2.0 Base Exception
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Exception;

/**
 * Exception class
 */
class OAuthException extends \Exception
{
    /**
     * The HTTP status code for this exception that should be sent in the response
     */
    public $httpStatusCode = 400;

    /**
     * The exception type
     */
    public $errorType = '';

    /**
     * Throw a new exception
     */
    public function __construct()
    {
        parent::__construct('An error occured');
    }

    /**
     * Get all headers that have to be send with the error response
     * @return array         Array with header values
     */
    public function getHttpHeaders()
    {
        $headers = [];
        switch ($this->httpStatusCode) {
            case 401:
                $headers[] = 'HTTP/1.1 401 Unauthorized';
                break;
            case 500:
                $headers[] = 'HTTP/1.1 500 Internal Server Error';
                break;
            case 501:
                $headers[] = 'HTTP/1.1 501 Not Implemented';
                break;
            case 400:
            default:
                $headers[] = 'HTTP/1.1 400 Bad Request';
                break;
        }

        // Add "WWW-Authenticate" header
        //
        // RFC 6749, section 5.2.:
        // "If the client attempted to authenticate via the 'Authorization'
        // request header field, the authorization server MUST
        // respond with an HTTP 401 (Unauthorized) status code and
        // include the "WWW-Authenticate" response header field
        // matching the authentication scheme used by the client.
        // @codeCoverageIgnoreStart
        if ($error === 'invalid_client') {
            $authScheme = null;
            $request = new Request();
            if ($request->server('PHP_AUTH_USER') !== null) {
                $authScheme = 'Basic';
            } else {
                $authHeader = $request->header('Authorization');
                if ($authHeader !== null) {
                    if (strpos($authHeader, 'Bearer') === 0) {
                        $authScheme = 'Bearer';
                    } elseif (strpos($authHeader, 'Basic') === 0) {
                        $authScheme = 'Basic';
                    }
                }
            }
            if ($authScheme !== null) {
                $headers[] = 'WWW-Authenticate: '.$authScheme.' realm=""';
            }
        }
        // @codeCoverageIgnoreEnd

        return $headers;
    }
}
