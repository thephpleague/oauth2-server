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
class NoTokenException extends OAuthException
{
    /**
     * The HTTP status code for this exception that should be sent in the response
     */
    public $httpStatusCode = 400;

    /**
     * The exception type
     */
    public $errorType = 'invalid_request';

    /**
     * Throw a new exception
     *
     * @param string $msg Exception Message
     */
    public function __construct($msg = 'No access token present')
    {
        parent::__construct($msg);
    }

    /**
     * Get all headers that have to be send with the error response
     *
     * @return array Array with header values
     */

    public function getHttpHeaders()
    {
        $headers = parent::getHttpHeaders();

        // Add "WWW-Authenticate" header
        //
        // RFC 6749, section 5.2.:
        // "If the client attempted to authenticate via the 'Authorization'
        // request header field, the authorization server MUST
        // respond with an HTTP 401 (Unauthorized) status code and
        // include the "WWW-Authenticate" response header field
        // matching the authentication scheme used by the client.
        // @codeCoverageIgnoreStart

        $authScheme = $this->determineAuthScheme();    

        switch ($authScheme) {
            case 'Bearer':
                $headers[] = 'WWW-Authenticate: ' . $authScheme;
            break;
        }
        
        // @codeCoverageIgnoreEnd
        
        return $headers;
    }

}
