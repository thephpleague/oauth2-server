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

use League\OAuth2\Server\Util\RedirectUri;
use Symfony\Component\HttpFoundation\Request;

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
     * Redirect URI if the server should redirect back to the client
     *
     * @var string|null
     */
    public $redirectUri = null;

    /**
     * The exception type
     */
    public $errorType = '';

    /**
     * Parameter eventually passed to Exception
     */
    public $parameter = '';

    /**
     * Throw a new exception
     *
     * @param string $msg Exception Message
     */
    public function __construct($msg = 'An error occured')
    {
        parent::__construct($msg);
    }

    /**
     * Should the server redirect back to the client?
     *
     * @return bool
     */
    public function shouldRedirect()
    {
        return is_null($this->redirectUri) ? false : true;
    }

    /**
     * Return redirect URI if set
     *
     * @return string|null
     */
    public function getRedirectUri()
    {
        return RedirectUri::make(
            $this->redirectUri,
            [
                'error' =>  $this->errorType,
                'message' =>  $this->getMessage(),
            ]
        );
    }

    /**
     * Return parameter if set
     *
     * @return string
     */
    public function getParameter()
    {
        return $this->parameter;
    }

    /**
     * Get all headers that have to be send with the error response
     *
     * @return array Array with header values
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
        if ($this->errorType === 'invalid_client') {
            $authScheme = null;
            $request = new Request();
            if ($request->getUser() !== null) {
                $authScheme = 'Basic';
            } else {
                $authHeader = $request->headers->get('Authorization');
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
