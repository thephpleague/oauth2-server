<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Exception;

use Psr\Http\Message\ResponseInterface;

class OAuthServerException extends \Exception
{
    /**
     * @var int
     */
    private $httpStatusCode;

    /**
     * @var string
     */
    private $errorType;

    /**
     * @var null|string
     */
    private $hint;

    /**
     * @var null|string
     */
    private $redirectUri;

    /**
     * Throw a new exception.
     *
     * @param string      $message        Error message
     * @param int         $code           Error code
     * @param string      $errorType      Error type
     * @param int         $httpStatusCode HTTP status code to send (default = 400)
     * @param null|string $hint           A helper hint
     * @param null|string $redirectUri    A HTTP URI to redirect the user back to
     */
    public function __construct($message, $code, $errorType, $httpStatusCode = 400, $hint = null, $redirectUri = null)
    {
        parent::__construct($message, $code);
        $this->httpStatusCode = $httpStatusCode;
        $this->errorType = $errorType;
        $this->hint = $hint;
        $this->redirectUri = $redirectUri;
    }

    /**
     * Unsupported grant type error.
     *
     * @return static
     */
    public static function unsupportedGrantType()
    {
        $errorMessage = 'The authorization grant type is not supported by the authorization server.';
        $hint = 'Check the `grant_type` parameter';

        return new static($errorMessage, 2, 'unsupported_grant_type', 400, $hint);
    }

    /**
     * Invalid request error.
     *
     * @param string      $parameter The invalid parameter
     * @param null|string $hint
     *
     * @return static
     */
    public static function invalidRequest($parameter, $hint = null)
    {
        $errorMessage = 'The request is missing a required parameter, includes an invalid parameter value, ' .
            'includes a parameter more than once, or is otherwise malformed.';
        $hint = ($hint === null) ? sprintf('Check the `%s` parameter', $parameter) : $hint;

        return new static($errorMessage, 3, 'invalid_request', 400, $hint);
    }

    /**
     * Invalid client error.
     *
     * @return static
     */
    public static function invalidClient()
    {
        $errorMessage = 'Client authentication failed';

        return new static($errorMessage, 4, 'invalid_client', 401);
    }

    /**
     * Invalid scope error.
     *
     * @param string      $scope       The bad scope
     * @param null|string $redirectUri A HTTP URI to redirect the user back to
     *
     * @return static
     */
    public static function invalidScope($scope, $redirectUri = null)
    {
        $errorMessage = 'The requested scope is invalid, unknown, or malformed';

        if (empty($scope)) {
            $hint = 'Specify a scope in the request or set a default scope';
        } else {
            $hint = sprintf(
                'Check the `%s` scope',
                htmlspecialchars($scope, ENT_QUOTES, 'UTF-8', false)
            );
        }

        return new static($errorMessage, 5, 'invalid_scope', 400, $hint, $redirectUri);
    }

    /**
     * Invalid credentials error.
     *
     * @return static
     */
    public static function invalidCredentials()
    {
        return new static('The user credentials were incorrect.', 6, 'invalid_credentials', 401);
    }

    /**
     * Server error.
     *
     * @param $hint
     *
     * @return static
     *
     * @codeCoverageIgnore
     */
    public static function serverError($hint)
    {
        return new static(
            'The authorization server encountered an unexpected condition which prevented it from fulfilling'
            . ' the request: ' . $hint,
            7,
            'server_error',
            500
        );
    }

    /**
     * Invalid refresh token.
     *
     * @param null|string $hint
     *
     * @return static
     */
    public static function invalidRefreshToken($hint = null)
    {
        return new static('The refresh token is invalid.', 8, 'invalid_request', 401, $hint);
    }

    /**
     * Access denied.
     *
     * @param null|string $hint
     * @param null|string $redirectUri
     *
     * @return static
     */
    public static function accessDenied($hint = null, $redirectUri = null)
    {
        return new static(
            'The resource owner or authorization server denied the request.',
            9,
            'access_denied',
            401,
            $hint,
            $redirectUri
        );
    }

    /**
     * Invalid grant.
     *
     * @param string $hint
     *
     * @return static
     */
    public static function invalidGrant($hint = '')
    {
        return new static(
            'The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token '
                . 'is invalid, expired, revoked, does not match the redirection URI used in the authorization request, '
                . 'or was issued to another client.',
            10,
            'invalid_grant',
            400,
            $hint
        );
    }

    /**
     * @return string
     */
    public function getErrorType()
    {
        return $this->errorType;
    }

    /**
     * Generate a HTTP response.
     *
     * @param ResponseInterface $response
     * @param bool              $useFragment True if errors should be in the URI fragment instead of query string
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response, $useFragment = false)
    {
        $headers = $this->getHttpHeaders();

        $payload = [
            'error'   => $this->getErrorType(),
            'message' => $this->getMessage(),
        ];

        if ($this->hint !== null) {
            $payload['hint'] = $this->hint;
        }

        if ($this->redirectUri !== null) {
            if ($useFragment === true) {
                $this->redirectUri .= (strstr($this->redirectUri, '#') === false) ? '#' : '&';
            } else {
                $this->redirectUri .= (strstr($this->redirectUri, '?') === false) ? '?' : '&';
            }

            return $response->withStatus(302)->withHeader('Location', $this->redirectUri . http_build_query($payload));
        }

        foreach ($headers as $header => $content) {
            $response = $response->withHeader($header, $content);
        }

        $response->getBody()->write(json_encode($payload));

        return $response->withStatus($this->getHttpStatusCode());
    }

    /**
     * Get all headers that have to be send with the error response.
     *
     * @return array Array with header values
     */
    public function getHttpHeaders()
    {
        $headers = [
            'Content-type' => 'application/json',
        ];

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
            $authScheme = 'Basic';
            if (array_key_exists('HTTP_AUTHORIZATION', $_SERVER) !== false
                && strpos($_SERVER['HTTP_AUTHORIZATION'], 'Bearer') === 0
            ) {
                $authScheme = 'Bearer';
            }
            $headers['WWW-Authenticate'] = $authScheme . ' realm="OAuth"';
        }
        // @codeCoverageIgnoreEnd
        return $headers;
    }

    /**
     * Returns the HTTP status code to send when the exceptions is output.
     *
     * @return int
     */
    public function getHttpStatusCode()
    {
        return $this->httpStatusCode;
    }

    /**
     * @return null|string
     */
    public function getHint()
    {
        return $this->hint;
    }
}
