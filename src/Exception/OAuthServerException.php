<?php

namespace League\OAuth2\Server\Exception;

use League\OAuth2\Server\Utils\RedirectUri;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

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
     * Throw a new exception
     *
     * @param string      $message        Error message
     * @param string      $errorType      Error type
     * @param int         $httpStatusCode HTTP status code to send (default = 400)
     * @param null|string $hint           A helper hint
     * @param null|string $redirectUri    A HTTP URI to redirect the user back to
     */
    public function __construct($message, $errorType, $httpStatusCode = 400, $hint = null, $redirectUri = null)
    {
        parent::__construct($message);
        $this->httpStatusCode = $httpStatusCode;
        $this->errorType = $errorType;
        $this->hint = $hint;
        $this->redirectUri = $redirectUri;
    }

    /**
     * @return int
     */
    public function getHttpStatusCode()
    {
        return $this->httpStatusCode;
    }


    /**
     * @return string
     */
    public function getErrorType()
    {
        return $this->errorType;
    }

    /**
     * Get all headers that have to be send with the error response
     *
     * @return array Array with header values
     */
    public function getHttpHeaders()
    {
        $headers = [
            'Content-type' => 'application/json'
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
            $authScheme = null;
            $request = new ServerRequest();
            if ($request->getServerParams()['PHP_AUTH_USER'] !== null) {
                $authScheme = 'Basic';
            } else {
                $authHeader = $request->getHeader('authorization');
                if ($authHeader !== null) {
                    if (strpos($authHeader, 'Bearer') === 0) {
                        $authScheme = 'Bearer';
                    } elseif (strpos($authHeader, 'Basic') === 0) {
                        $authScheme = 'Basic';
                    }
                }
            }
            if ($authScheme !== null) {
                $headers[] = 'WWW-Authenticate: ' . $authScheme . ' realm="OAuth"';
            }
        }

        // @codeCoverageIgnoreEnd
        return $headers;
    }

    /**
     * Generate a HTTP response
     * @return ResponseInterface
     */
    public function generateHttpResponse()
    {
        $headers = $this->getHttpHeaders();

        $payload = [
            'error'   => $this->errorType,
            'message' => $this->getMessage()
        ];

        if ($this->hint !== null) {
            $payload['hint'] = $this->hint;
        }

        if ($this->redirectUri !== null) {
            $headers['Location'] = RedirectUri::make($this->redirectUri, $payload);
        }

        $response = new Response(
            'php://memory',
            $this->getHttpStatusCode(),
            $headers
        );
        $response->getBody()->write(json_encode($payload));

        return $response;
    }

    /**
     * Invalid grant type error
     *
     * @param null|string $localizedError
     * @param null|string $localizedHint
     *
     * @return static
     */
    public static function invalidGrantType(
        $localizedError = null,
        $localizedHint = null
    ) {
        $errorMessage = (is_null($localizedError))
            ? 'The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.'
            : $localizedError;
        $hint = (is_null($localizedHint))
            ? 'Check the `grant_type` parameter'
            : $localizedHint;

        return new static($errorMessage, 'invalid_grant', 400, $hint);
    }

    /**
     * Unsupported grant type error
     *
     * @param null|string $localizedError
     * @param null|string $localizedHint
     *
     * @return static
     */
    public static function unsupportedGrantType(
        $localizedError = null,
        $localizedHint = null
    ) {
        $errorMessage = (is_null($localizedError))
            ? 'The authorization grant type is not supported by the authorization server.'
            : $localizedError;
        $hint = (is_null($localizedHint))
            ? 'Check the `grant_type` parameter'
            : $localizedHint;

        return new static($errorMessage, 'unsupported_grant_type', 400, $hint);
    }

    /**
     * Invalid request error
     *
     * @param string      $parameter The invalid parameter
     * @param null|string $localizedError
     * @param null|string $localizedHint
     *
     * @return static
     */
    public static function invalidRequest(
        $parameter,
        $localizedError = null,
        $localizedHint = null
    ) {
        $errorMessage = (is_null($localizedError))
            ? 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.'
            : $localizedError;
        $hint = (is_null($localizedHint))
            ? sprintf('Check the `%s` parameter', $parameter)
            : sprintf($localizedHint, $parameter);

        return new static($errorMessage, 'invalid_request', 400, $hint);
    }

    /**
     * Invalid client error
     *
     * @param null|string $localizedError
     *
     * @return static
     */
    public static function invalidClient($localizedError = null)
    {
        $errorMessage = (is_null($localizedError))
            ? 'Client authentication failed'
            : $localizedError;

        return new static($errorMessage, 'invalid_client', 401);
    }

    /**
     * Invalid scope error
     *
     * @param string      $scope          The bad scope
     * @param null|string $localizedError A localized error message
     * @param null|string $localizedHint  A localized error hint
     * @param null|string $redirectUri    A HTTP URI to redirect the user back to
     *
     * @return static
     */
    public static function invalidScope($scope, $localizedError = null, $localizedHint = null, $redirectUri = null)
    {
        $errorMessage = (is_null($localizedError))
            ? 'The requested scope is invalid, unknown, or malformed'
            : $localizedError;
        $hint = (is_null($localizedHint))
            ? sprintf('Check the `%s` scope', $scope)
            : sprintf($localizedHint, $scope);

        return new static($errorMessage, 'invalid_scope', 400, $hint, $redirectUri);
    }
}
