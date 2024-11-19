<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Exception;

use Exception;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

use function htmlspecialchars;
use function http_build_query;
use function sprintf;

class OAuthServerException extends Exception
{
    /**
     * @var array<string, string>
     */
    private array $payload;

    private ServerRequestInterface $serverRequest;

    /**
     * Throw a new exception.
     */
    final public function __construct(string $message, int $code, private string $errorType, private int $httpStatusCode = 400, private ?string $hint = null, private ?string $redirectUri = null, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->payload = [
            'error'             => $errorType,
            'error_description' => $message,
        ];

        if ($hint !== null) {
            $this->payload['hint'] = $hint;
        }
    }

    /**
     * Returns the current payload.
     *
     * @return array<string, string>
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    /**
     * Updates the current payload.
     *
     * @param array<string, string> $payload
     */
    public function setPayload(array $payload): void
    {
        $this->payload = $payload;
    }

    /**
     * Set the server request that is responsible for generating the exception
     */
    public function setServerRequest(ServerRequestInterface $serverRequest): void
    {
        $this->serverRequest = $serverRequest;
    }

    /**
     * Unsupported grant type error.
     */
    public static function unsupportedGrantType(): static
    {
        $errorMessage = 'The authorization grant type is not supported by the authorization server.';
        $hint = 'Check that all required parameters have been provided';

        return new static($errorMessage, 2, 'unsupported_grant_type', 400, $hint);
    }

    /**
     * Invalid request error.
     */
    public static function invalidRequest(string $parameter, ?string $hint = null, ?Throwable $previous = null): static
    {
        $errorMessage = 'The request is missing a required parameter, includes an invalid parameter value, ' .
            'includes a parameter more than once, or is otherwise malformed.';
        $hint = ($hint === null) ? sprintf('Check the `%s` parameter', $parameter) : $hint;

        return new static($errorMessage, 3, 'invalid_request', 400, $hint, null, $previous);
    }

    /**
     * Invalid client error.
     */
    public static function invalidClient(ServerRequestInterface $serverRequest): static
    {
        $exception = new static('Client authentication failed', 4, 'invalid_client', 401);

        $exception->setServerRequest($serverRequest);

        return $exception;
    }

    /**
     * Invalid scope error
     */
    public static function invalidScope(string $scope, string|null $redirectUri = null): static
    {
        $errorMessage = 'The requested scope is invalid, unknown, or malformed';

        if ($scope === '') {
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
     */
    public static function invalidCredentials(): static
    {
        return new static('The user credentials were incorrect.', 6, 'invalid_grant', 400);
    }

    /**
     * Server error.
     *
     * @codeCoverageIgnore
     */
    public static function serverError(string $hint, ?Throwable $previous = null): static
    {
        return new static(
            'The authorization server encountered an unexpected condition which prevented it from fulfilling'
            . ' the request: ' . $hint,
            7,
            'server_error',
            500,
            null,
            null,
            $previous
        );
    }

    /**
     * Invalid refresh token.
     */
    public static function invalidRefreshToken(?string $hint = null, ?Throwable $previous = null): static
    {
        return new static('The refresh token is invalid.', 8, 'invalid_grant', 400, $hint, null, $previous);
    }

    /**
     * Access denied.
     */
    public static function accessDenied(?string $hint = null, ?string $redirectUri = null, ?Throwable $previous = null): static
    {
        return new static(
            'The resource owner or authorization server denied the request.',
            9,
            'access_denied',
            401,
            $hint,
            $redirectUri,
            $previous
        );
    }

    /**
     * Invalid grant.
     */
    public static function invalidGrant(string $hint = ''): static
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

    public function getErrorType(): string
    {
        return $this->errorType;
    }

    /**
     * Expired token error.
     *
     * @param Throwable $previous Previous exception
     *
     * @return static
     */
    public static function expiredToken(?string $hint = null, ?Throwable $previous = null): static
    {
        $errorMessage = 'The `device_code` has expired and the device ' .
                        'authorization session has concluded.';

        return new static($errorMessage, 11, 'expired_token', 400, $hint, null, $previous);
    }

    public static function authorizationPending(string $hint = '', ?Throwable $previous = null): static
    {
        return new static(
            'The authorization request is still pending as the end user ' .
            'hasn\'t yet completed the user interaction steps. The client ' .
            'SHOULD repeat the Access Token Request to the token endpoint',
            12,
            'authorization_pending',
            400,
            $hint,
            null,
            $previous
        );
    }

    /**
     * Slow down error used with the Device Authorization Grant.
     *
     *
     * @return static
     */
    public static function slowDown(string $hint = '', ?Throwable $previous = null): static
    {
        return new static(
            'The authorization request is still pending and polling should ' .
                'continue, but the interval MUST be increased ' .
                'by 5 seconds for this and all subsequent requests.',
            13,
            'slow_down',
            400,
            $hint,
            null,
            $previous
        );
    }

    /**
     * Unauthorized client error.
     */
    public static function unauthorizedClient(?string $hint = null): static
    {
        return new static(
            'The authenticated client is not authorized to use this authorization grant type.',
            14,
            'unauthorized_client',
            400,
            $hint
        );
    }

    /**
     * Generate a HTTP response.
     */
    public function generateHttpResponse(ResponseInterface $response, bool $useFragment = false, int $jsonOptions = 0): ResponseInterface
    {
        $headers = $this->getHttpHeaders();

        $payload = $this->getPayload();

        if ($this->redirectUri !== null) {
            if ($useFragment === true) {
                $this->redirectUri .= (str_contains($this->redirectUri, '#') === false) ? '#' : '&';
            } else {
                $this->redirectUri .= (str_contains($this->redirectUri, '?') === false) ? '?' : '&';
            }

            return $response->withStatus(302)->withHeader('Location', $this->redirectUri . http_build_query($payload));
        }

        foreach ($headers as $header => $content) {
            $response = $response->withHeader($header, $content);
        }

        $jsonEncodedPayload = json_encode($payload, $jsonOptions);

        $responseBody = $jsonEncodedPayload === false ? 'JSON encoding of payload failed' : $jsonEncodedPayload;

        $response->getBody()->write($responseBody);

        return $response->withStatus($this->getHttpStatusCode());
    }

    /**
     * Get all headers that have to be send with the error response.
     *
     * @return array<string, string> Array with header values
     */
    public function getHttpHeaders(): array
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
        if ($this->errorType === 'invalid_client' && $this->requestHasAuthorizationHeader()) {
            $authScheme = str_starts_with($this->serverRequest->getHeader('Authorization')[0], 'Bearer') ? 'Bearer' : 'Basic';

            $headers['WWW-Authenticate'] = $authScheme . ' realm="OAuth"';
        }

        return $headers;
    }

    /**
     * Check if the exception has an associated redirect URI.
     *
     * Returns whether the exception includes a redirect, since
     * getHttpStatusCode() doesn't return a 302 when there's a
     * redirect enabled. This helps when you want to override local
     * error pages but want to let redirects through.
     */
    public function hasRedirect(): bool
    {
        return $this->redirectUri !== null;
    }

    /**
     * Returns the Redirect URI used for redirecting.
     */
    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    /**
     * Returns the HTTP status code to send when the exceptions is output.
     */
    public function getHttpStatusCode(): int
    {
        return $this->httpStatusCode;
    }

    public function getHint(): ?string
    {
        return $this->hint;
    }

    /**
     * Check if the request has a non-empty 'Authorization' header value.
     *
     * Returns true if the header is present and not an empty string, false
     * otherwise.
     */
    private function requestHasAuthorizationHeader(): bool
    {
        if (!$this->serverRequest->hasHeader('Authorization')) {
            return false;
        }

        $authorizationHeader = $this->serverRequest->getHeader('Authorization');

        // Common .htaccess configurations yield an empty string for the
        // 'Authorization' header when one is not provided by the client.
        // For practical purposes that case should be treated as though the
        // header isn't present.
        // See https://github.com/thephpleague/oauth2-server/issues/1162
        if ($authorizationHeader === [] || $authorizationHeader[0] === '') {
            return false;
        }

        return true;
    }
}
