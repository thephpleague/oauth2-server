<?php

namespace League\OAuth2\Server\Exception;

use Throwable;

class InvalidRequestException extends OAuthServerException
{
    private const ERROR_TYPE = 'invalid_request';
    private const HTTP_STATUS_CODE = 400;
    private const EXCEPTION_CODE = 3;

    public function __construct($errorMessage, $redirectUri = null, Throwable $previousException = null)
    {
        parent::__construct($errorMessage, self::EXCEPTION_CODE, self::ERROR_TYPE, self::HTTP_STATUS_CODE, $redirectUri, $previousException);
    }


    public static function missingAuthCode() {
        $errorMessage = 'The auth code is missing from the request';

        return new static($errorMessage);
    }

    public static function authCodeDecryptError(Throwable $previousException)
    {
        $errorMessage = 'Cannot decrypt the authorization code';

        return new static($errorMessage, null, $previousException);
    }

    public static function missingCodeVerifier()
    {
        $errorMessage = 'The code_verifier is missing';

        return new static($errorMessage);
    }

    public static function illegalCharacters($parameterName)
    {
        $errorMessage = 'The ' . $parameterName . ' contains illegal characters';

        return new static($errorMessage);
    }

    public static function missingAuthCodeId()
    {
        $errorMessage = 'The auth_code_id property is missing from the auth code provided';

        return new static($errorMessage);
    }

    public static function authCodeExpired()
    {
        $errorMessage = 'The provided authorization code has expired';

        return new static($errorMessage);
    }

    public static function authCodeNotClients()
    {
        $errorMessage = 'The authorization code was not issued to this client';

        return new static($errorMessage);
    }

    public static function invalidRedirectUri()
    {
        $errorMessage = 'The redirect_uri given is not valid';

        return new static($errorMessage);
    }

    public static function missingParameter(string $parameterName)
    {
        $errorMessage = 'The ' . $parameterName . ' is missing from the request';

        return new static($errorMessage);
    }

    public static function invalidCodeChallengeMethod(array $methods)
    {
        $errorMessage = 'Code challenge method must be one of ' . \implode(', ', \array_map(
            function ($method) {
                return '`' . $method . '`';
            },
            $methods)
        );

        return new static($errorMessage);
    }

    ### Illegal Characters
    ### Parameters Missing
}