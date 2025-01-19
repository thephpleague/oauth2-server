<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Grant;

use DateInterval;
use DateTimeImmutable;
use Exception;
use InvalidArgumentException;
use League\OAuth2\Server\CodeChallengeVerifiers\CodeChallengeVerifierInterface;
use League\OAuth2\Server\CodeChallengeVerifiers\PlainVerifier;
use League\OAuth2\Server\CodeChallengeVerifiers\S256Verifier;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestRefreshTokenEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use stdClass;

use function array_key_exists;
use function array_keys;
use function array_map;
use function count;
use function hash_algos;
use function implode;
use function in_array;
use function is_array;
use function json_decode;
use function json_encode;
use function preg_match;
use function property_exists;
use function sprintf;
use function time;

class AuthCodeGrant extends AbstractAuthorizeGrant
{
    private bool $requireCodeChallengeForPublicClients = true;

    /**
     * @var CodeChallengeVerifierInterface[]
     */
    private array $codeChallengeVerifiers = [];

    /**
     * @throws Exception
     */
    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        private DateInterval $authCodeTTL
    ) {
        $this->setAuthCodeRepository($authCodeRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->refreshTokenTTL = new DateInterval('P1M');

        if (in_array('sha256', hash_algos(), true)) {
            $s256Verifier = new S256Verifier();
            $this->codeChallengeVerifiers[$s256Verifier->getMethod()] = $s256Verifier;
        }

        $plainVerifier = new PlainVerifier();
        $this->codeChallengeVerifiers[$plainVerifier->getMethod()] = $plainVerifier;
    }

    /**
     * Disable the requirement for a code challenge for public clients.
     */
    public function disableRequireCodeChallengeForPublicClients(): void
    {
        $this->requireCodeChallengeForPublicClients = false;
    }

    /**
     * Respond to an access token request.
     *
     * @throws OAuthServerException
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        list($clientId) = $this->getClientCredentials($request);

        $client = $this->getClientEntityOrFail($clientId, $request);

        // Only validate the client if it is confidential
        if ($client->isConfidential()) {
            $this->validateClient($request);
        }

        $code = $this->getRequestParameter('code', $request);

        if ($code === null) {
            throw OAuthServerException::invalidRequest('code');
        }

        if ($this->canUseCrypt()) {
            try {
                $authCodePayload = json_decode($this->decrypt($code));

                $ace = $this->authCodeRepository->getNewAuthCode();

                if ($ace == null) {
                    // Probably should throw an exception here instead
                    return $responseType;
                }

                if (isset($authCodePayload->auth_code_id))
                    $ace->setIdentifier($authCodePayload->auth_code_id);

                if (isset($authCodePayload->client_id))
                    $ace->setClient($this->getClientEntityOrFail($authCodePayload->client_id, $request));

                if (isset($authCodePayload->user_id))
                    $ace->setUserIdentifier((string)$authCodePayload->user_id);

                if (isset($authCodePayload->code_challenge))
                    $ace->setCodeChallenge($authCodePayload->code_challenge);

                if (isset($authCodePayload->code_challenge_method))
                    $ace->setCodeChallengeMethod($authCodePayload->code_challenge_method);

                if (isset($authCodePayload->redirect_uri))
                    $ace->setRedirectUri($authCodePayload->redirect_uri);

                if (isset($authCodePayload->expire_time)) {
                    $expire = new DateTimeImmutable();
                    $expire = $expire->setTimestamp($authCodePayload->expire_time);

                    $ace->setExpiryDateTime($expire);
                }

                if (isset($authCodePayload->scopes)) {
                    $scopes = $this->validateScopes($authCodePayload->scopes);

                    $ace->setScopes($scopes);
                }

                
                
            } catch (InvalidArgumentException $e) {
                throw OAuthServerException::invalidGrant('Cannot validate the provided authorization code');
            } catch (LogicException $e) {
                throw OAuthServerException::invalidRequest('code', 'Issue decrypting the authorization code', $e);
            }
        }
        else {
            // Get the Auth Code Payload from Repository
            $ace = $this->authCodeRepository->getAuthCodeEntity($code);

            if (empty($ace)) {
                throw OAuthServerException::invalidRequest('code', 'Cannot find authorization code');
            }
        }

        $this->validateAuthorizationCode($ace, $client, $request);

        $scopes = $this->scopeRepository->finalizeScopes(
            $ace->getScopes(),
            $this->getIdentifier(),
            $client,
            $ace->getUserIdentifier(),
            $ace->getIdentifier()
        );

        $codeVerifier = $this->getRequestParameter('code_verifier', $request);

        // If a code challenge isn't present but a code verifier is, reject the request to block PKCE downgrade attack
        if ($ace->getCodeChallenge() === null && $codeVerifier !== null) {
            throw OAuthServerException::invalidRequest(
                'code_challenge',
                'code_verifier received when no code_challenge is present'
            );
        }

        if ($ace->getCodeChallenge() !== null) {
            $this->validateCodeChallenge($ace, $codeVerifier);
        }

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $ace->getUserIdentifier(), $scopes);
        $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));
        $responseType->setAccessToken($accessToken);

        // Issue and persist new refresh token if given
        $refreshToken = $this->issueRefreshToken($accessToken);

        if ($refreshToken !== null) {
            $this->getEmitter()->emit(new RequestRefreshTokenEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request, $refreshToken));
            $responseType->setRefreshToken($refreshToken);
        }

        // Revoke used auth code
        $this->authCodeRepository->revokeAuthCode($ace->getIdentifier());

        return $responseType;
    }

    private function validateCodeChallenge(AuthCodeEntityInterface $authCodeEntity, ?string $codeVerifier): void
    {
        if ($codeVerifier === null) {
            throw OAuthServerException::invalidRequest('code_verifier');
        }

        // Validate code_verifier according to RFC-7636
        // @see: https://tools.ietf.org/html/rfc7636#section-4.1
        if (preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $codeVerifier) !== 1) {
            throw OAuthServerException::invalidRequest(
                'code_verifier',
                'Code Verifier must follow the specifications of RFC-7636.'
            );
        }


        if (isset($this->codeChallengeVerifiers[$authCodeEntity->getCodeChallengeMethod()])) {
            $codeChallengeVerifier = $this->codeChallengeVerifiers[$authCodeEntity->getCodeChallengeMethod()];

            if ($authCodeEntity->getCodeChallenge() === null || $codeChallengeVerifier->verifyCodeChallenge($codeVerifier, $authCodeEntity->getCodeChallenge()) === false) {
                throw OAuthServerException::invalidGrant('Failed to verify `code_verifier`.');
            }
        } else {
            throw OAuthServerException::serverError(
                sprintf(
                    'Unsupported code challenge method `%s`',
                    $authCodeEntity->getCodeChallengeMethod()
                )
            );
        }
    }

    /**
     * Validate the authorization code.
     */
    private function validateAuthorizationCode(
        AuthCodeEntityInterface $authCodeEntity,
        ClientEntityInterface $client,
        ServerRequestInterface $request
    ): void {

        try {
            if (empty($authCodeEntity->getIdentifier())) {
                // Make sure its not empty
                throw OAuthServerException::invalidRequest('code', 'Authorization code malformed');
            }
        } catch (\Throwable $th) {
            // $identifier must not be accessed before initialization
            throw OAuthServerException::invalidRequest('code', 'Authorization code malformed');
        }

        if (time() > $authCodeEntity->getExpiryDateTime()->getTimestamp()) {
            throw OAuthServerException::invalidGrant('Authorization code has expired');
        }

        if ($this->authCodeRepository->isAuthCodeRevoked($authCodeEntity->getIdentifier()) === true) {
            throw OAuthServerException::invalidGrant('Authorization code has been revoked');
        }

        if ($authCodeEntity->getClient()->getIdentifier() !== $client->getIdentifier()) {
            throw OAuthServerException::invalidRequest('code', 'Authorization code was not issued to this client');
        }

        // The redirect URI is required in this request if it was specified
        // in the authorization request
        $redirectUri = $this->getRequestParameter('redirect_uri', $request);
        if ($authCodeEntity->getRedirectUri() !== null && $redirectUri === null) {
            throw OAuthServerException::invalidRequest('redirect_uri');
        }

        // If a redirect URI has been provided ensure it matches the stored redirect URI
        if ($redirectUri !== null && $authCodeEntity->getRedirectUri() !== $redirectUri) {
            throw OAuthServerException::invalidRequest('redirect_uri', 'Invalid redirect URI');
        }
    }

    /**
     * Return the grant identifier that can be used in matching up requests.
     */
    public function getIdentifier(): string
    {
        return 'authorization_code';
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool
    {
        return (
            array_key_exists('response_type', $request->getQueryParams())
            && $request->getQueryParams()['response_type'] === 'code'
            && isset($request->getQueryParams()['client_id'])
        );
    }

    /**
     * {@inheritdoc}
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $clientId = $this->getQueryStringParameter(
            'client_id',
            $request,
            $this->getServerParameter('PHP_AUTH_USER', $request)
        );

        if ($clientId === null) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        $client = $this->getClientEntityOrFail($clientId, $request);

        $redirectUri = $this->getQueryStringParameter('redirect_uri', $request);

        if ($redirectUri !== null) {
            $this->validateRedirectUri($redirectUri, $client, $request);
        } elseif (
            $client->getRedirectUri() === '' ||
            (is_array($client->getRedirectUri()) && count($client->getRedirectUri()) !== 1)
        ) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidClient($request);
        }

        $stateParameter = $this->getQueryStringParameter('state', $request);

        $scopes = $this->validateScopes(
            $this->getQueryStringParameter('scope', $request, $this->defaultScope),
            $this->makeRedirectUri(
                $redirectUri ?? $this->getClientRedirectUri($client),
                $stateParameter !== null ? ['state' => $stateParameter] : []
            )
        );

        $authorizationRequest = $this->createAuthorizationRequest();
        $authorizationRequest->setGrantTypeId($this->getIdentifier());
        $authorizationRequest->setClient($client);
        $authorizationRequest->setRedirectUri($redirectUri);

        if ($stateParameter !== null) {
            $authorizationRequest->setState($stateParameter);
        }

        $authorizationRequest->setScopes($scopes);

        $codeChallenge = $this->getQueryStringParameter('code_challenge', $request);

        if ($codeChallenge !== null) {
            $codeChallengeMethod = $this->getQueryStringParameter('code_challenge_method', $request, 'plain');

            if ($codeChallengeMethod === null) {
                throw OAuthServerException::invalidRequest(
                    'code_challenge_method',
                    'Code challenge method must be provided when `code_challenge` is set.'
                );
            }

            if (array_key_exists($codeChallengeMethod, $this->codeChallengeVerifiers) === false) {
                throw OAuthServerException::invalidRequest(
                    'code_challenge_method',
                    'Code challenge method must be one of ' . implode(', ', array_map(
                        function ($method) {
                            return '`' . $method . '`';
                        },
                        array_keys($this->codeChallengeVerifiers)
                    ))
                );
            }

            // Validate code_challenge according to RFC-7636
            // @see: https://tools.ietf.org/html/rfc7636#section-4.2
            if (preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $codeChallenge) !== 1) {
                throw OAuthServerException::invalidRequest(
                    'code_challenge',
                    'Code challenge must follow the specifications of RFC-7636.'
                );
            }

            $authorizationRequest->setCodeChallenge($codeChallenge);
            $authorizationRequest->setCodeChallengeMethod($codeChallengeMethod);
        } elseif ($this->requireCodeChallengeForPublicClients && !$client->isConfidential()) {
            throw OAuthServerException::invalidRequest('code_challenge', 'Code challenge must be provided for public clients');
        }

        return $authorizationRequest;
    }

    /**
     * {@inheritdoc}
     */
    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): ResponseTypeInterface
    {
        if ($authorizationRequest->getUser() instanceof UserEntityInterface === false) {
            throw new LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        $finalRedirectUri = $authorizationRequest->getRedirectUri()
                          ?? $this->getClientRedirectUri($authorizationRequest->getClient());

        // The user approved the client, redirect them back with an auth code
        if ($authorizationRequest->isAuthorizationApproved() === true) {
            $authCode = $this->issueAuthCode(
                $this->authCodeTTL,
                $authorizationRequest->getClient(),
                $authorizationRequest->getUser()->getIdentifier(),
                $authorizationRequest->getRedirectUri(),
                $authorizationRequest->getScopes(),
                $authorizationRequest->getCodeChallenge(),
                $authorizationRequest->getCodeChallengeMethod()
            );

            $code = $authCode->getIdentifier();

            if ($this->canUseCrypt()) {
                $payload = [
                    'client_id'             => $authCode->getClient()->getIdentifier(),
                    'redirect_uri'          => $authCode->getRedirectUri(),
                    'auth_code_id'          => $authCode->getIdentifier(),
                    'scopes'                => $authCode->getScopes(),
                    'user_id'               => $authCode->getUserIdentifier(),
                    'expire_time'           => (new DateTimeImmutable())->add($this->authCodeTTL)->getTimestamp(),
                    'code_challenge'        => $authorizationRequest->getCodeChallenge(),
                    'code_challenge_method' => $authorizationRequest->getCodeChallengeMethod(),
                ];
    
                $jsonPayload = json_encode($payload);
    
                if ($jsonPayload === false) {
                    throw new LogicException('An error was encountered when JSON encoding the authorization request response');
                }

                $code = $this->encrypt($jsonPayload);
            }
            

            $response = new RedirectResponse();
            $response->setRedirectUri(
                $this->makeRedirectUri(
                    $finalRedirectUri,
                    [
                        'code'  => $code,
                        'state' => $authorizationRequest->getState(),
                    ]
                )
            );

            return $response;
        }

        // The user denied the client, redirect them back with an error
        throw OAuthServerException::accessDenied(
            'The user denied the request',
            $this->makeRedirectUri(
                $finalRedirectUri,
                [
                    'state' => $authorizationRequest->getState(),
                ]
            )
        );
    }
}
