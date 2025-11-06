<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\AuthorizationValidators;

use DateInterval;
use DateTimeZone;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Exception;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

use function date_default_timezone_get;
use function preg_replace;
use function trim;

class BearerTokenValidator implements AuthorizationValidatorInterface, JwtValidatorInterface
{
    use CryptTrait;

    protected CryptKeyInterface $publicKey;

    private Configuration $jwtConfiguration;

    public function __construct(private AccessTokenRepositoryInterface $accessTokenRepository, private ?DateInterval $jwtValidAtDateLeeway = null)
    {
    }

    /**
     * Set the public key
     */
    public function setPublicKey(CryptKeyInterface $key): void
    {
        $this->publicKey = $key;

        $this->initJwtConfiguration();
    }

    /**
     * Initialise the JWT configuration.
     */
    private function initJwtConfiguration(): void
    {
        $this->jwtConfiguration = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText('empty', 'empty')
        );

        $clock = new SystemClock(new DateTimeZone(date_default_timezone_get()));

        $publicKeyContents = $this->publicKey->getKeyContents();

        if ($publicKeyContents === '') {
            throw new RuntimeException('Public key is empty');
        }

        // TODO: next major release: replace deprecated method and remove phpstan ignored error
        $this->jwtConfiguration->setValidationConstraints(
            new LooseValidAt($clock, $this->jwtValidAtDateLeeway),
            new SignedWith(
                new Sha256(),
                InMemory::plainText($publicKeyContents, $this->publicKey->getPassPhrase() ?? '')
            )
        );
    }

    /**
     * {@inheritdoc}
     */
    public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface
    {
        if ($request->hasHeader('authorization') === false) {
            throw OAuthServerException::accessDenied('Missing "Authorization" header');
        }

        $header = $request->getHeader('authorization');
        $jwt = trim((string) preg_replace('/^\s*Bearer\s/i', '', $header[0]));

        if ($jwt === '') {
            throw OAuthServerException::accessDenied('Missing "Bearer" token');
        }

        $claims = $this->validateJwt($request, $jwt);

        // Return the request with additional attributes
        return $request
            ->withAttribute('oauth_access_token_id', $claims['jti'] ?? null)
            ->withAttribute('oauth_client_id', $claims['aud'][0] ?? null)
            ->withAttribute('oauth_user_id', $claims['sub'] ?? null)
            ->withAttribute('oauth_scopes', $claims['scopes'] ?? null);
    }

    /**
     * {@inheritdoc}
     */
    public function validateJwt(ServerRequestInterface $request, string $jwt, ?string $clientId = null): array
    {
        try {
            // Attempt to parse the JWT
            $token = $this->jwtConfiguration->parser()->parse($jwt);
        } catch (Exception $exception) {
            throw OAuthServerException::accessDenied($exception->getMessage(), null, $exception);
        }

        try {
            // Attempt to validate the JWT
            $constraints = $this->jwtConfiguration->validationConstraints();
            $this->jwtConfiguration->validator()->assert($token, ...$constraints);
        } catch (RequiredConstraintsViolated $exception) {
            throw OAuthServerException::accessDenied('Access token could not be verified', null, $exception);
        }

        if (!$token instanceof UnencryptedToken) {
            throw OAuthServerException::accessDenied('Access token is not an instance of UnencryptedToken');
        }

        $claims = $token->claims();

        // Check if token is linked to the client
        if (
            $clientId !== null &&
            $claims->get('client_id') !== $clientId &&
            !$token->isPermittedFor($clientId)
        ) {
            throw OAuthServerException::accessDenied('Access token is not linked to client');
        }

        // Check if token has been revoked
        if ($this->accessTokenRepository->isAccessTokenRevoked($claims->get('jti'))) {
            throw OAuthServerException::accessDenied('Access token has been revoked');
        }

        return $claims->all();
    }
}
