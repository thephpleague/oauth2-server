<?php

declare( strict_types=1 );

namespace League\OAuth2\Server\TokenValidators;

use DateInterval;
use DateTimeZone;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Exception;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\TokenValidators\TokenValidationResult;

/**
 * A validator for access tokens that have been issued by this server.
 */
class AccessTokenValidator implements TokenValidatorInterface {
	use CryptTrait;

	protected CryptKey $publicKey;

	private Configuration $jwtConfiguration;

	public function __construct(
		private AccessTokenRepositoryInterface $accessTokenRepository,
		private ?DateInterval $jwtValidAtDateLeeway = null
	) {
	}

	/**
	 * Set the public key
	 */
	public function setPublicKey( CryptKey $key ): void {
		$this->publicKey = $key;

		$this->initJwtConfiguration();
	}

	/**
	 * Initialise the JWT configuration.
	 */
	private function initJwtConfiguration(): void {
				$this->jwtConfiguration = Configuration::forSymmetricSigner(
			new Sha256(),
			InMemory::plainText( '' )
		);

		$this->jwtConfiguration->setValidationConstraints(
			new ValidAt( new SystemClock( new DateTimeZone( \date_default_timezone_get() ) ) ),
			new SignedWith( new Sha256(), LocalFileReference::file( $this->publicKey->getKeyPath() ) )
		);
// TODO before merging upstream: There are some changes here between versions. Make sure we have the correct version.
/*		$this->jwtConfiguration = Configuration::forSymmetricSigner(
			new Sha256(),
			InMemory::plainText('empty', 'empty')
		);

		$clock = new class () implements ClockInterface {
			public function now(): DateTimeImmutable
			{
				return new DateTimeImmutable('now', new DateTimeZone(date_default_timezone_get()));
			}
		};

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
		);*/
	}

	/**
	 * {@inheritdoc}
	 */
	public function validateToken( string $jwt ): TokenValidationResult {
		if ( $jwt === '' ) {
			throw OAuthServerException::accessDenied( 'Missing "Bearer" token' );
		}

		try {
			// Attempt to parse the JWT
			$token = $this->jwtConfiguration->parser()->parse( $jwt );
		} catch ( Exception $exception ) {
			throw OAuthServerException::accessDenied( $exception->getMessage(), null, $exception );
		}

		try {
			// Attempt to validate the JWT
			$constraints = $this->jwtConfiguration->validationConstraints();
			$this->jwtConfiguration->validator()->assert( $token, ...$constraints );
		} catch ( RequiredConstraintsViolated $exception ) {
			throw OAuthServerException::accessDenied( 'Access token could not be verified', null, $exception );
		}

		if ( !$token instanceof UnencryptedToken ) {
			throw OAuthServerException::accessDenied( 'Access token is not an instance of UnencryptedToken' );
		}

		$claims = $token->claims();

		// Check if token has been revoked
		if ( $this->accessTokenRepository->isAccessTokenRevoked( $claims->get( 'jti' ) ) ) {
			throw OAuthServerException::accessDenied( 'Access token has been revoked' );
		}

		return TokenValidationResult::fromValues( [
			'access_token_id' => $claims->get( 'jti' ),
			'client_id' => $claims->get( 'aud' )[0],
			'user_id' => $claims->get( 'sub' ),
			'scopes' => $claims->get( 'scopes' ),
		] );
	}
}
