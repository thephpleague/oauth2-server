<?php

declare( strict_types=1 );

namespace League\OAuth2\Server\TokenValidators;

interface TokenValidatorInterface {
	/**
	 * Validates the token. Different validators may be suitable for different types of tokens.
	 *
	 * @throws OAuthServerException As created with OAuthServerException::accessDenied
	 */
	public function validateToken( string $token ): TokenValidationResult;
}
