<?php

namespace League\OAuth2\Server\TokenExchange;

use League\OAuth2\Server\TokenIssuers\AccessTokenIssuer;
use League\OAuth2\Server\TokenIssuers\TokenIssuerInterface;

class SimpleTokenExchangePolicy {
	protected ?AccessTokenValidator $accessTokenValidator = null;
	private AccessTokenRepositoryInterface $accessTokenRepository;
	private ?DateInterval $jwtValidAtDateLeeway = null;

	public function requiresActorToken(): bool {
		return false;
	}

	public function isValidSubjectTokenType( string $subjectTokenType ): bool {
		return $subjectTokenType === TokenType::ACCESS_TOKEN;
	}

	public function getSubjectTokenValidator( $request ): Validator {
		return $this->getAccessTokenValidator();
	}

	public function isValidActorTokenType( string $actorTokenType ): bool {
		return $actorTokenType === TokenType::ACCESS_TOKEN;
	}

	public function getActorTokenValidator( $request ): Validator {
		return $this->getAccessTokenValidator();
	}

	public function determineRequestedTokenType( $request ): string {
		return TokenType::ACCESS_TOKEN;
	}

	public function getTokenIssuer(): TokenIssuerInterface {
		$issuer = new AccessTokenIssuer;
		$issuer->setAccessTokenRepository( $this->accessTokenRepository );
		return $issuer;
	}

	private function getAccessTokenValidator() {
		if ( !$this->accessTokenValidator instanceof AccessTokenValidator ) {
			$this->accessTokenValidator = new AccessTokenValidator(
				$this->accessTokenRepository,
				$this->jwtValidAtDateLeeway
			);
		}
		return $this->accessTokenValidator;
	}

	public function setAccessTokenRepository( AccessTokenRepositoryInterface $accessTokenRepository ): void {
		$this->accessTokenRepository = $accessTokenRepository;
	}

	public function setJwtValidAtDateLeeway( ?DateInterval $jwtValidAtDateLeeway ): void {
		$this->jwtValidAtDateLeeway = $jwtValidAtDateLeeway;
	}
}
