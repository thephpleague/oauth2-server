<?php

declare( strict_types=1 );

namespace League\OAuth2\Server\TokenValidators;

class TokenValidationResult {
	public function __construct( private string|int|null $userId ) {
	}

	public static function fromValues( array $values ) {
		return new self(
			$values['user_id'] ?? null,
		);
	}

	public function getUserId(): string|int|null {
		return $this->userId;
	}
}
