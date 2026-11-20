<?php

declare( strict_types=1 );

namespace League\OAuth2\Server\RequestTypes;

use League\OAuth2\Server\Entities\ClientEntityInterface;

interface TokenExchangeRequestInterface {
	public function getClient(): ClientEntityInterface;

	public function setScope( ?string $scope ): void;

	public function setGrantTypeId( string $grantTypeId ): void;

	public function setClient( ClientEntityInterface $client ): void;

	public function getScope(): ?string;

	public function getGrantTypeId(): string;

	public function setSubjectToken( string $subjectToken ): void;

	public function getSubjectToken(): string;

	public function setSubjectTokenType( string $subjectTokenType ): void;

	public function getSubjectTokenType(): string;

	public function setActorToken( ?string $actorToken ): void;

	public function getActorToken(): ?string;

	public function setActorTokenType( ?string $actorTokenType ): void;

	public function getActorTokenType(): ?string;

	public function setAudience( ?string $audience ): void;

	public function getAudience(): ?string;

	public function setRequestedTokenType( ?string $requestedTokenType ): void;

	public function getRequestedTokenType(): ?string;

	public function setResource( ?string $resource ): void;

	public function getResource(): ?string;
}
