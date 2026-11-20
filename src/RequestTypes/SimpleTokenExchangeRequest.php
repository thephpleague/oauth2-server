<?php

declare( strict_types=1 );

namespace League\OAuth2\Server\RequestTypes;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

class SimpleTokenExchangeRequest implements TokenExchangeRequestInterface {
	protected ClientEntityInterface $client;
	protected string $scope;
	protected string $grantTypeId;
	protected string $subjectToken;
        protected string $subjectTokenType;
	protected ?string $audience;
	protected ?string $actorToken;
        protected ?string $actorTokenType;
        protected ?string $requestedTokenType;
        protected ?string $resource;


	public function getClient(): ClientEntityInterface {
		return $this->client;
	}

	public function setScope( ?string $scope ): void {
		$this->scope = $scope;
	}

	public function setGrantTypeId( string $grantTypeId ): void {
		$this->grantTypeId = $grantTypeId;
	}

	public function setClient( ClientEntityInterface $client ): void {
		$this->client = $client;
	}

	public function getScope(): ?string {
		return $this->scope;
	}

	public function getGrantTypeId(): string {
		return $this->grantTypeId;
	}

	public function setSubjectToken( string $subjectToken ): void {
		$this->subjectToken = $subjectToken;
	}

	public function getSubjectToken(): string {
		return $this->subjectToken;
	}

	public function setAudience( ?string $audience ): void {
		$this->audience = $audience;
	}

	public function getAudience(): ?string {
		return $this->audience;
	}

	public function setSubjectTokenType( string $subjectTokenType ): void {
		$this->subjectTokenType = $subjectTokenType;
	}

	public function getSubjectTokenType(): string {
		return $this->subjectTokenType;
	}

	public function setActorToken( ?string $actorToken ): void {
		$this->actorToken = $actorToken;
	}

	public function getActorToken(): ?string {
		return $this->actorToken;
	}

	public function setActorTokenType( ?string $actorTokenType ): void {
		$this->actorTokenType = $actorTokenType;
	}

	public function getActorTokenType(): ?string {
		return $this->actorTokenType;
	}

	public function setRequestedTokenType( ?string $requestedTokenType ): void {
		$this->requestedTokenType = $requestedTokenType;
	}

	public function getRequestedTokenType(): ?string {
		return $this->requestedTokenType;
	}

	public function setResource( ?string $resource ): void {
		$this->resource = $resource;
	}

	public function getResource(): ?string {
		return $this->resource;
	}
}
