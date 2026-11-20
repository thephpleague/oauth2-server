<?php

namespace League\OAuth2\Server\TokenExchange;

use League\OAuth2\Server\TokenIssuers\TokenIssuerInterface;
use League\OAuth2\Server\TokenValidators\TokenValidationResult;
use League\OAuth2\Server\TokenValidators\TokenValidatorInterface;

interface TokenExchangePolicyInterface {
	/**
	 * Checks if the value of subject_token_type is supported by this policy.
	 */
	public function isAllowedSubjectTokenType( string $subjectTokenType ): bool;

	/**
	 * Give a validator that validates the tokens this policy accepts as subject tokens.
	 */
	public function getSubjectTokenValidator( string $subjectTokenType ): TokenValidatorInterface;

	/**
	 * Does this exchange policy _require_ an actor_token to be present in the request?
	 */
	public function requiresActorToken(): bool;

	/**
	 * Checks if the value of actor_token_type is supported by this policy.
	 */
	public function isAllowedActorTokenType( string $actorTokenType ): bool;

	/**
	 * Give a validator that validates the tokens this policy accepts as actor tokens.
	 */
	public function getActorTokenValidator( $actorTokenType ): TokenValidatorInterface;

	/**
	 * If requested_token_type is not provided, this function is called to determine what type of token will be issued.
	 */
	public function determineRequestedTokenType(): string;

	/**
	 * Give a TokenIssuer that issues the tokens this policy should give out.
	 */
	public function getTokenIssuer( string $requestedTokenType ): TokenIssuerInterface;

	/**
	 * Determines if this request should actually be granted;
	 * This is the actual policy that determines who should receive tokens.
	 *
	 * You should check things such as:
	 * * Is the entity identified by the subject_token allowed to access the given scope(s) on the given resource(s)?
	 * * Is the entity identified by the actor_token allowed to get this delegated/impersonation access?
	 * * Is the audience supported by this policy?
	 * * Has any token been revoked?
	 *
	 * @return bool true if request is granted, false if request is denied.
	 * @throws OAuthException with a specific reason for failure of the request.
	 */
	public function authorizeRequest(
		TokenValidationResult $subjectToken,
		?TokenValidationResult $actorToken,
		string $requestedTokenType,
		// More parameters are probably needed...
	): bool;
}
