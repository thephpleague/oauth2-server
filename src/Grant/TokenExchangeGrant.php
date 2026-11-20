<?php

namespace League\OAuth2\Server\Grant;

use DateInterval;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\Repositories\TokenExchangePolicyRepositoryInterface;
use League\OAuth2\Server\RequestTypes\TokenExchangeRequestInterface;
use League\OAuth2\Server\RequestTypes\SimpleTokenExchangeRequest;
use League\OAuth2\Server\ResponseTypes\TokenExchangeResponseTypeInterface;
use League\OAuth2\Server\TokenExchange\TokenExchangePolicyInterface;
use League\OAuth2\Server\TokenValidators\TokenValidationResult;
use Psr\Http\Message\ServerRequestInterface;

class TokenExchangeGrant extends AbstractGrant {
	protected TokenExchangePolicyRepositoryInterface $tokenExchangePolicyRepository;

	public function __construct(
		TokenExchangePolicyRepositoryInterface $tokenExchangePolicyRepository
	) {
		$this->setTokenExchangePolicyRepository( $tokenExchangePolicyRepository );
	}

	public function getIdentifier(): string {
		return 'urn:ietf:params:oauth:grant-type:token-exchange';
	}

	public function setTokenExchangePolicyRepository(
		TokenExchangePolicyRepositoryInterface $tokenExchangePolicyRepository
	): void {
		$this->tokenExchangePolicyRepository = $tokenExchangePolicyRepository;
	}

	/**
	 * Respond to an incoming request.
	 */
	public function respondToAccessTokenRequest(
		ServerRequestInterface $request,
		ResponseTypeInterface $responseType,
		DateInterval $accessTokenTTL
	): TokenExchangeResponseTypeInterface {
		$client = $this->validateAuthenticatedClient( $request );

		$tokenExchangeRequest = $this->validateTokenExchangeRequest( $request );
		$tokenExchangeRequest->setClient( $client );
		$policy = $this->tokenExchangePolicyRepository->getPolicyFromRequest( $tokenExchangeRequest );
		if ( $policy instanceof TokenExchangePolicyInterface === false ) {
			throw OAuthServerException::invalidRequest();
		}

		$subjectTokenData = $this->validateSubjectToken( $tokenExchangeRequest, $policy );
		$actorTokenData = $this->validateOptionalActorToken( $tokenExchangeRequest, $policy );

		$requestedTokenType = $tokenExchangeRequest->getRequestedTokenType() ?? $policy->determineRequestedTokenType();
		if ( !$policy->authorizeRequest( $subjectTokenData, $actorTokenData, $requestedTokenType ) ) {
			throw OAuthServerException::accessDenied( 'you do not have access' );
		}
		$scopes = $this->validateScopes( $tokenExchangeRequest->getScope() );
		$finalizedScopes = $this->scopeRepository->finalizeScopes(
			$scopes,
			$this->getIdentifier(),
			$client,
			$subjectTokenData->getUserId()
		);
		$newToken = $policy->getTokenIssuer(
			$requestedTokenType
		)->issueToken(
			$accessTokenTTL,
			$client,
			$subjectTokenData->getUserId(),
			$finalizedScopes ?? [],
			$actorTokenData?->getUserId(),
			$request
		);

		$responseType->setAccessToken( $newToken );
		$responseType->setTokenType( $requestedTokenType );

		return $responseType;
	}

	protected function validateTokenExchangeRequest( ServerRequestInterface $request ): TokenExchangeRequestInterface {
		$subjectToken = $this->getRequestParameter( 'subject_token', $request );
		$subjectTokenType = $this->getRequestParameter( 'subject_token_type', $request );
		if ( $subjectToken === null ) {
			$this->getEmitter()->emit( new RequestEvent( RequestEvent::USER_AUTHENTICATION_FAILED, $request ) );

			throw OAuthServerException::invalidRequest( 'subject_token' );
		}
		if ( $subjectTokenType === null ) {
			$this->getEmitter()->emit( new RequestEvent( RequestEvent::USER_AUTHENTICATION_FAILED, $request ) );

			throw OAuthServerException::invalidRequest( 'subject_token_type' );
		}

		$actorToken = $this->getRequestParameter( 'actor_token', $request );
		$actorTokenType = $this->getRequestParameter( 'actor_token_type', $request );

		// Actor token type should only be provided if actor token is also provided.
		if ( $actorToken !== null && $actorTokenType === null ) {
			$this->getEmitter()->emit( new RequestEvent( RequestEvent::USER_AUTHENTICATION_FAILED, $request ) );

			throw OAuthServerException::invalidRequest( 'actor_token_type' );
		} elseif ( $actorToken === null && $actorTokenType !== null ) {
			$this->getEmitter()->emit( new RequestEvent( RequestEvent::USER_AUTHENTICATION_FAILED, $request ) );

			throw OAuthServerException::invalidRequest( '', 'An actor_token_type was given without an actor_token' );
		}

		// All other parameters are optional, so no a-priori validation is needed on those.

		$validatedRequest = new SimpleTokenExchangeRequest;

		$validatedRequest->setSubjectToken( $subjectToken );
		$validatedRequest->setSubjectTokenType( $subjectTokenType );

		$validatedRequest->setActorToken( $actorToken );
		$validatedRequest->setActorTokenType( $actorTokenType );

		$validatedRequest->setResource( $this->getRequestParameter( 'resource', $request ) );
		$validatedRequest->setAudience( $this->getRequestParameter( 'audience', $request ) );
		$validatedRequest->setScope( $this->getRequestParameter( 'scope', $request ) );
		$validatedRequest->setRequestedTokenType( $this->getRequestParameter( 'requested_token_type', $request ) );

		return $validatedRequest;
	}

	/**
	 * A wrapper around validateClient that makes sure the client is authenticated.
	 *
	 * Override this function to support other methods of client authentication.
	 *
	 * Note that RFC 8693 warns about allowing non-authenticated clients:
	 * > omitting client authentication allows for a compromised token to be leveraged
	 * > via an STS into other tokens by anyone possessing the compromised token.
	 *
	 * @throws OAuthServerException
	 */
	protected function validateAuthenticatedClient( ServerRequestInterface $request ): ClientEntityInterface {
		$client = $this->validateClient( $request );

		// validateClient will have checked client credentials for confidential clients,
		// so we only check that it is indeed a confidential client.
		if ( !$client->isConfidential() ) {
			$this->getEmitter()->emit( new RequestEvent( RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request ) );

			throw OAuthServerException::invalidClient( $request );
		}

		return $client;
	}

	protected function validateSubjectToken( $request, $policy ): TokenValidationResult {
		$subjectTokenType = $request->getSubjectTokenType();
		$subjectToken = $request->getSubjectToken();

		if ( !$policy->isAllowedSubjectTokenType( $subjectTokenType ) ) {
			throw OAuthServerException::invalidRequest( 'subject_token_type' );
		}

		try {
			$validatedToken = $policy->getSubjectTokenValidator( $subjectTokenType )->validateToken( $subjectToken );
		} catch (OAuthServerException $exception) {
			throw OAuthServerException::invalidRequest( 'subject_token', $exception->getHint(), $exception );
		}

		return $validatedToken;
	}

	protected function validateOptionalActorToken( $request, $policy ): ?TokenValidationResult {
		$actorTokenType = $request->getActorTokenType();
		$actorToken = $request->getActorToken();
		if ( $actorToken === null ) {
			if ( $policy->requiresActorToken() ) {
				throw OAuthServerException::invalidRequest( 'actor_token' );
			}
			return null;
		}

		if ( !$policy->isAllowedActorTokenType( $actorTokenType ) ) {
			throw OAuthServerException::invalidRequest( 'actor_token_type' );
		}

		try {
			return $policy->getActorTokenValidator( $actorTokenType )->validateToken( $actorToken );
		} catch (OAuthServerException $exception) {
			throw OAuthServerException::invalidRequest( 'actor_token', $exception->getHint(), $exception );
		}
	}
}
