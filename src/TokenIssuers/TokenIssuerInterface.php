<?php

declare( strict_types=1 );

namespace League\OAuth2\Server\TokenIssuers;

use DateInterval;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\TokenInterface;
use Psr\Http\Message\ServerRequestInterface;

interface TokenIssuerInterface {
	/**
	 * Issue a token
	 *
	 * @param DateInterval $tokenTTL How long the token should be valid.
	 * @param ClientEntityInterface $client The client from whom this token is issued.
	 * @param string|null $userIdentifier The user to issue the token for, if any.
	 * @param ScopeEntityInterface[] $scopes The scopes this token should provide.
	 * @param string|null $actorIdentifier The actor in token exchange who will use the token, if any.
	 * @param ServerRequestInterface|null $request The request for retrieving any possibly relevant other parameters.
	 * @return TokenInterface
	 * @throws OAuthException When the token could not be issued for any reason.
	 */
	public function issueToken(
			DateInterval $tokenTTL,
			ClientEntityInterface $client,
			string|null $userIdentifier,
			array $scopes = [],
			?string $actorIdentifier = null,
			?ServerRequestInterface $request = null,
	): TokenInterface;
}
