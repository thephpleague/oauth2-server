<?php

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Repositories\RepositoryInterface;
use League\OAuth2\Server\RequestTypes\TokenExchangeRequestInterface;
use League\OAuth2\Server\TokenExchange\TokenExchangePolicyInterface;

interface TokenExchangePolicyRepositoryInterface extends RepositoryInterface {
	/**
	 * Determines the token exchange policy to apply
	 *
	 * Can use request parameters such as
	 * requested_token_type, resource, audience and scope
	 * to determine this.
	 *
	 * @throws OAuthServerException
	 * @return TokenExchangePolicyInterface|null The policy to use, or null if no policy could be determined.
	 */
	public function getPolicyFromRequest( ?TokenExchangeRequestInterface $request ): ?TokenExchangePolicyInterface;
}
