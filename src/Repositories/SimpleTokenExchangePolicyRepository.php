<?php

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\RequestTypes\TokenExchangeRequestInterface;
use League\OAuth2\Server\TokenExchange\TokenExchangePolicyInterface;

class SimpleTokenExchangePolicyRepository implements TokenExchangePolicyRepositoryInterface {
	public function __construct( private TokenExchangePolicyInterface $tokenExchangePolicy ) {
	}

	public function getPolicyFromRequest( ?TokenExchangeRequestInterface $request ): ?TokenExchangePolicyInterface {
		return $this->tokenExchangePolicy;
	}
}
