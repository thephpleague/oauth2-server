<?php

declare(strict_types=1);

namespace League\OAuth2\Server\ResponseTypes\Introspection;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;

class BearerTokenResponse extends AbstractResponseType
{
    /**
     * @var Configuration|null
     */
    private $jwtConfiguration;

    public function __construct()
    {
        $this->initJwtConfiguration();
    }


    /**
     * Initialise the JWT configuration.
     */
    private function initJwtConfiguration()
    {
        $this->jwtConfiguration = Configuration::forSymmetricSigner(new Sha256(), InMemory::empty());
    }

    /**
     * Add the token data to the response.
     *
     * @return array
     */
    protected function validIntrospectionResponse(): array
    {
        $token = $this->getTokenFromRequest();

        $responseParams = [
            'active' => true,
            'token_type' => 'access_token',
            'scope' => $this->getClaimFromToken($token, 'scopes', ''),
            'client_id' => $this->getClaimFromToken($token, 'aud'),
            'exp' => $this->getClaimFromToken($token, 'exp'),
            'iat' => $this->getClaimFromToken($token, 'iat'),
            'sub' => $this->getClaimFromToken($token, 'sub'),
            'jti' => $this->getClaimFromToken($token, 'jti'),
        ];

        return array_merge($this->getExtraParams(), $responseParams);
    }

    /**
     * Gets the token from the request body.
     *
     * @return UnencryptedToken|Token
     */
    protected function getTokenFromRequest()
    {
        $jwt = $this->request->getParsedBody()['token'] ?? '';

        return $this->jwtConfiguration->parser()
            ->parse($jwt);
    }

    /**
     * Gets a single claim from the JWT token.
     *
     * @param UnencryptedToken|Token\Plain $token
     * @param string $claim
     * @param mixed|null $default
     *
     * @return mixed
     */
    protected function getClaimFromToken($token, string $claim, $default = null)
    {
        return $token->claims()->get($claim, $default);
    }
}
