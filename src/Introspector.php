<?php

namespace League\OAuth2\Server;

use Exception;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Lcobucci\JWT\Parser;
use League\OAuth2\Server\ResponseTypes\IntrospectionResponse;

class Introspector
{
    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var CryptKey
     */
    private $privateKey;

    /**
     * @var Parser
     */
    private $parser;

    /**
     * New Introspector instance.
     *
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     * @param CryptKey                       $privateKey
     * @param Parser                         $parser
     */
    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        CryptKey $privateKey,
        Parser $parser
    )
    {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->privateKey = $privateKey;
        $this->parser = $parser;
    }

    /**
     * Return an introspection response.
     *
     * @param ServerRequestInterface $request
     *
     * @return IntrospectionResponse
     */
    public function respondToIntrospectionRequest(ServerRequestInterface $request)
    {
        $jwt = $request->getParsedBody()['token'] ?? null;

        try {
            $token = $this->parser->parse($jwt);

            $this->verifyToken($token);
            $this->checkIfTokenIsExpired($token);
            $this->checkIfTokenIsRevoked($token);

            return $this->createActiveResponse($token);
        }
        catch(Exception $ex) {
            return $this->createInactiveResponse();
        }
    }

    /**
     * Validate the JWT token.
     *
     * @param Token $token
     *
     * @throws OAuthServerException
     */
    private function verifyToken(Token $token)
    {
        $keychain = new Keychain();
        $key = $keychain->getPrivateKey($this->privateKey->getKeyPath(), $this->privateKey->getPassPhrase());

        if (!$token->verify(new Sha256, $key)) {
            throw OAuthServerException::accessDenied('Access token could not be verified');
        }
    }

    /**
     * Ensure access token hasn't expired
     *
     * @param Token $token
     *
     * @throws OAuthServerException
     */
    private function checkIfTokenIsExpired(Token $token)
    {
        $data = new ValidationData(time());

        if (!$token->validate($data)) {
            throw OAuthServerException::accessDenied('Access token is invalid');
        }
    }

    /**
     * Check if the given access token is revoked.
     *
     * @param Token $token
     *
     * @throws OAuthServerException
     */
    private function checkIfTokenIsRevoked(Token $token)
    {
        if ($this->accessTokenRepository->isAccessTokenRevoked($token->getClaim('jti'))) {
            throw OAuthServerException::accessDenied('Access token has been revoked');
        }
    }

    /**
     * Create active introspection response.
     *
     * @param Token             $token
     *
     * @return IntrospectionResponse
     */
    private function createActiveResponse(Token $token)
    {
        $response = new IntrospectionResponse();

        $response->setIntrospectionData(
            [
                'active' => true,
                'token_type' => 'access_token',
                'scope' => $token->getClaim('scopes', ''),
                'client_id' => $token->getClaim('aud'),
                'exp' => $token->getClaim('exp'),
                'iat' => $token->getClaim('iat'),
                'sub' => $token->getClaim('sub'),
                'jti' => $token->getClaim('jti'),
            ]
            );

        return $response;
    }

    /**
     * Create inactive introspection response
     *
     * @return IntrospectionResponse
     */
    private function createInactiveResponse()
    {
        $response = new IntrospectionResponse();

        $response->setIntrospectionData(
            [
                'active' => false,
            ]
        );

        return $response;
    }
}
