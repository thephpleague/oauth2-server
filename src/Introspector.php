<?php

namespace League\OAuth2\Server;

use Exception;
use InvalidArgumentException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\IntrospectionResponse;
use Psr\Http\Message\ServerRequestInterface;

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
    ) {
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
    public function respondToIntrospectionRequest(
        ServerRequestInterface $request,
        IntrospectionResponse $responseType
    )
    {
        $jwt = $request->getParsedBody()['token'] ?? null;

        try {
            $token = $this->parser->parse($jwt);
        } catch (InvalidArgumentException $e) {
            return $responseType;
        }

        return $this->isTokenValid($token) ?
            $this->setTokenOnResponse($token, $responseType) :
            $responseType;
    }

    /**
     * Validate the JWT and make sure it has not expired or been revoked
     *
     * @return bool
     */
    private function isTokenValid(Token $token)
    {
        return $this->verifyToken($token) && !$this->isTokenExpired($token) && !$this->isTokenRevoked($token);
    }

    /**
     * Validate the JWT token.
     *
     * @param Token $token
     *
     * @return bool
     */
    private function verifyToken(Token $token)
    {
        $keychain = new Keychain();
        $key = $keychain->getPrivateKey($this->privateKey->getKeyPath(), $this->privateKey->getPassPhrase());

        return $token->verify(new Sha256, $key->getContent());
    }

    /**
     * Ensure access token hasn't expired
     *
     * @param Token $token
     *
     * @return bool
     */
    private function isTokenExpired(Token $token)
    {
        $data = new ValidationData(time());

        return !$token->validate($data);
    }

    /**
     * Check if the given access token is revoked.
     *
     * @param Token $token
     *
     * @return bool
     */
    private function isTokenRevoked(Token $token)
    {
        return $this->accessTokenRepository->isAccessTokenRevoked($token->getClaim('jti'));
    }

    /**
     * Create active introspection response.
     *
     * @param Token $token
     *
     * @return IntrospectionResponse
     */
    private function setTokenOnResponse(Token $token, IntrospectionResponse $responseType)
    {
        $responseType->setToken($token);

        return $responseType;
    }
}
