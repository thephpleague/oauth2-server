<?php

declare(strict_types=1);

namespace League\OAuth2\Server;

use Defuse\Crypto\Key;
use League\OAuth2\Server\EventEmitting\EmitterAwareInterface;
use League\OAuth2\Server\EventEmitting\EmitterAwarePolyfill;
use League\OAuth2\Server\Handlers\TokenHandlerInterface;
use League\OAuth2\Server\Handlers\TokenIntrospectionHandler;
use League\OAuth2\Server\Handlers\TokenRevocationHandler;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SensitiveParameter;

class TokenServer implements EmitterAwareInterface
{
    use EmitterAwarePolyfill;

    private CryptKeyInterface $publicKey;

    private ?TokenHandlerInterface $tokenRevocationHandler = null;

    private ?TokenHandlerInterface $tokenIntrospectionHandler = null;

    public function __construct(
        private ClientRepositoryInterface $clientRepository,
        private AccessTokenRepositoryInterface $accessTokenRepository,
        private RefreshTokenRepositoryInterface $refreshTokenRepository,
        CryptKeyInterface|string $publicKey,
        #[SensitiveParameter]
        private Key|string $encryptionKey
    ) {
        if ($publicKey instanceof CryptKeyInterface === false) {
            $publicKey = new CryptKey($publicKey);
        }

        $this->publicKey = $publicKey;
    }

    public function setTokenRevocationHandler(TokenHandlerInterface $handler): void
    {
        $this->tokenRevocationHandler = $handler;
    }

    public function setTokenIntrospectionHandler(TokenHandlerInterface $handler): void
    {
        $this->tokenIntrospectionHandler = $handler;
    }

    protected function getTokenRevocationHandler(): TokenHandlerInterface
    {
        $this->tokenRevocationHandler ??= new TokenRevocationHandler();

        $this->tokenRevocationHandler->setClientRepository($this->clientRepository);
        $this->tokenRevocationHandler->setAccessTokenRepository($this->accessTokenRepository);
        $this->tokenRevocationHandler->setRefreshTokenRepository($this->refreshTokenRepository);
        $this->tokenRevocationHandler->setPublicKey($this->publicKey);
        $this->tokenRevocationHandler->setEmitter($this->getEmitter());
        $this->tokenRevocationHandler->setEncryptionKey($this->encryptionKey);

        return $this->tokenRevocationHandler;
    }

    protected function getTokenIntrospectionHandler(): TokenHandlerInterface
    {
        $this->tokenIntrospectionHandler ??= new TokenIntrospectionHandler();

        $this->tokenIntrospectionHandler->setClientRepository($this->clientRepository);
        $this->tokenIntrospectionHandler->setAccessTokenRepository($this->accessTokenRepository);
        $this->tokenIntrospectionHandler->setRefreshTokenRepository($this->refreshTokenRepository);
        $this->tokenIntrospectionHandler->setPublicKey($this->publicKey);
        $this->tokenIntrospectionHandler->setEmitter($this->getEmitter());
        $this->tokenIntrospectionHandler->setEncryptionKey($this->encryptionKey);

        return $this->tokenIntrospectionHandler;
    }

    public function respondToTokenRevocationRequest(
        ServerRequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface {
        return $this->getTokenRevocationHandler()->respondToRequest($request, $response);
    }

    public function respondToTokenIntrospectionRequest(
        ServerRequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface {
        return $this->getTokenIntrospectionHandler()->respondToRequest($request, $response);
    }
}
