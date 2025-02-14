<?php

declare(strict_types=1);

namespace League\OAuth2\Server\Handlers;

use Defuse\Crypto\Key;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\EventEmitting\EmitterAwareInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface TokenHandlerInterface extends EmitterAwareInterface
{
    public function respondToRequest(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface;

    public function setClientRepository(ClientRepositoryInterface $clientRepository): void;

    public function setAccessTokenRepository(AccessTokenRepositoryInterface $accessTokenRepository): void;

    public function setRefreshTokenRepository(RefreshTokenRepositoryInterface $accessTokenRepository): void;

    public function setPublicKey(CryptKeyInterface $publicKey): void;

    public function setEncryptionKey(Key|string|null $key = null): void;
}
