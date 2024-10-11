<?php

declare(strict_types=1);

namespace LeagueTests;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResourceServer;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

class ResourceServerTest extends TestCase
{
    public function testValidateAuthenticatedRequest(): void
    {
        $server = new ResourceServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/Stubs/public.key'
        );

        try {
            $server->validateAuthenticatedRequest(new ServerRequest('', ''));
        } catch (OAuthServerException $e) {
            self::assertEquals('Missing "Authorization" header', $e->getHint());
        }
    }
}
