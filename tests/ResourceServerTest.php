<?php


namespace LeagueTests;

use Laminas\Diactoros\ServerRequestFactory;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResourceServer;
use PHPUnit\Framework\TestCase;

class ResourceServerTest extends TestCase
{
    /**
     * @dataProvider publicKeys
     */
    public function testValidateAuthenticatedRequest($publicKey)
    {
        $server = new ResourceServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            $publicKey
        );

        try {
            $server->validateAuthenticatedRequest(ServerRequestFactory::fromGlobals());
        } catch (OAuthServerException $e) {
            $this->assertEquals('Missing "Authorization" header', $e->getHint());
        }
    }

    public function publicKeys(): array
    {
        return [
            'file key' => ['file://' . __DIR__ . '/Stubs/public.key'],
            'inmemory key' => [file_get_contents(__DIR__ . '/Stubs/public.key')],
        ];
    }

}
