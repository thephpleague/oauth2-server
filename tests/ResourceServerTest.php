<?php


namespace LeagueTests;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequestFactory;
use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\Exception\ExceptionResponseHandlerInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResourceServer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class ResourceServerTest extends TestCase
{
    public function testValidateAuthenticatedRequest()
    {
        $server = new ResourceServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/Stubs/public.key'
        );

        try {
            $server->validateAuthenticatedRequest(ServerRequestFactory::fromGlobals());
        } catch (OAuthServerException $e) {
            $this->assertEquals('Missing "Authorization" header', $e->getHint());
        }
    }

    public function testGenerateHttpResponseFromExceptionIsProxiesExceptionResponseHandlerMethod()
    {
        $exception = OAuthServerException::invalidScope('foo', 'https://bar.test');
        $existingResponse = new Response();
        $useFragment = true;
        $jsonOptions = 0;

        $responseMock = $this->createMock(ResponseInterface::class);
        $exceptionResponseHandlerMock = $this->createMock(ExceptionResponseHandlerInterface::class);
        $exceptionResponseHandlerMock
            ->expects($this->once())
            ->method('generateHttpResponse')
            ->with($exception, $existingResponse, $useFragment, $jsonOptions)
            ->willReturn($responseMock);

        $server = new ResourceServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/Stubs/public.key',
            $this->getMockBuilder(AuthorizationValidatorInterface::class)->getMock(),
            $exceptionResponseHandlerMock
        );

        $response = $server->generateHttpResponse($exception, $existingResponse, $useFragment, $jsonOptions);

        $this->assertSame($responseMock, $response);
    }
}
