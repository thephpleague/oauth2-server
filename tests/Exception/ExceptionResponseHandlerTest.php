<?php declare(strict_types=1);

namespace LeagueTests\Exception;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\ExceptionResponseHandler;
use League\OAuth2\Server\Exception\ExceptionResponseHandlerInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use PHPUnit\Framework\TestCase;

class ExceptionResponseHandlerTest extends TestCase
{
    /**
     * @var ExceptionResponseHandler
     */
    private $handler;

    protected function setUp(): void
    {
        $this->handler = new ExceptionResponseHandler();
    }

    public function testHandlerImplementsContract(): void
    {
        $this->assertInstanceOf(ExceptionResponseHandlerInterface::class, $this->handler);
    }

    public function testGenerateRedirectResponseStatusCodeForInvalidScopeExceptionWithRedirectUri()
    {
        $exception = OAuthServerException::invalidScope('foo', 'https://bar.test');
        $response = $this->handler->generateHttpResponse($exception, new Response());
        $this->assertSame(302, $response->getStatusCode());
    }

    public function testGenerateRedirectResponseLocationHeaderForInvalidScopeExceptionWithRedirectUri()
    {
        $redirectUri = 'https://bar.test';
        $exception = OAuthServerException::invalidScope('foo', $redirectUri);
        $response = $this->handler->generateHttpResponse($exception, new Response());

        $payload = $exception->getPayload();
        $query = \http_build_query($payload);
        $expectedRedirectUri = $redirectUri . '?' . $query;
        $header = $response->getHeader('Location')[0];
        $this->assertSame($expectedRedirectUri, $header);
    }

    public function testGenerateRedirectResponseLocationHeaderForInvalidScopeExceptionWithRedirectUriUsingFragment()
    {
        $redirectUri = 'https://bar.test';
        $exception = OAuthServerException::invalidScope('foo', $redirectUri);
        $response = $this->handler->generateHttpResponse($exception, new Response(), true);

        $payload = $exception->getPayload();
        $query = \http_build_query($payload);
        $expectedRedirectUri = $redirectUri . '#' . $query;
        $header = $response->getHeader('Location')[0];
        $this->assertSame($expectedRedirectUri, $header);
    }

    public function testInvalidClientExceptionSetsAuthenticateHeader()
    {
        $serverRequest = (new ServerRequest())
            ->withParsedBody([
                                 'client_id' => 'foo',
                             ])
            ->withAddedHeader('Authorization', 'Basic fakeauthdetails');

        try {
            $this->issueInvalidClientException($serverRequest);
        } catch (OAuthServerException $e) {
            $response = $this->handler->generateHttpResponse($e, new Response());

            $this->assertTrue($response->hasHeader('WWW-Authenticate'));
        }
    }

    public function testInvalidClientExceptionOmitsAuthenticateHeader()
    {
        $serverRequest = (new ServerRequest())
            ->withParsedBody([
                                 'client_id' => 'foo',
                             ]);

        try {
            $this->issueInvalidClientException($serverRequest);
        } catch (OAuthServerException $e) {
            $response = $this->handler->generateHttpResponse($e, new Response());

            $this->assertFalse($response->hasHeader('WWW-Authenticate'));
        }
    }

    /**
     * Issue an invalid client exception
     *
     * @throws OAuthServerException
     */
    private function issueInvalidClientException($serverRequest)
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('validateClient')->willReturn(false);

        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new \ReflectionClass($grantMock);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $validateClientMethod->invoke($grantMock, $serverRequest);
    }
}
