<?php

namespace LeagueTests\Exception;

use Exception;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use PHPUnit\Framework\TestCase;

class OAuthServerExceptionTest extends TestCase
{
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
            $response = $e->generateHttpResponse(new Response());

            $this->assertTrue($response->hasHeader('WWW-Authenticate'));
        }
    }

    public function testInvalidClientExceptionSetsBearerAuthenticateHeader()
    {
        $serverRequest = (new ServerRequest())
            ->withParsedBody([
                'client_id' => 'foo',
            ])
            ->withAddedHeader('Authorization', 'Bearer fakeauthdetails');

        try {
            $this->issueInvalidClientException($serverRequest);
        } catch (OAuthServerException $e) {
            $response = $e->generateHttpResponse(new Response());

            $this->assertEquals(['Bearer realm="OAuth"'], $response->getHeader('WWW-Authenticate'));
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
            $response = $e->generateHttpResponse(new Response());

            $this->assertFalse($response->hasHeader('WWW-Authenticate'));
        }
    }

    public function testInvalidClientExceptionOmitsAuthenticateHeaderGivenEmptyAuthorizationHeader()
    {
        $serverRequest = (new ServerRequest())
            ->withParsedBody([
                'client_id' => 'foo',
            ])
            ->withAddedHeader('Authorization', '');

        try {
            $this->issueInvalidClientException($serverRequest);
        } catch (OAuthServerException $e) {
            $response = $e->generateHttpResponse(new Response());

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

    public function testHasRedirect()
    {
        $exceptionWithRedirect = OAuthServerException::accessDenied('some hint', 'https://example.com/error');

        $this->assertTrue($exceptionWithRedirect->hasRedirect());
    }

    public function testDoesNotHaveRedirect()
    {
        $exceptionWithoutRedirect = OAuthServerException::accessDenied('Some hint');

        $this->assertFalse($exceptionWithoutRedirect->hasRedirect());
    }

    public function testHasPrevious()
    {
        $previous = new Exception('This is the previous');
        $exceptionWithPrevious = OAuthServerException::accessDenied(null, null, $previous);

        $previousMessage = $exceptionWithPrevious->getPrevious() !== null ? $exceptionWithPrevious->getPrevious()->getMessage() : null;

        $this->assertSame('This is the previous', $previousMessage);
    }

    public function testDoesNotHavePrevious()
    {
        $exceptionWithoutPrevious = OAuthServerException::accessDenied();

        $this->assertNull($exceptionWithoutPrevious->getPrevious());
    }

    public function testCanGetRedirectionUri()
    {
        $exceptionWithRedirect = OAuthServerException::accessDenied('some hint', 'https://example.com/error');

        $this->assertSame('https://example.com/error', $exceptionWithRedirect->getRedirectUri());
    }

    public function testInvalidCredentialsIsInvalidGrant()
    {
        $exception = OAuthServerException::invalidCredentials();

        $this->assertSame('invalid_grant', $exception->getErrorType());
    }
}
