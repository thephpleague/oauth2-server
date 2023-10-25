<?php

declare(strict_types=1);

namespace LeagueTests\Exception;

use Exception;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClass;

class OAuthServerExceptionTest extends TestCase
{
    public function testInvalidClientExceptionSetsAuthenticateHeader(): void
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

            self::assertTrue($response->hasHeader('WWW-Authenticate'));
        }
    }

    public function testInvalidClientExceptionSetsBearerAuthenticateHeader(): void
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

            self::assertEquals(['Bearer realm="OAuth"'], $response->getHeader('WWW-Authenticate'));
        }
    }

    public function testInvalidClientExceptionOmitsAuthenticateHeader(): void
    {
        $serverRequest = (new ServerRequest())
            ->withParsedBody([
                'client_id' => 'foo',
            ]);

        try {
            $this->issueInvalidClientException($serverRequest);
        } catch (OAuthServerException $e) {
            $response = $e->generateHttpResponse(new Response());

            self::assertFalse($response->hasHeader('WWW-Authenticate'));
        }
    }

    public function testInvalidClientExceptionOmitsAuthenticateHeaderGivenEmptyAuthorizationHeader(): void
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

            self::assertFalse($response->hasHeader('WWW-Authenticate'));
        }
    }

    /**
     * Issue an invalid client exception
     *
     * @throws OAuthServerException
     */
    private function issueInvalidClientException(ServerRequestInterface $serverRequest): void
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('validateClient')->willReturn(false);

        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $validateClientMethod->invoke($grantMock, $serverRequest);
    }

    public function testHasRedirect(): void
    {
        $exceptionWithRedirect = OAuthServerException::accessDenied('some hint', 'https://example.com/error');

        self::assertTrue($exceptionWithRedirect->hasRedirect());
    }

    public function testDoesNotHaveRedirect(): void
    {
        $exceptionWithoutRedirect = OAuthServerException::accessDenied('Some hint');

        self::assertFalse($exceptionWithoutRedirect->hasRedirect());
    }

    public function testHasPrevious(): void
    {
        $previous = new Exception('This is the previous');
        $exceptionWithPrevious = OAuthServerException::accessDenied(null, null, $previous);

        $previousMessage = $exceptionWithPrevious->getPrevious() !== null ? $exceptionWithPrevious->getPrevious()->getMessage() : null;

        self::assertSame('This is the previous', $previousMessage);
    }

    public function testDoesNotHavePrevious(): void
    {
        $exceptionWithoutPrevious = OAuthServerException::accessDenied();

        self::assertNull($exceptionWithoutPrevious->getPrevious());
    }

    public function testCanGetRedirectionUri(): void
    {
        $exceptionWithRedirect = OAuthServerException::accessDenied('some hint', 'https://example.com/error');

        self::assertSame('https://example.com/error', $exceptionWithRedirect->getRedirectUri());
    }

    public function testInvalidCredentialsIsInvalidGrant(): void
    {
        $exception = OAuthServerException::invalidCredentials();

        self::assertSame('invalid_grant', $exception->getErrorType());
    }
}
