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

    public function testGetRedirectUri(): void
    {
        $redirectUri = 'https://bar.test';
        $exception = OAuthServerException::invalidScope('foo', $redirectUri);

        $this->assertSame($redirectUri, $exception->getRedirectUri());
    }
}
