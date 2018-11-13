<?php

namespace LeagueTests\Exception;

use Exception;
use League\OAuth2\Server\Exception\OAuthServerException;
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

        $this->assertSame('This is the previous', $exceptionWithPrevious->getPrevious()->getMessage());
    }

    public function testDoesNotHavePrevious()
    {
        $exceptionWithoutPrevious = OAuthServerException::accessDenied();

        $this->assertNull($exceptionWithoutPrevious->getPrevious());
    }
}
