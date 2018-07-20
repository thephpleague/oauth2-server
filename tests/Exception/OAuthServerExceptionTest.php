<?php

namespace LeagueTests\Exception;

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
}
