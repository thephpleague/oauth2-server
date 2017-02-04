<?php

namespace LeagueTests\Utils;

use League\OAuth2\Server\Exception\OAuthServerException;

class ExceptionTest extends \PHPUnit_Framework_TestCase
{
    public function testHasRedirect()
    {
        $exceptionWithoutRedirect = OAuthServerException::accessDenied('Some hint');
        $this->assertFalse($exceptionWithoutRedirect->hasRedirect());

        $exceptionWithRedirect = OAuthServerException::accessDenied('some hint', 'https://example.com/error');
        $this->assertTrue($exceptionWithRedirect->hasRedirect());
    }
}