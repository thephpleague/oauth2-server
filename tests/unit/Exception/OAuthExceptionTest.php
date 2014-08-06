<?php

namespace LeagueTests;

use \Mockery as M;

class OAuthExceptionTest extends \PHPUnit_Framework_TestCase
{
    public function testGetHttpHeaders()
    {
        $exception = new \League\OAuth2\Server\Exception\OAuthException();

        $exception->httpStatusCode = 400;
        $this->assertSame($exception->getHttpHeaders(), ['HTTP/1.1 400 Bad Request']);

        $exception->httpStatusCode = 401;
        $this->assertSame($exception->getHttpHeaders(), ['HTTP/1.1 401 Unauthorized']);

        $exception->httpStatusCode = 500;
        $this->assertSame($exception->getHttpHeaders(), ['HTTP/1.1 500 Internal Server Error']);

        $exception->httpStatusCode = 501;
        $this->assertSame($exception->getHttpHeaders(), ['HTTP/1.1 501 Not Implemented']);
    }
}
