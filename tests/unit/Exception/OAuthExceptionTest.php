<?php

namespace LeagueTests;

use League\OAuth2\Server\Exception\OAuthException;

class OAuthExceptionTest extends \PHPUnit_Framework_TestCase
{
    public function testGetHttpHeaders()
    {
        $exceptionStub = $this->getMockForAbstractClass('\League\OAuth2\Server\Exception\OAuthException');

        $exceptionStub->httpStatusCode = 400;
        $this->assertSame($exceptionStub->getHttpHeaders(), ['HTTP/1.1 400 Bad Request']);

        $exceptionStub->httpStatusCode = 401;
        $this->assertSame($exceptionStub->getHttpHeaders(), ['HTTP/1.1 401 Unauthorized']);

        $exceptionStub->httpStatusCode = 500;
        $this->assertSame($exceptionStub->getHttpHeaders(), ['HTTP/1.1 500 Internal Server Error']);

        $exceptionStub->httpStatusCode = 501;
        $this->assertSame($exceptionStub->getHttpHeaders(), ['HTTP/1.1 501 Not Implemented']);
    }

    public function testShouldRedirect()
    {
        $exceptionStub = $this->getMockForAbstractClass('\League\OAuth2\Server\Exception\OAuthException');

        $exceptionStub->redirectUri = 'http://example.com/';
        $exceptionStub->errorType = 'Error';
        $this->assertTrue($exceptionStub->shouldRedirect());
        $this->assertEquals(
            'http://example.com/?error=Error&message=An+error+occured',
            $exceptionStub->getRedirectUri()
        );
    }
}
