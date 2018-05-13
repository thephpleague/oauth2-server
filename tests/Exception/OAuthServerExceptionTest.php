<?php

use PHPUnit\Framework\TestCase;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

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

    /**
     * Issue an invalid client exception
     *
     * @return void
     * @throws OAuthServerException
     */
    private function issueInvalidClientException($serverRequest)
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(false);

        $grantMock = $this->getMockForAbstractClass(AbstractGrant::class);
        $grantMock->setClientRepository($clientRepositoryMock);

        $abstractGrantReflection = new ReflectionClass($grantMock);

        $validateClientMethod = $abstractGrantReflection->getMethod('validateClient');
        $validateClientMethod->setAccessible(true);

        $validateClientMethod->invoke($grantMock, $serverRequest);
    }
}
