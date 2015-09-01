<?php

namespace LeagueTests\TokenType;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\TokenType\MAC;
use Mockery as M;
use Symfony\Component\HttpFoundation\Request;

class MacTest extends \PHPUnit_Framework_TestCase
{
    public function testGenerateResponse()
    {
        $macStorage = M::mock('\League\OAuth2\Server\Storage\MacTokenInterface');
        $macStorage->shouldReceive('create');

        $server = new AuthorizationServer();
        $server->setMacStorage($macStorage);

        $tokenType = new MAC();
        $tokenType->setServer($server);

        $accessToken = new AccessTokenEntity($server);
        $accessToken->setId(uniqid());
        $accessToken->setExpireTime(time());

        $tokenType->setParam('access_token', $accessToken->getId());
        $tokenType->setParam('expires_in', 3600);

        $response = $tokenType->generateResponse();

        $this->assertEquals($accessToken->getId(), $response['access_token']);
        $this->assertEquals('mac', $response['token_type']);
        $this->assertEquals(3600, $response['expires_in']);
        $this->assertEquals('hmac-sha-256', $response['mac_algorithm']);
        $this->assertArrayHasKey('mac_key', $response);
    }

    public function testDetermineAccessTokenInHeaderValid()
    {
        $macStorage = M::mock('\League\OAuth2\Server\Storage\MacTokenInterface');
        $macStorage->shouldReceive('getByAccessToken')->andReturn('abcdef');

        $server = new AuthorizationServer();
        $server->setMacStorage($macStorage);

        $ts = time();

        $request = Request::createFromGlobals();
        $calculatedSignatureParts = [
            $ts,
            'foo',
            strtoupper($request->getMethod()),
            $request->getRequestUri(),
            $request->getHost(),
            $request->getPort(),
            'ext'
        ];
        $calculatedSignature = base64_encode(hash_hmac('sha256', implode("\n", $calculatedSignatureParts), 'abcdef'));

        $request->headers->set('Authorization',  sprintf('MAC id="foo", nonce="foo", ts="%s", mac="%s", ext="ext"', $ts, $calculatedSignature));

        $tokenType = new MAC();
        $tokenType->setServer($server);

        $response = $tokenType->determineAccessTokenInHeader($request);
        $this->assertEquals('foo', $response);
    }

    public function testDetermineAccessTokenInHeaderMissingHeader()
    {
        $macStorage = M::mock('\League\OAuth2\Server\Storage\MacTokenInterface');
        $macStorage->shouldReceive('getByAccessToken')->andReturn('abcdef');

        $server = new AuthorizationServer();
        $server->setMacStorage($macStorage);

        $request = Request::createFromGlobals();
        $tokenType = new MAC();
        $tokenType->setServer($server);

        $response = $tokenType->determineAccessTokenInHeader($request);

        $this->assertEquals(null, $response);
    }

    public function testDetermineAccessTokenInHeaderMissingAuthMac()
    {
        $macStorage = M::mock('\League\OAuth2\Server\Storage\MacTokenInterface');
        $macStorage->shouldReceive('getByAccessToken')->andReturn('abcdef');

        $server = new AuthorizationServer();
        $server->setMacStorage($macStorage);

        $request = Request::createFromGlobals();
        $request->headers->set('Authorization', '');

        $tokenType = new MAC();
        $tokenType->setServer($server);

        $response = $tokenType->determineAccessTokenInHeader($request);

        $this->assertEquals(null, $response);
    }

    public function testDetermineAccessTokenInHeaderInvalidParam()
    {
        $macStorage = M::mock('\League\OAuth2\Server\Storage\MacTokenInterface');
        $macStorage->shouldReceive('getByAccessToken')->andReturn('abcdef');

        $server = new AuthorizationServer();
        $server->setMacStorage($macStorage);

        $request = Request::createFromGlobals();
        $request->headers->set('Authorization', 'MAC ');

        $tokenType = new MAC();
        $tokenType->setServer($server);

        $response = $tokenType->determineAccessTokenInHeader($request);

        $this->assertEquals(null, $response);
    }

    public function testDetermineAccessTokenInHeaderMismatchTimestamp()
    {
        $macStorage = M::mock('\League\OAuth2\Server\Storage\MacTokenInterface');
        $macStorage->shouldReceive('getByAccessToken')->andReturn('abcdef');

        $server = new AuthorizationServer();
        $server->setMacStorage($macStorage);

        $ts = time() - 100;

        $request = Request::createFromGlobals();
        $request->headers->set('Authorization',  sprintf('MAC id="foo", nonce="foo", ts="%s", mac="%s", ext="ext"', $ts, 'foo'));

        $tokenType = new MAC();
        $tokenType->setServer($server);

        $response = $tokenType->determineAccessTokenInHeader($request);
        $this->assertEquals(null, $response);
    }

    public function testDetermineAccessTokenInHeaderMissingMacKey()
    {
        $macStorage = M::mock('\League\OAuth2\Server\Storage\MacTokenInterface');
        $macStorage->shouldReceive('getByAccessToken')->andReturn(null);

        $server = new AuthorizationServer();
        $server->setMacStorage($macStorage);

        $ts = time();

        $request = Request::createFromGlobals();
        $request->headers->set('Authorization',  sprintf('MAC id="foo", nonce="foo", ts="%s", mac="%s", ext="ext"', $ts, 'foo'));

        $tokenType = new MAC();
        $tokenType->setServer($server);

        $response = $tokenType->determineAccessTokenInHeader($request);
        $this->assertEquals(null, $response);
    }
}
