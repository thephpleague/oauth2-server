<?php

namespace LeagueTests\ResponseTypes;

use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResponseTypes\DeviceCodeResponse;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\DeviceCodeEntity;
use LeagueTests\Stubs\ScopeEntity;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;

class DeviceCodeResponseTypeTest extends TestCase
{
    public function testGenerateHttpResponse()
    {
        $responseType = new DeviceCodeResponse();
        $responseType->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $responseType->setEncryptionKey(\base64_encode(\random_bytes(36)));

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $scope = new ScopeEntity();
        $scope->setIdentifier('basic');

        $deviceCode = new DeviceCodeEntity();
        $deviceCode->setIdentifier('abcdef');
        $deviceCode->setUserCode('12345678');
        $deviceCode->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $deviceCode->setClient($client);
        $deviceCode->addScope($scope);


        $responseType->setDeviceCode($deviceCode);
        $responseType->setPayload('test');

        $response = $responseType->generateHttpResponse(new Response());

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('pragma')[0]);
        $this->assertEquals('no-store', $response->getHeader('cache-control')[0]);
        $this->assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = \json_decode($response->getBody()->getContents());
        $this->assertObjectHasAttribute('expires_in', $json);
        $this->assertObjectHasAttribute('device_code', $json);
        $this->assertEquals('test', $json->device_code);
        $this->assertObjectHasAttribute('verification_uri', $json);
        $this->assertObjectHasAttribute('user_code', $json);
    }
}
