<?php

declare(strict_types=1);

namespace LeagueTests\ResponseTypes;

use DateInterval;
use DateTimeImmutable;
use Laminas\Diactoros\Response;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResponseTypes\DeviceCodeResponse;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\DeviceCodeEntity;
use LeagueTests\Stubs\ScopeEntity;
use PHPUnit\Framework\TestCase;

use function json_decode;
use function json_encode;

class DeviceCodeResponseTypeTest extends TestCase
{
    protected CryptTraitStub $cryptStub;

    public function setUp(): void
    {
        $this->cryptStub = new CryptTraitStub();
    }

    public function testGenerateHttpResponse(): void
    {
        $responseType = new DeviceCodeResponse();
        $responseType->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $responseType->setEncryptionKey($this->cryptStub->getKey());

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
        $deviceCode->setVerificationUri('https://example.com/device');

        $responseType->setDeviceCodeEntity($deviceCode);

        $response = $responseType->generateHttpResponse(new Response());

        $this::assertEquals(200, $response->getStatusCode());
        $this::assertEquals('no-cache', $response->getHeader('pragma')[0]);
        $this::assertEquals('no-store', $response->getHeader('cache-control')[0]);
        $this::assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());
        $this::assertObjectHasProperty('expires_in', $json);
        $this::assertObjectHasProperty('device_code', $json);
        $this::assertSame(json_encode([
            'client_id'             => 'clientName',
            'device_code_id'        => 'abcdef',
            'scopes'                => ['basic'],
            'expire_time'           => $deviceCode->getExpiryDateTime()->getTimestamp(),
        ]), $this->cryptStub->doDecrypt($json->device_code));
        $this::assertObjectHasProperty('verification_uri', $json);
        $this::assertObjectHasProperty('user_code', $json);
    }
}
