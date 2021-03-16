<?php

namespace LeagueTests\RedirectUriValidators;

use League\OAuth2\Server\RedirectUriValidators\RedirectUriValidator;
use LeagueTests\Stubs\ClientEntity;
use PHPUnit\Framework\TestCase;

class RedirectUriValidatorTest extends TestCase
{
    public function testInvalidNonLoopbackUri()
    {
        $client = new ClientEntity();
        $client->setRedirectUri([
            'https://example.com:8443/endpoint',
            'https://example.com/different/endpoint',
        ]);
        $redirectUri = 'https://example.com/endpoint';

        $validator = new RedirectUriValidator($client);

        $this->assertFalse(
            $validator->validateRedirectUri($redirectUri),
            'Non loopback URI must match in every part'
        );
    }

    public function testValidNonLoopbackUri()
    {
        $client = new ClientEntity();
        $client->setRedirectUri([
            'https://example.com:8443/endpoint',
            'https://example.com/different/endpoint',
        ]);
        $redirectUri = 'https://example.com:8443/endpoint';

        $validator = new RedirectUriValidator($client);

        $this->assertTrue(
            $validator->validateRedirectUri($redirectUri),
            'Redirect URI must be valid when matching in every part'
        );
    }

    public function testInvalidLoopbackUri()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://127.0.0.1:8443/endpoint');

        $redirectUri = 'http://127.0.0.1:8443/different/endpoint';

        $validator = new RedirectUriValidator($client);

        $this->assertFalse(
            $validator->validateRedirectUri($redirectUri),
            'Valid loopback redirect URI can change only the port number'
        );
    }

    public function testValidLoopbackUri()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://127.0.0.1:8443/endpoint');

        $redirectUri = 'http://127.0.0.1:8080/endpoint';

        $validator = new RedirectUriValidator($client);

        $this->assertTrue(
            $validator->validateRedirectUri($redirectUri),
            'Loopback redirect URI can change the port number'
        );
    }

    public function testValidIpv4LoopbackUri()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://[::1]:8443/endpoint');

        $redirectUri = 'http://[::1]:8080/endpoint';

        $validator = new RedirectUriValidator($client);

        $this->assertTrue(
            $validator->validateRedirectUri($redirectUri),
            'Loopback redirect URI can change the port number'
        );
    }
}
