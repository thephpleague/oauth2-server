<?php

namespace LeagueTests\RedirectUriValidators;

use League\OAuth2\Server\RedirectUriValidators\RedirectUriValidator;
use PHPUnit\Framework\TestCase;

class RedirectUriValidatorTest extends TestCase
{
    public function testInvalidNonLoopbackUri()
    {
        $validator = new RedirectUriValidator([
            'https://example.com:8443/endpoint',
            'https://example.com/different/endpoint',
        ]);

        $invalidRedirectUri = 'https://example.com/endpoint';

        $this->assertFalse(
            $validator->validateRedirectUri($invalidRedirectUri),
            'Non loopback URI must match in every part'
        );
    }

    public function testValidNonLoopbackUri()
    {
        $validator = new RedirectUriValidator([
            'https://example.com:8443/endpoint',
            'https://example.com/different/endpoint',
        ]);

        $validRedirectUri = 'https://example.com:8443/endpoint';

        $this->assertTrue(
            $validator->validateRedirectUri($validRedirectUri),
            'Redirect URI must be valid when matching in every part'
        );
    }

    public function testInvalidLoopbackUri()
    {
        $validator = new RedirectUriValidator('http://127.0.0.1:8443/endpoint');

        $invalidRedirectUri = 'http://127.0.0.1:8443/different/endpoint';

        $this->assertFalse(
            $validator->validateRedirectUri($invalidRedirectUri),
            'Valid loopback redirect URI can change only the port number'
        );
    }

    public function testValidLoopbackUri()
    {
        $validator = new RedirectUriValidator('http://127.0.0.1:8443/endpoint');

        $validRedirectUri = 'http://127.0.0.1:8080/endpoint';

        $this->assertTrue(
            $validator->validateRedirectUri($validRedirectUri),
            'Loopback redirect URI can change the port number'
        );
    }

    public function testValidIpv6LoopbackUri()
    {
        $validator = new RedirectUriValidator('http://[::1]:8443/endpoint');

        $validRedirectUri = 'http://[::1]:8080/endpoint';

        $this->assertTrue(
            $validator->validateRedirectUri($validRedirectUri),
            'Loopback redirect URI can change the port number'
        );
    }

    public function testMaformedLoopbackUri()
    {
        $validator = new RedirectUriValidator('http://127.0.0.1:8443/endpoint');

        $invalidRedirectUri = '127.0.0.1:8443/endpoint';

        $this->assertFalse(
            $validator->validateRedirectUri($invalidRedirectUri),
            'Valid loopback redirect URI must contain the scheme'
        );
    }
}
