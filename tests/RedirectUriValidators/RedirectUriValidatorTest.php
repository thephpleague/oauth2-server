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

    /**
     * @dataProvider provideUriCases
     *
     * @param string $uri
     * @param bool   $valid
     */
    public function testRedirectUri($uri, $valid)
    {
        $validator = new RedirectUriValidator($uri);
        $this->assertEquals($valid, $validator->validateRedirectUri($uri));
    }

    public function provideUriCases()
    {
        return [
            'Valid URN' => ['urn:ietf:wg:oauth:2.0:oob', true],
            'Valid Private Use URI Scheme Host' => ['msal://redirect', true],
            'Valid Private Use URI Scheme Path' => ['com.example.app:/oauth2redirect/example-provider', true],
            'Invalid loopback without scheme' => ['127.0.0.1:8443/endpoint', false],
            'Invalid HTTPS URL with fragment' => ['https://example.com/endpoint#fragment', false],
            'Invalid HTTP URL with port and fragment' => ['http://127.0.0.1:8080/endpoint#fragment', false],
            'Invalid path without scheme ' => ['/path/to/endpoint', false],
            'Invalid host and path without scheme ' => ['//host/path/to/endpoint', false],
        ];
    }
}
