<?php

namespace LeagueTests\CodeChallengeVerifiers;

use League\OAuth2\Server\CodeChallengeVerifiers\S256Verifier;
use PHPUnit\Framework\TestCase;

class S256VerifierTest extends TestCase
{
    public function testGetMethod()
    {
        $verifier = new S256Verifier();
        $this->assertEquals('S256', $verifier->getMethod());
    }

    public function testVerifyCodeChallenge()
    {
        $verifier = new S256Verifier();

        $this->assertTrue($verifier->verifyCodeChallenge('foo', strtr(rtrim(base64_encode(hash('sha256', 'foo', true)), '='), '+/', '-_')));
        $this->assertFalse($verifier->verifyCodeChallenge('foo', strtr(rtrim(base64_encode(hash('sha256', 'bar', true)), '='), '+/', '-_')));
    }
}
