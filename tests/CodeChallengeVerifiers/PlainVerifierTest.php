<?php

namespace LeagueTests\CodeChallengeVerifiers;

use League\OAuth2\Server\CodeChallengeVerifiers\PlainVerifier;
use PHPUnit\Framework\TestCase;

class PlainVerifierTest extends TestCase
{
    public function testGetMethod()
    {
        $verifier = new PlainVerifier();

        $this->assertEquals('plain', $verifier->getMethod());
    }

    public function testVerifyCodeChallenge()
    {
        $verifier = new PlainVerifier();

        $this->assertTrue($verifier->verifyCodeChallenge('foo', 'foo'));
        $this->assertFalse($verifier->verifyCodeChallenge('foo', 'bar'));
    }
}
