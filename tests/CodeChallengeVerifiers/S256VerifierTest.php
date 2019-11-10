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

    public function testVerifyCodeChallengeSucceeds()
    {
        $codeChallenge = $this->createCodeChallenge('foo');
        $verifier = new S256Verifier();

        $this->assertTrue($verifier->verifyCodeChallenge('foo', $codeChallenge));
    }

    public function testVerifyCodeChallengeFails()
    {
        $codeChallenge = $this->createCodeChallenge('bar');
        $verifier = new S256Verifier();

        $this->assertFalse($verifier->verifyCodeChallenge('foo', $codeChallenge));
    }

    private function createCodeChallenge($codeVerifier)
    {
        return strtr(rtrim(base64_encode(hash('sha256', $codeVerifier, true)), '='), '+/', '-_');
    }
}
