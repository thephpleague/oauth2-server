<?php

declare(strict_types=1);

namespace LeagueTests\CodeChallengeVerifiers;

use League\OAuth2\Server\CodeChallengeVerifiers\S256Verifier;
use PHPUnit\Framework\TestCase;

use function base64_encode;
use function hash;
use function rtrim;
use function strtr;

class S256VerifierTest extends TestCase
{
    public function testGetMethod(): void
    {
        $verifier = new S256Verifier();

        self::assertEquals('S256', $verifier->getMethod());
    }

    public function testVerifyCodeChallengeSucceeds(): void
    {
        $codeChallenge = $this->createCodeChallenge('foo');
        $verifier = new S256Verifier();

        self::assertTrue($verifier->verifyCodeChallenge('foo', $codeChallenge));
    }

    public function testVerifyCodeChallengeFails(): void
    {
        $codeChallenge = $this->createCodeChallenge('bar');
        $verifier = new S256Verifier();

        self::assertFalse($verifier->verifyCodeChallenge('foo', $codeChallenge));
    }

    private function createCodeChallenge(string $codeVerifier): string
    {
        return strtr(rtrim(base64_encode(hash('sha256', $codeVerifier, true)), '='), '+/', '-_');
    }
}
