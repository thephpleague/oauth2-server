<?php

declare(strict_types=1);

namespace LeagueTests\CodeChallengeVerifiers;

use League\OAuth2\Server\CodeChallengeVerifiers\PlainVerifier;
use PHPUnit\Framework\TestCase;

class PlainVerifierTest extends TestCase
{
    public function testGetMethod(): void
    {
        $verifier = new PlainVerifier();

        self::assertEquals('plain', $verifier->getMethod());
    }

    public function testVerifyCodeChallenge(): void
    {
        $verifier = new PlainVerifier();

        self::assertTrue($verifier->verifyCodeChallenge('foo', 'foo'));
        self::assertFalse($verifier->verifyCodeChallenge('foo', 'bar'));
    }
}
