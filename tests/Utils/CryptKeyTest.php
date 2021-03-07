<?php

namespace LeagueTests\Utils;

use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\TestCase;

class CryptKeyTest extends TestCase
{
    public function testNoFile()
    {
        $this->expectException(\LogicException::class);

        new CryptKey('undefined file');
    }

    public function testKeyCreation()
    {
        $keyFile = __DIR__ . '/../Stubs/public.key';
        $key = new CryptKey($keyFile, 'secret');

        $this->assertEquals('file://' . $keyFile, $key->getKeyPath());
        $this->assertEquals('secret', $key->getPassPhrase());
        $this->assertTrue($key->isFilePath());
    }

    public function testInmemoryKeyCreation()
    {
        $keyContent = \file_get_contents(__DIR__ . '/../Stubs/public.key');

        if (!\is_string($keyContent)) {
            $this->fail('The public key stub is not a string');
        }

        $key = new CryptKey($keyContent);

        $this->assertEquals($keyContent, $key->getKeyPath());
        $this->assertFalse($key->isFilePath());

        $keyContent = \file_get_contents(__DIR__ . '/../Stubs/private.key.crlf');

        if (!\is_string($keyContent)) {
            $this->fail('The private key (crlf) stub is not a string');
        }

        $key = new CryptKey($keyContent);

        $this->assertEquals($keyContent, $key->getKeyPath());
        $this->assertFalse($key->isFilePath());
    }

    /**
     * Test whether we get a RuntimeException if a PCRE error is encountered.
     *
     * @link https://www.php.net/manual/en/function.preg-last-error.php
     */
    public function testPcreErrorExceptions()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/^PCRE error/');

        new class('foobar foobar foobar') extends CryptKey {
            const RSA_KEY_PATTERN = '/(?:\D+|<\d+>)*[!?]/';
        };
    }
}
