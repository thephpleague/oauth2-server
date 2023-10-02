<?php

declare(strict_types=1);

namespace LeagueTests\Utils;

use League\OAuth2\Server\CryptKey;
use LogicException;
use PHPUnit\Framework\TestCase;
use Throwable;

use function file_get_contents;
use function is_string;
use function openssl_pkey_export;
use function openssl_pkey_new;
use function sha1;
use function sys_get_temp_dir;
use function unlink;

class CryptKeyTest extends TestCase
{
    public function testNoFile(): void
    {
        $this->expectException(LogicException::class);

        new CryptKey('undefined file');
    }

    public function testKeyCreation(): void
    {
        $keyFile = __DIR__ . '/../Stubs/public.key';
        $key = new CryptKey($keyFile, 'secret');

        self::assertEquals('file://' . $keyFile, $key->getKeyPath());
        self::assertEquals('secret', $key->getPassPhrase());
    }

    public function testKeyString(): void
    {
        $keyContent = file_get_contents(__DIR__ . '/../Stubs/public.key');

        if (!is_string($keyContent)) {
            self::fail('The public key stub is not a string');
        }

        $key = new CryptKey($keyContent);

        self::assertEquals(
            $keyContent,
            $key->getKeyContents()
        );

        $keyContent = file_get_contents(__DIR__ . '/../Stubs/private.key.crlf');

        if (!is_string($keyContent)) {
            self::fail('The private key (crlf) stub is not a string');
        }

        $key = new CryptKey($keyContent);

        self::assertEquals(
            $keyContent,
            $key->getKeyContents()
        );
    }

    public function testUnsupportedKeyType(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Unable to read key');

        try {
            // Create the keypair
            $res = openssl_pkey_new([
                'digest_alg' => 'sha512',
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_DSA,
            ]);

            if ($res === false) {
                self::fail('The keypair was not created');
            }

            // Get private key
            openssl_pkey_export($res, $keyContent, 'mystrongpassword');
            $path = self::generateKeyPath($keyContent);

            new CryptKey($keyContent, 'mystrongpassword');
        } finally {
            if (isset($path)) {
                @unlink($path);
            }
        }
    }

    public function testECKeyType(): void
    {
        try {
            // Create the keypair
            $res = openssl_pkey_new([
                'digest_alg' => 'sha512',
                'curve_name' => 'prime256v1',
                'private_key_type' => OPENSSL_KEYTYPE_EC,
            ]);

            if ($res === false) {
                self::fail('The keypair was not created');
            }

            // Get private key
            openssl_pkey_export($res, $keyContent, 'mystrongpassword');

            $key = new CryptKey($keyContent, 'mystrongpassword');

            self::assertEquals('', $key->getKeyPath());
            self::assertEquals('mystrongpassword', $key->getPassPhrase());
        } catch (Throwable $e) {
            self::fail('The EC key was not created');
        }
    }

    public function testRSAKeyType(): void
    {
        try {
            // Create the keypair
            $res = openssl_pkey_new([
                 'digest_alg' => 'sha512',
                 'private_key_bits' => 2048,
                 'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            if ($res === false) {
                self::fail('The keypair was not created');
            }

            // Get private key
            openssl_pkey_export($res, $keyContent, 'mystrongpassword');

            $key = new CryptKey($keyContent, 'mystrongpassword');

            self::assertEquals('', $key->getKeyPath());
            self::assertEquals('mystrongpassword', $key->getPassPhrase());
        } catch (Throwable $e) {
            self::fail('The RSA key was not created');
        }
    }

    private static function generateKeyPath(string $keyContent): string
    {
        return 'file://' . sys_get_temp_dir() . '/' . sha1($keyContent) . '.key';
    }
}
