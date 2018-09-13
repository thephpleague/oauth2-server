<?php

namespace LeagueTests\Utils;

use Defuse\Crypto\Key;
use Defuse\Crypto\Encoding;
use LeagueTests\Stubs\CryptTraitStub;
use PHPUnit\Framework\TestCase;

class CryptTraitTest extends TestCase
{
    protected $cryptStub;

    protected function setUp()
    {
        $this->cryptStub = new CryptTraitStub();
    }

    public function testEncryptDecryptWithPassword()
    {
        $this->cryptStub->setEncryptionKey(base64_encode(random_bytes(36)));

        $this->encryptDecrypt();
    }

    public function testEncryptDecryptWithKey()
    {
        $this->cryptStub->setEncryptionKey(Key::createNewRandomKey());

        $this->encryptDecrypt();
    }

    private function encryptDecrypt()
    {
        $payload = 'alex loves whisky';
        $encrypted = $this->cryptStub->doEncrypt($payload);
        $plainText = $this->cryptStub->doDecrypt($encrypted);

        $this->assertNotEquals($payload, $encrypted);
        $this->assertEquals($payload, $plainText);
    }

    public function testEncryptWithPasswordDecryptBackwardsCompatibility()
    {
        $payload = 'this is a test';
        $key = random_bytes(32);

        // Set to our original password key
        $this->cryptStub->setEncryptionKey($key);

        // Encrypt with password
        $encrypted = $this->cryptStub->doEncrypt($payload);

        $this->assertNotEquals($payload, $encrypted);

        // Switch to using a Key object - we must do this in a roundabout way as the Key object has a private constructor
        $keyObject = Key::loadFromAsciiSafeString(
            Encoding::saveBytesToChecksummedAsciiSafeString(
                Key::KEY_CURRENT_VERSION,
                $key
            )
        );
        $this->cryptStub->setEncryptionKey($keyObject);

        // Decrypt after we switched to a Key object, with the same underlying data
        $plainText = $this->cryptStub->doDecrypt($encrypted);

        // Verify the ciphertext encrypted with the old algorithm can be decrypted even after we switched to the new Key format
        $this->assertEquals($payload, $plainText);
    }

    public function testEncryptWithPasswordDecryptBackwardsCompatibilityBadKey()
    {
        $payload = 'this is a test';

        // Encrypt with password
        $encrypted = $this->cryptStub->doEncrypt($payload);
        $this->assertNotEquals($payload, $encrypted);

        // Switch to using a Key object with different underlying data
        $this->cryptStub->setEncryptionKey(Key::createNewRandomKey());

        // This should fail to decrypt as we changed the key
        $this->expectException(\LogicException::class);
        $this->cryptStub->doDecrypt($encrypted);
    }
}
