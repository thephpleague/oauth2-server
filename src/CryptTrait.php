<?php
/**
 * Public/private key encryption.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use Defuse\Crypto\Crypto;

trait CryptTrait
{
    /**
     * @var CryptKey
     */
    protected $privateKey;

    /**
     * @var CryptKey
     */
    protected $publicKey;

    /**
     * @var string
     */
    protected $encryptionKey;

    /**
     * Set path to private key.
     *
     * @param CryptKey $privateKey
     */
    public function setPrivateKey(CryptKey $privateKey)
    {
        $this->privateKey = $privateKey;
    }

    /**
     * Set path to public key.
     *
     * @param CryptKey $publicKey
     */
    public function setPublicKey(CryptKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * Encrypt data with a private key.
     *
     * @param string $unencryptedData
     *
     * @throws \LogicException
     *
     * @return string
     */
    protected function encrypt($unencryptedData)
    {
        if ($this->encryptionKey !== null) {
            return Crypto::encryptWithPassword($unencryptedData, $this->encryptionKey);
        }

        $privateKey = openssl_pkey_get_private($this->privateKey->getKeyPath(), $this->privateKey->getPassPhrase());
        $privateKeyDetails = @openssl_pkey_get_details($privateKey);
        if ($privateKeyDetails === null) {
            throw new \LogicException(
                sprintf('Could not get details of private key: %s', $this->privateKey->getKeyPath())
            );
        }

        $chunkSize = ceil($privateKeyDetails['bits'] / 8) - 11;
        $output = '';

        while ($unencryptedData) {
            $chunk = substr($unencryptedData, 0, $chunkSize);
            $unencryptedData = substr($unencryptedData, $chunkSize);
            if (openssl_private_encrypt($chunk, $encrypted, $privateKey) === false) {
                // @codeCoverageIgnoreStart
                throw new \LogicException('Failed to encrypt data');
                // @codeCoverageIgnoreEnd
            }
            $output .= $encrypted;
        }
        openssl_pkey_free($privateKey);

        return base64_encode($output);
    }

    /**
     * Decrypt data with a public key.
     *
     * @param string $encryptedData
     *
     * @throws \LogicException
     *
     * @return string
     */
    protected function decrypt($encryptedData)
    {
        if ($this->encryptionKey !== null) {
            return Crypto::decryptWithPassword($encryptedData, $this->encryptionKey);
        }

        $publicKey = openssl_pkey_get_public($this->publicKey->getKeyPath());
        $publicKeyDetails = @openssl_pkey_get_details($publicKey);
        if ($publicKeyDetails === null) {
            throw new \LogicException(
                sprintf('Could not get details of public key: %s', $this->publicKey->getKeyPath())
            );
        }

        $chunkSize = ceil($publicKeyDetails['bits'] / 8);
        $output = '';

        $encryptedData = base64_decode($encryptedData);

        while ($encryptedData) {
            $chunk = substr($encryptedData, 0, $chunkSize);
            $encryptedData = substr($encryptedData, $chunkSize);
            if (openssl_public_decrypt($chunk, $decrypted, $publicKey/*, OPENSSL_PKCS1_OAEP_PADDING*/) === false) {
                // @codeCoverageIgnoreStart
                throw new \LogicException('Failed to decrypt data');
                // @codeCoverageIgnoreEnd
            }
            $output .= $decrypted;
        }
        openssl_pkey_free($publicKey);

        return $output;
    }

    /**
     * Set the encryption key
     *
     * @param string $key
     */
    public function setEncryptionKey($key = null)
    {
        $this->encryptionKey = $key;
    }
}
